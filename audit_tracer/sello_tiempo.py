"""
audit_tracer/sello_tiempo.py
============================
SRV-T2 (21/11/2026) — Sello de tiempo RFC 3161 para las raíces de Merkle.

Hasta ahora el "ancla externa" era un archivo JSON en el mismo servidor (salvo
que AUDIT_MERKLE_ANCHORS_DIR apuntara afuera): quien controlara el servidor
podía reescribir la bitácora y el ancla a la vez. Con un sello de tiempo, una
autoridad de sellado (TSA) independiente firma "esta raíz existía en este
instante", y esa firma no la puede rehacer el administrador del servidor.

  * solicitar_sello(raiz_hex, url_tsa) -> token DER (TimeStampResp)
  * verificar_sello(token, raiz_hex) -> dict con la hora certificada, si la
    huella sellada coincide con la raíz y si la firma de la TSA es válida.

La TSA se configura con AUDIT_TSA_URL (p. ej. la de una entidad de
certificación colombiana acreditada ante la ONAC, o https://freetsa.org/tsr
para pruebas). AUDIT_TSA_CERT_SHA256 fija, opcionalmente, la huella del
certificado de la TSA en que se confía.

El protocolo usa ASN.1 DER. Para no agregar dependencias se implementa aquí el
subconjunto necesario (TimeStampReq, TimeStampResp, CMS SignedData, TSTInfo);
la firma se verifica con `cryptography`. La cadena de certificación de la TSA
hasta una raíz de confianza se valida fuera de línea (openssl ts -verify),
como se explica en la guía de instalación (Anexo 16).
"""

import base64
import hashlib
import os
import secrets
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SHA1 = "1.3.14.3.2.26"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"

_HASHES = {OID_SHA256: hashlib.sha256, OID_SHA384: hashlib.sha384, OID_SHA512: hashlib.sha512, OID_SHA1: hashlib.sha1}


class ErrorSelloTiempo(Exception):
    """La TSA no respondió, rechazó la solicitud o devolvió algo que no es un sello válido."""


# ──────────────────────────────────────────────────────────────
# DER mínimo
# ──────────────────────────────────────────────────────────────

def _largo(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    cuerpo = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(cuerpo)]) + cuerpo


def tlv(etiqueta: int, contenido: bytes) -> bytes:
    return bytes([etiqueta]) + _largo(len(contenido)) + contenido


def der_entero(valor: int) -> bytes:
    cuerpo = valor.to_bytes(max(1, (valor.bit_length() + 8) // 8), "big", signed=True)
    return tlv(0x02, cuerpo)


def der_oid(oid: str) -> bytes:
    partes = [int(p) for p in oid.split(".")]
    cuerpo = bytearray([40 * partes[0] + partes[1]])
    for parte in partes[2:]:
        trozo = [parte & 0x7F]
        parte >>= 7
        while parte:
            trozo.append(0x80 | (parte & 0x7F))
            parte >>= 7
        cuerpo.extend(reversed(trozo))
    return tlv(0x06, bytes(cuerpo))


def der_secuencia(*elementos: bytes) -> bytes:
    return tlv(0x30, b"".join(elementos))


def leer(datos: bytes, pos: int = 0) -> Tuple[int, bytes, int, int]:
    """(etiqueta, contenido, inicio_del_TLV, fin_del_TLV) del elemento en `pos`."""
    if pos + 2 > len(datos):
        raise ErrorSelloTiempo("DER truncado")
    etiqueta = datos[pos]
    largo = datos[pos + 1]
    cursor = pos + 2
    if largo & 0x80:
        n = largo & 0x7F
        if n == 0 or n > 4 or cursor + n > len(datos):
            raise ErrorSelloTiempo("Largo DER no soportado")
        largo = int.from_bytes(datos[cursor:cursor + n], "big")
        cursor += n
    if cursor + largo > len(datos):
        raise ErrorSelloTiempo("DER truncado")
    return etiqueta, datos[cursor:cursor + largo], pos, cursor + largo


def hijos(contenido: bytes) -> List[Tuple[int, bytes, bytes]]:
    """Elementos de una SEQUENCE/SET: (etiqueta, contenido, TLV completo)."""
    resultado, pos = [], 0
    while pos < len(contenido):
        etiqueta, valor, inicio, fin = leer(contenido, pos)
        resultado.append((etiqueta, valor, contenido[inicio:fin]))
        pos = fin
    return resultado


def oid_texto(contenido: bytes) -> str:
    primero = contenido[0]
    partes = [primero // 40, primero % 40]
    valor = 0
    for byte in contenido[1:]:
        valor = (valor << 7) | (byte & 0x7F)
        if not byte & 0x80:
            partes.append(valor)
            valor = 0
    return ".".join(str(p) for p in partes)


# ──────────────────────────────────────────────────────────────
# Solicitud (RFC 3161 §2.4.1)
# ──────────────────────────────────────────────────────────────

def construir_solicitud(huella: bytes, nonce: Optional[int] = None) -> bytes:
    """TimeStampReq para una huella SHA-256, pidiendo el certificado de la TSA (certReq)."""
    nonce = nonce if nonce is not None else secrets.randbits(63)
    imprint = der_secuencia(der_secuencia(der_oid(OID_SHA256), b"\x05\x00"), tlv(0x04, huella))
    return der_secuencia(der_entero(1), imprint, der_entero(nonce), tlv(0x01, b"\xff"))


def solicitar_sello(raiz_hex: str, url_tsa: Optional[str] = None, timeout: float = 15) -> bytes:
    """Pide a la TSA un sello para la raíz de Merkle (hex) y devuelve la respuesta DER verificada."""
    import requests
    url_tsa = url_tsa or os.environ.get("AUDIT_TSA_URL")
    if not url_tsa:
        raise ErrorSelloTiempo("No hay TSA configurada (AUDIT_TSA_URL)")
    huella = bytes.fromhex(raiz_hex)
    solicitud = construir_solicitud(huella)
    try:
        respuesta = requests.post(url_tsa, data=solicitud, timeout=timeout,
                                  headers={"Content-Type": "application/timestamp-query"})
    except requests.RequestException as exc:
        raise ErrorSelloTiempo(f"No se pudo contactar la TSA: {type(exc).__name__}") from exc
    if respuesta.status_code != 200:
        raise ErrorSelloTiempo(f"La TSA respondió HTTP {respuesta.status_code}")
    token = respuesta.content
    resultado = verificar_sello(token, raiz_hex)
    if not resultado["huella_coincide"]:
        raise ErrorSelloTiempo("La TSA selló una huella distinta a la raíz enviada")
    return token


# ──────────────────────────────────────────────────────────────
# Verificación
# ──────────────────────────────────────────────────────────────

def _fecha_generalizada(contenido: bytes) -> str:
    texto = contenido.decode("ascii").rstrip("Z")
    formato = "%Y%m%d%H%M%S.%f" if "." in texto else "%Y%m%d%H%M%S"
    return datetime.strptime(texto, formato).replace(tzinfo=timezone.utc).isoformat()


def _descomponer(token: bytes) -> Dict:
    _, resp, _, _ = leer(token)
    elementos = hijos(resp)
    estado = hijos(elementos[0][1])
    codigo = int.from_bytes(estado[0][1], "big", signed=True)
    if codigo not in (0, 1):  # granted / grantedWithMods
        raise ErrorSelloTiempo(f"La TSA rechazó la solicitud (estado PKI {codigo})")
    if len(elementos) < 2:
        raise ErrorSelloTiempo("La respuesta no trae el sello (timeStampToken)")
    content_info = hijos(elementos[1][1])
    if oid_texto(content_info[0][1]) != OID_SIGNED_DATA:
        raise ErrorSelloTiempo("El sello no es un CMS SignedData")
    _, signed_data, _, _ = leer(content_info[1][1])            # [0] EXPLICIT
    partes = hijos(signed_data)
    encap = hijos(partes[2][1])
    if oid_texto(encap[0][1]) != OID_TST_INFO:
        raise ErrorSelloTiempo("El contenido sellado no es un TSTInfo")
    _, tst_der, _, _ = leer(encap[1][1])                       # [0] EXPLICIT OCTET STRING
    certificados, signer_infos = [], None
    for etiqueta, valor, completo in partes[3:]:
        if etiqueta == 0xA0:
            certificados = [c for _, _, c in hijos(valor)]
        elif etiqueta == 0x31:
            signer_infos = hijos(valor)
    return {"tst": tst_der, "certificados": certificados, "firmantes": signer_infos or []}


def _info_sello(tst_der: bytes) -> Dict:
    campos = hijos(leer(tst_der)[1])
    imprint = hijos(campos[2][1])
    algoritmo = oid_texto(hijos(imprint[0][1])[0][1])
    hora = next((_fecha_generalizada(v) for e, v, _ in campos[4:] if e == 0x18), None)
    return {"algoritmo": algoritmo, "huella": imprint[1][1], "serie": int.from_bytes(campos[3][1], "big"),
            "hora": hora}


def _verificar_firma(partes: Dict) -> Tuple[bool, Optional[str], Optional[str]]:
    """(firma_valida, sujeto_del_certificado, sha256_del_certificado) del primer firmante."""
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    if not partes["firmantes"] or not partes["certificados"]:
        return False, None, None
    firmante = hijos(partes["firmantes"][0][1])
    algoritmo_digest = oid_texto(hijos(firmante[2][1])[0][1])
    atributos = next((c for e, _, c in firmante[3:] if e == 0xA0), None)
    firma = next((v for e, v, _ in firmante[3:] if e == 0x04), None)
    if atributos is None or firma is None or algoritmo_digest not in _HASHES:
        return False, None, None
    funcion = _HASHES[algoritmo_digest]
    # messageDigest firmado == hash del TSTInfo
    digest = None
    for _, atributo, _ in hijos(leer(atributos)[1]):
        partes_attr = hijos(atributo)
        if oid_texto(partes_attr[0][1]) == OID_MESSAGE_DIGEST:
            digest = hijos(partes_attr[1][1])[0][1]
    if digest != funcion(partes["tst"]).digest():
        return False, None, None
    firmado = b"\x31" + atributos[1:]                           # [0] IMPLICIT -> SET para verificar
    algoritmo_hash = {OID_SHA256: hashes.SHA256(), OID_SHA384: hashes.SHA384(), OID_SHA512: hashes.SHA512(),
                      OID_SHA1: hashes.SHA1()}[algoritmo_digest]
    for cert_der in partes["certificados"]:
        try:
            certificado = x509.load_der_x509_certificate(cert_der)
        except ValueError:
            continue
        llave = certificado.public_key()
        try:
            if isinstance(llave, rsa.RSAPublicKey):
                llave.verify(firma, firmado, padding.PKCS1v15(), algoritmo_hash)
            elif isinstance(llave, ec.EllipticCurvePublicKey):
                llave.verify(firma, firmado, ec.ECDSA(algoritmo_hash))
            else:
                continue
        except InvalidSignature:
            continue
        return True, certificado.subject.rfc4514_string(), hashlib.sha256(cert_der).hexdigest()
    return False, None, None


def verificar_sello(token: bytes, raiz_hex: str) -> Dict:
    """
    Verifica un sello RFC 3161 contra la raíz de Merkle recalculada.

    Returns:
        {'huella_coincide', 'firma_valida', 'hora_certificada', 'tsa', 'certificado_sha256',
         'certificado_confiable' (None si no se fijó AUDIT_TSA_CERT_SHA256), 'serie'}
    """
    partes = _descomponer(token)
    info = _info_sello(partes["tst"])
    funcion = _HASHES.get(info["algoritmo"], hashlib.sha256)
    huella_esperada = funcion(bytes.fromhex(raiz_hex)).digest() if info["algoritmo"] != OID_SHA256 \
        else bytes.fromhex(raiz_hex)
    firma_valida, sujeto, cert_sha = _verificar_firma(partes)
    fijado = (os.environ.get("AUDIT_TSA_CERT_SHA256") or "").lower().replace(":", "")
    return {
        "huella_coincide": info["huella"] == huella_esperada,
        "firma_valida": firma_valida,
        "hora_certificada": info["hora"],
        "tsa": sujeto,
        "certificado_sha256": cert_sha,
        "certificado_confiable": (cert_sha == fijado) if fijado and cert_sha else None,
        "serie": info["serie"],
    }


def a_texto(token: bytes) -> str:
    return base64.b64encode(token).decode("ascii")


def de_texto(texto: str) -> bytes:
    return base64.b64decode(texto)
