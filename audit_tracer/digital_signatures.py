"""
audit_tracer/digital_signatures.py
==================================
HU-6.1 — Firmas digitales de eventos de auditoría.

Este módulo implementa la lógica criptográfica para firmar los eventos
generados localmente y verificar dichas firmas en el servidor central.
Utiliza el algoritmo Ed25519, que es un esquema de firma de llave pública
rápido, determinista y seguro contra ataques de canal lateral (Side-channel).

LIB-I2 (21/11/2026) — La llave privada ya no se guarda en claro siempre:
  1. Si existe AUDIT_TRACER_KEY_PASSPHRASE, el PEM se cifra con esa frase.
  2. Si no, se intenta el llavero del sistema operativo (Administrador de
     credenciales de Windows, Llavero de macOS, Secret Service en Linux)
     mediante la librería `keyring`: se genera una frase aleatoria, se guarda
     allí y el PEM queda cifrado con ella. Copiar el archivo a otro equipo o
     a otro usuario ya no basta para firmar a nombre del dueño.
  3. Si no hay llavero (p. ej. Colab), el PEM queda sin cifrar pero con
     permisos 0600, y así se informa en el log de errores.
Las llaves en claro de versiones anteriores se vuelven a guardar cifradas en
cuanto hay una forma de protegerlas. AUDIT_TRACER_KEYRING=0 desactiva el
llavero (la suite de pruebas lo hace para no tocar el del desarrollador).
"""

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import time
from typing import Dict, Tuple, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# Los 14 campos que componen la firma, en orden alfabético estricto
# para garantizar un JSON determinista en _canonical_message().
# Se excluye hash_integridad (porque se calcula localmente y no viaja en el payload firmado)
# y firma_digital (porque es lo que estamos calculando).
_SIGNED_FIELDS = (
    "columnas_afectadas",
    "contexto_ejecucion",
    "dataset_nombre",
    "evento_uuid",
    "filas_exportadas",
    "motivo_alerta",
    "motivo_fallo",
    "nivel_alerta",
    "ruta_destino",
    "sesion_id",
    "sobrescritura",
    "timestamp",
    "tipo_accion",
    "usuario_id",
)

def _canonical_message(evento: Dict) -> bytes:
    """
    Construye la representación canónica del evento para ser firmada.
    Extrae solo los campos en _SIGNED_FIELDS, reemplaza omitidos con None,
    y serializa a JSON sin espacios y con claves ordenadas.
    """
    if "evento_uuid" not in evento:
        raise ValueError("El evento debe tener evento_uuid para ser firmado.")
        
    canonical_dict = {
        campo: evento.get(campo) for campo in _SIGNED_FIELDS
    }
    canonical_json = json.dumps(canonical_dict, sort_keys=True, separators=(',', ':'))
    return canonical_json.encode('utf-8')


# ── GENERACIÓN Y MANEJO DE LLAVES (PDGTRAZDSA-140) ──────────────────────────

def generate_keypair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Genera un nuevo par de llaves Ed25519 (privada, pública)."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

_SERVICIO_LLAVERO = "audit_tracer"


def _usar_llavero() -> bool:
    return os.environ.get("AUDIT_TRACER_KEYRING", "1") != "0"


def _frase_de_entorno() -> Optional[bytes]:
    valor = os.environ.get("AUDIT_TRACER_KEY_PASSPHRASE")
    return valor.encode("utf-8") if valor else None


def _cuenta_llavero(dir_path: str) -> str:
    """Una entrada del llavero por carpeta de llaves (el home de cada usuario tiene la suya)."""
    return "llave_firma:" + hashlib.sha256(os.path.abspath(str(dir_path)).encode("utf-8")).hexdigest()[:16]


def _frase_de_llavero(dir_path: str, crear: bool) -> Optional[bytes]:
    """Frase guardada en el llavero del sistema, o None si no hay llavero utilizable."""
    if not _usar_llavero():
        return None
    try:
        import keyring
        cuenta = _cuenta_llavero(dir_path)
        valor = keyring.get_password(_SERVICIO_LLAVERO, cuenta)
        if valor is None and crear:
            valor = secrets.token_urlsafe(32)
            keyring.set_password(_SERVICIO_LLAVERO, cuenta, valor)
            if keyring.get_password(_SERVICIO_LLAVERO, cuenta) != valor:  # backend que no guarda nada
                return None
        return valor.encode("utf-8") if valor else None
    except Exception:
        return None


def proteccion_disponible(dir_path: str) -> Optional[str]:
    """'frase' (variable de entorno), 'llavero' o None si la llave quedaría en claro."""
    if _frase_de_entorno():
        return "frase"
    if _frase_de_llavero(dir_path, crear=True):
        return "llavero"
    return None


def save_private_key(private_key: ed25519.Ed25519PrivateKey, dir_path: str) -> None:
    """
    Guarda la llave privada en disco en formato PEM PKCS8, cifrada con la
    frase de AUDIT_TRACER_KEY_PASSPHRASE o del llavero del sistema si hay
    alguna, y siempre con permisos de solo-dueño (LIB-I2).
    """
    from .utils.permisos import escribir_privado, restringir_a_dueno
    os.makedirs(dir_path, exist_ok=True)
    restringir_a_dueno(str(dir_path))
    frase = _frase_de_entorno() or _frase_de_llavero(str(dir_path), crear=True)
    cifrado = (serialization.BestAvailableEncryption(frase) if frase
               else serialization.NoEncryption())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=cifrado,
    )
    escribir_privado(os.path.join(dir_path, "private_key.pem"), pem)
    if frase is None:
        try:
            from .utils.error_log import log_internal_error
            log_internal_error(
                "LIB-I2: no hay llavero del sistema ni AUDIT_TRACER_KEY_PASSPHRASE; la llave de firma "
                "quedó sin cifrar (permisos de solo-dueño)", None)
        except Exception:
            pass

def save_public_key(public_key: ed25519.Ed25519PublicKey, dir_path: str) -> None:
    """Guarda la llave pública en disco en formato PEM SubjectPublicKeyInfo."""
    os.makedirs(dir_path, exist_ok=True)
    pem = public_key_to_pem(public_key)
    key_path = os.path.join(dir_path, "public_key.pem")
    with open(key_path, "w") as f:
        f.write(pem)

class LlaveInaccesibleError(ValueError):
    """La llave privada está cifrada y no se encontró la frase que la abre."""


def load_private_key(dir_path: str) -> Optional[ed25519.Ed25519PrivateKey]:
    """Carga la llave privada desde el disco si existe (cifrada o, en versiones anteriores, en claro)."""
    key_path = os.path.join(dir_path, "private_key.pem")
    if not os.path.exists(key_path):
        return None
    with open(key_path, "rb") as f:
        pem = f.read()
    if b"ENCRYPTED" not in pem:
        return serialization.load_pem_private_key(pem, password=None)
    for frase in (_frase_de_entorno(), _frase_de_llavero(str(dir_path), crear=False)):
        if frase:
            try:
                return serialization.load_pem_private_key(pem, password=frase)
            except (ValueError, TypeError):
                continue
    raise LlaveInaccesibleError(
        "La llave privada está cifrada y no se encontró su frase (llavero del sistema o "
        "AUDIT_TRACER_KEY_PASSPHRASE).")


def llave_esta_cifrada(dir_path: str) -> bool:
    key_path = os.path.join(dir_path, "private_key.pem")
    try:
        with open(key_path, "rb") as f:
            return b"ENCRYPTED" in f.read()
    except OSError:
        return False

def load_public_key(dir_path: str) -> Optional[ed25519.Ed25519PublicKey]:
    """Carga la llave pública desde el disco si existe."""
    key_path = os.path.join(dir_path, "public_key.pem")
    if not os.path.exists(key_path):
        return None
    with open(key_path, "rb") as f:
        pem = f.read()
    return serialization.load_pem_public_key(pem)

_keypair_cache: Dict[str, Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]] = {}


def get_or_create_user_keypair(dir_path: str = None) -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """
    Obtiene el par de llaves del usuario desde el directorio local.
    Si no existe, genera uno nuevo y lo guarda (PDGTRAZDSA-140).

    HU-5.1: por defecto en `~/.audit_tracer/keys` (no en el directorio de
    trabajo, para que el par no cambie al cambiar de carpeta) y cacheado en
    memoria, porque se usa para firmar cada evento capturado.
    """
    if dir_path is None:
        from audit_tracer.utils.paths import keys_dir
        dir_path = keys_dir()
    cache_key = os.path.abspath(str(dir_path))
    cached = _keypair_cache.get(cache_key)
    if cached is not None and os.path.exists(os.path.join(cache_key, "private_key.pem")):
        return cached

    try:
        private_key = load_private_key(dir_path)
    except LlaveInaccesibleError as exc:
        # La frase se perdió (otro usuario, llavero borrado): se conserva el
        # archivo con otro nombre y se crea un par nuevo, que el servidor
        # registrará como llave adicional (con aviso de equipo nuevo).
        from .utils.error_log import log_internal_error
        respaldo = os.path.join(dir_path, f"private_key.inaccesible-{int(time.time())}.pem")
        os.replace(os.path.join(dir_path, "private_key.pem"), respaldo)
        log_internal_error(f"LIB-I2: llave privada inaccesible, se generó un par nuevo ({respaldo})", exc)
        private_key = None
    public_key = load_public_key(dir_path)

    if private_key is None or public_key is None:
        private_key, public_key = generate_keypair()
        save_private_key(private_key, dir_path)
        save_public_key(public_key, dir_path)
    elif not llave_esta_cifrada(dir_path) and proteccion_disponible(dir_path):
        save_private_key(private_key, dir_path)   # LIB-I2: migrar una llave en claro de versiones anteriores

    _keypair_cache[cache_key] = (private_key, public_key)
    return private_key, public_key

def public_key_to_pem(public_key: ed25519.Ed25519PublicKey) -> str:
    """Exporta la llave pública a string PEM."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode('utf-8')

def public_key_from_pem(pem_str: str) -> ed25519.Ed25519PublicKey:
    """Importa la llave pública desde un string PEM."""
    return serialization.load_pem_public_key(pem_str.encode('utf-8'))


# ── FIRMA EN LA LIBRERÍA (PDGTRAZDSA-141) ───────────────────────────────────

def sign_event(evento: Dict, private_key: ed25519.Ed25519PrivateKey) -> str:
    """
    CA2 — Firma el evento con la llave privada.
    Retorna la firma cruda codificada en Base64url (sin padding).
    """
    mensaje = _canonical_message(evento)
    raw_signature = private_key.sign(mensaje)
    # Codificamos en base64url y quitamos el padding ('=')
    return base64.urlsafe_b64encode(raw_signature).decode('utf-8').rstrip('=')

def add_signature_to_event(evento: Dict, private_key: ed25519.Ed25519PrivateKey) -> Dict:
    """
    Firma una copia del evento y le adjunta el campo 'firma_digital'.
    """
    evento_firmado = dict(evento)
    firma = sign_event(evento_firmado, private_key)
    evento_firmado["firma_digital"] = firma
    return evento_firmado


# ── VALIDACIÓN EN EL SERVIDOR (PDGTRAZDSA-142) ──────────────────────────────

def verify_event_signature(evento: Dict, public_key_pem: str) -> bool:
    """
    CA3 — Valida la firma_digital de un evento utilizando la llave pública PEM.
    """
    firma_b64 = evento.get("firma_digital")
    if not firma_b64:
        return False
        
    try:
        public_key = public_key_from_pem(public_key_pem)
        mensaje = _canonical_message(evento)
        
        # Restaurar padding de base64url si es necesario
        padding = '=' * (-len(firma_b64) % 4)
        raw_signature = base64.urlsafe_b64decode(firma_b64 + padding)
        
        public_key.verify(raw_signature, mensaje)
        return True
    except Exception:
        # Falla la decodificación PEM, base64, o la verificación criptográfica
        return False


# ── VERIFICACIÓN POSTERIOR (PDGTRAZDSA-143) ─────────────────────────────────

def verify_signature(conn: sqlite3.Connection, event_id: int, public_key_pem: str) -> Dict:
    """
    CA5 — Verifica la firma de un evento ya persistido en audit_log.
    """
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM audit_log WHERE event_id = ?", (event_id,)).fetchone()
    
    if not row:
        raise ValueError(f"No se encontró el evento con event_id={event_id}")
        
    evento = dict(row)
    firma_presente = bool(evento.get("firma_digital"))
    
    if not firma_presente:
        return {
            "event_id": event_id,
            "evento_uuid": evento.get("evento_uuid"),
            "usuario_id": evento.get("usuario_id"),
            "firma_presente": False,
            "firma_valida": False,
            "mensaje": "El evento no tiene firma digital."
        }
        
    valida = verify_event_signature(evento, public_key_pem)
    
    return {
        "event_id": event_id,
        "evento_uuid": evento.get("evento_uuid"),
        "usuario_id": evento.get("usuario_id"),
        "firma_presente": True,
        "firma_valida": valida,
        "mensaje": "Firma válida." if valida else "Firma INVÁLIDA."
    }
