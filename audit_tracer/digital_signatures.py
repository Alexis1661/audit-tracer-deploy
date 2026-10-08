"""
audit_tracer/digital_signatures.py
==================================
HU-6.1 — Firmas digitales de eventos de auditoría.

Este módulo implementa la lógica criptográfica para firmar los eventos
generados localmente y verificar dichas firmas en el servidor central.
Utiliza el algoritmo Ed25519, que es un esquema de firma de llave pública
rápido, determinista y seguro contra ataques de canal lateral (Side-channel).
"""

import base64
import json
import os
import sqlite3
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

def save_private_key(private_key: ed25519.Ed25519PrivateKey, dir_path: str) -> None:
    """Guarda la llave privada en disco en formato PEM PKCS8 (sin cifrar)."""
    os.makedirs(dir_path, exist_ok=True)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    key_path = os.path.join(dir_path, "private_key.pem")
    with open(key_path, "wb") as f:
        f.write(pem)

def save_public_key(public_key: ed25519.Ed25519PublicKey, dir_path: str) -> None:
    """Guarda la llave pública en disco en formato PEM SubjectPublicKeyInfo."""
    os.makedirs(dir_path, exist_ok=True)
    pem = public_key_to_pem(public_key)
    key_path = os.path.join(dir_path, "public_key.pem")
    with open(key_path, "w") as f:
        f.write(pem)

def load_private_key(dir_path: str) -> Optional[ed25519.Ed25519PrivateKey]:
    """Carga la llave privada desde el disco si existe."""
    key_path = os.path.join(dir_path, "private_key.pem")
    if not os.path.exists(key_path):
        return None
    with open(key_path, "rb") as f:
        pem = f.read()
    return serialization.load_pem_private_key(pem, password=None)

def load_public_key(dir_path: str) -> Optional[ed25519.Ed25519PublicKey]:
    """Carga la llave pública desde el disco si existe."""
    key_path = os.path.join(dir_path, "public_key.pem")
    if not os.path.exists(key_path):
        return None
    with open(key_path, "rb") as f:
        pem = f.read()
    return serialization.load_pem_public_key(pem)

def get_or_create_user_keypair(dir_path: str = ".audit_keys") -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """
    Obtiene el par de llaves del usuario desde el directorio local.
    Si no existe, genera uno nuevo y lo guarda (PDGTRAZDSA-140).
    """
    private_key = load_private_key(dir_path)
    public_key = load_public_key(dir_path)
    
    if private_key is None or public_key is None:
        private_key, public_key = generate_keypair()
        save_private_key(private_key, dir_path)
        save_public_key(public_key, dir_path)
        
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
