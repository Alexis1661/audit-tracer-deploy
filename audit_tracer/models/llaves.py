"""
audit_tracer/models/llaves.py
=============================
SRV-S2 / SRV-R2 (21/11/2026) — Historial de llaves públicas Ed25519.

Antes, cada registro de llave reemplazaba la anterior en usuarios.llave_publica
sin dejar rastro: con un token robado se podía poner una llave propia y las
firmas viejas de la víctima dejaban de verificarse. Ahora:

  * Un usuario puede tener varias llaves activas (una por equipo o runtime de
    Colab). Registrar una llave nueva deja un evento REGISTRO_LLAVE_PUBLICA
    (ADVERTENCIA si ya tenía otra activa, que dispara la alerta de "equipo
    nuevo").
  * Nada se borra: una llave revocada por un ADMIN deja de aceptar eventos
    nuevos, pero sigue verificando los que llegaron antes de la revocación.
  * Una llave revocada no puede volver a registrarse.

usuarios.llave_publica se conserva con la última llave registrada por
compatibilidad (la leen versiones anteriores del dashboard y algunas pruebas).
"""

import hashlib
import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .usuarios import set_user_public_key

_DDL = """
CREATE TABLE IF NOT EXISTS llaves_publicas (
    llave_id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    usuario_id        TEXT     NOT NULL REFERENCES usuarios(usuario_id),
    llave_publica     TEXT     NOT NULL,
    huella            TEXT     NOT NULL,
    token_id          TEXT,
    registrada_en     TEXT     NOT NULL,
    revocada_en       TEXT,
    revocada_por      TEXT,
    UNIQUE (usuario_id, huella)
);
CREATE INDEX IF NOT EXISTS idx_llaves_usuario ON llaves_publicas(usuario_id);
"""


def _ensure(conn: sqlite3.Connection) -> None:
    conn.executescript(_DDL)


def huella(llave_pem: str) -> str:
    """Identificador corto y estable de una llave: primeros 16 hex del SHA-256 del PEM."""
    return hashlib.sha256(llave_pem.strip().encode("utf-8")).hexdigest()[:16]


def _filas(conn: sqlite3.Connection, sql: str, params: tuple) -> List[Dict]:
    cursor = conn.execute(sql, params)
    nombres = [d[0] for d in cursor.description]
    return [dict(zip(nombres, fila)) for fila in cursor.fetchall()]


def listar_llaves(conn: sqlite3.Connection, usuario_id: str) -> List[Dict]:
    _ensure(conn)
    return _filas(conn, "SELECT * FROM llaves_publicas WHERE usuario_id = ? ORDER BY llave_id", (usuario_id,))


def llaves_activas(conn: sqlite3.Connection, usuario_id: str) -> List[Dict]:
    return [ll for ll in listar_llaves(conn, usuario_id) if not ll["revocada_en"]]


def registrar_llave(conn: sqlite3.Connection, usuario_id: str, llave_pem: str,
                    token_id: Optional[str] = None) -> Dict:
    """
    Registra `llave_pem` para el usuario.

    Returns:
        {'estado': 'NUEVA' | 'YA_REGISTRADA' | 'REVOCADA', 'huella', 'activas_previas'}
        'REVOCADA' significa que esa llave fue revocada y no se reactivó.
    """
    _ensure(conn)
    marca = huella(llave_pem)
    existente = conn.execute(
        "SELECT revocada_en FROM llaves_publicas WHERE usuario_id = ? AND huella = ?",
        (usuario_id, marca)).fetchone()
    if existente is not None:
        return {"estado": "REVOCADA" if existente[0] else "YA_REGISTRADA", "huella": marca,
                "activas_previas": len(llaves_activas(conn, usuario_id))}

    activas_previas = len(llaves_activas(conn, usuario_id))
    conn.execute(
        "INSERT INTO llaves_publicas (usuario_id, llave_publica, huella, token_id, registrada_en) "
        "VALUES (?, ?, ?, ?, ?)",
        (usuario_id, llave_pem, marca, token_id, datetime.utcnow().isoformat()))
    conn.commit()
    set_user_public_key(conn, usuario_id, llave_pem)
    return {"estado": "NUEVA", "huella": marca, "activas_previas": activas_previas}


def revocar_llave(conn: sqlite3.Connection, llave_id: int, revocada_por: str) -> Optional[Dict]:
    """Revoca una llave (no la borra). Devuelve la fila revocada, o None si no existía o ya estaba revocada."""
    _ensure(conn)
    cursor = conn.execute(
        "UPDATE llaves_publicas SET revocada_en = ?, revocada_por = ? WHERE llave_id = ? AND revocada_en IS NULL",
        (datetime.utcnow().isoformat(), revocada_por, llave_id))
    conn.commit()
    if cursor.rowcount == 0:
        return None
    fila = _filas(conn, "SELECT * FROM llaves_publicas WHERE llave_id = ?", (llave_id,))[0]
    activas = llaves_activas(conn, fila["usuario_id"])
    set_user_public_key(conn, fila["usuario_id"], activas[-1]["llave_publica"] if activas else None)
    return fila


def usuario_tiene_llaves(conn: sqlite3.Connection, usuario_id: str) -> bool:
    """True si el usuario registró alguna llave alguna vez (activa o revocada)."""
    _ensure(conn)
    fila = conn.execute("SELECT 1 FROM llaves_publicas WHERE usuario_id = ? LIMIT 1", (usuario_id,)).fetchone()
    if fila:
        return True
    # Bases anteriores a esta tabla que todavía no pasaron por la migración.
    fila = conn.execute("SELECT llave_publica FROM usuarios WHERE usuario_id = ?", (usuario_id,)).fetchone()
    return bool(fila and fila[0])


def verificar_con_historial(conn: sqlite3.Connection, evento: Dict, instante: Optional[str] = None,
                            usuario_id: Optional[str] = None) -> Tuple[bool, Optional[str]]:
    """
    Verifica la firma de `evento` con las llaves del usuario vigentes en
    `instante` (por defecto, ahora): activas, o revocadas después de ese
    instante. Así un evento que llegó antes de revocar una llave sigue
    verificándose, y uno nuevo firmado con una llave revocada no.

    `usuario_id` (por defecto, el del evento) es de quién se toman las
    llaves: al sincronizar es el dueño del token, que también firma los
    eventos capturados antes del login (usuario DESCONOCIDO).

    Returns:
        (firma_valida, huella_de_la_llave_que_verificó | None)
    """
    from ..digital_signatures import verify_event_signature

    if not evento.get("firma_digital"):
        return False, None
    _ensure(conn)
    instante = instante or datetime.utcnow().isoformat()
    usuario_id = usuario_id or evento.get("usuario_id")
    candidatas = _filas(
        conn,
        "SELECT llave_publica, huella FROM llaves_publicas WHERE usuario_id = ? "
        "AND (revocada_en IS NULL OR revocada_en > ?) ORDER BY llave_id DESC",
        (usuario_id, instante))
    if not candidatas:
        fila = conn.execute("SELECT llave_publica FROM usuarios WHERE usuario_id = ?", (usuario_id,)).fetchone()
        if fila and fila[0] and not conn.execute(
                "SELECT 1 FROM llaves_publicas WHERE usuario_id = ? LIMIT 1", (usuario_id,)).fetchone():
            candidatas = [{"llave_publica": fila[0], "huella": huella(fila[0])}]
    for llave in candidatas:
        if verify_event_signature(evento, llave["llave_publica"]):
            return True, llave["huella"]
    return False, None
