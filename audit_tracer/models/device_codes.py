"""
device_codes.py — Modelo de acceso a datos para el login por código de
dispositivo (HU-5.7).

Mismo patrón que models/tokens.py: la tabla se crea de forma perezosa
(_ensure_device_codes_table) en la conexión que se le pase, sin tocar
schema/*.sql ni las migraciones aditivas de db.py.

No está sujeta a los triggers de inmutabilidad de audit_log (HU-5.4):
esos triggers están definidos `BEFORE UPDATE/DELETE ON audit_log`
específicamente, no sobre esta tabla. codigos_dispositivo es, igual que
tokens_acceso, metadata operativa que necesita mutar (PENDIENTE ->
CONFIRMADO -> CONSUMIDO), no el evento auditado en sí.
"""

import secrets
import sqlite3
import string
from datetime import datetime
from typing import Dict, Optional

# Alfabeto sin caracteres ambiguos al teclear (0/O, 1/I).
_ALFABETO_CODIGO = "".join(c for c in (string.ascii_uppercase + string.digits) if c not in "01OI")


def _ensure_device_codes_table(conn: sqlite3.Connection) -> None:
    """Garantiza que la tabla codigos_dispositivo e índices existan en la conexión."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS codigos_dispositivo (
            codigo            TEXT     PRIMARY KEY,
            device_code       TEXT     NOT NULL UNIQUE,
            estado            TEXT     NOT NULL DEFAULT 'PENDIENTE',
            usuario_id        TEXT,
            token             TEXT,
            fecha_creacion    TEXT     NOT NULL,
            fecha_expiracion  TEXT     NOT NULL
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_codigos_device_code ON codigos_dispositivo(device_code);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_codigos_estado ON codigos_dispositivo(estado);")


def _generar_codigo_legible() -> str:
    """8 caracteres agrupados 'XXXX-XXXX' — corto y fácil de teclear desde el navegador."""
    raw = "".join(secrets.choice(_ALFABETO_CODIGO) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def insert_device_code(conn: sqlite3.Connection, fecha_expiracion: str) -> Dict:
    """
    CA1 — Crea un nuevo código PENDIENTE con su device_code (credencial
    secreta y larga que solo conoce quien inició el flujo, usada para el
    polling — el codigo corto que ve el humano NO alcanza para consultar
    el estado, así nadie puede "adivinar" el código de otra persona y
    robarle el token por esa vía).

    Returns:
        Dict: {codigo, device_code, fecha_creacion, fecha_expiracion}
    """
    _ensure_device_codes_table(conn)
    device_code = secrets.token_urlsafe(32)
    fecha_creacion = datetime.utcnow().isoformat()
    codigo = _generar_codigo_legible()

    cursor = conn.cursor()
    for _ in range(5):  # colisión del código corto: extremadamente improbable, pero es la PK
        try:
            cursor.execute(
                "INSERT INTO codigos_dispositivo "
                "(codigo, device_code, estado, fecha_creacion, fecha_expiracion) "
                "VALUES (?, ?, 'PENDIENTE', ?, ?)",
                (codigo, device_code, fecha_creacion, fecha_expiracion),
            )
            conn.commit()
            break
        except sqlite3.IntegrityError:
            codigo = _generar_codigo_legible()
    else:
        raise RuntimeError("No se pudo generar un código de dispositivo único")

    return {
        "codigo": codigo,
        "device_code": device_code,
        "fecha_creacion": fecha_creacion,
        "fecha_expiracion": fecha_expiracion,
    }


def get_by_codigo(conn: sqlite3.Connection, codigo: str) -> Optional[Dict]:
    _ensure_device_codes_table(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM codigos_dispositivo WHERE codigo = ?", (codigo,)).fetchone()
    return dict(row) if row else None


def get_by_device_code(conn: sqlite3.Connection, device_code: str) -> Optional[Dict]:
    _ensure_device_codes_table(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT * FROM codigos_dispositivo WHERE device_code = ?", (device_code,)).fetchone()
    return dict(row) if row else None


def confirmar_codigo(conn: sqlite3.Connection, codigo: str, usuario_id: str, token: str) -> bool:
    """CA2 — Asocia el código a usuario_id y al token ya generado. Solo aplica si seguía PENDIENTE."""
    _ensure_device_codes_table(conn)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE codigos_dispositivo SET estado = 'CONFIRMADO', usuario_id = ?, token = ? "
        "WHERE codigo = ? AND estado = 'PENDIENTE'",
        (usuario_id, token, codigo),
    )
    conn.commit()
    return cursor.rowcount > 0


def marcar_consumido(conn: sqlite3.Connection, device_code: str) -> None:
    """El token solo se entrega una vez por polling; tras entregarlo, se limpia de la tabla."""
    _ensure_device_codes_table(conn)
    conn.execute(
        "UPDATE codigos_dispositivo SET estado = 'CONSUMIDO', token = NULL WHERE device_code = ?",
        (device_code,),
    )
    conn.commit()


def marcar_expirado(conn: sqlite3.Connection, device_code: str) -> None:
    _ensure_device_codes_table(conn)
    conn.execute(
        "UPDATE codigos_dispositivo SET estado = 'EXPIRADO' WHERE device_code = ?",
        (device_code,),
    )
    conn.commit()
