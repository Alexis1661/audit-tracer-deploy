"""
device_codes.py — Modelo de acceso a datos para el login por código de
dispositivo (HU-5.7).

Mismo patrón que models/tokens.py: la tabla se crea de forma perezosa
(_ensure_device_codes_table) en la conexión que se le pase, sin tocar
audit_tracer/schema/*.sql ni las migraciones aditivas de db.py.

No está sujeta a los triggers de inmutabilidad de audit_log (HU-5.4):
esos triggers están definidos `BEFORE UPDATE/DELETE ON audit_log`
específicamente, no sobre esta tabla. codigos_dispositivo es, igual que
tokens_acceso, metadata operativa que necesita mutar (PENDIENTE ->
CONFIRMADO -> CONSUMIDO), no el evento auditado en sí.

SRV-I1 (21/11/2026) — `device_code` guarda solo su SHA-256 y la columna
`token` ya no se llena: el token se genera en el polling que lo entrega
(auth/device_codes.py), así nunca queda en claro en la base.
CAN-S2 — se guardan la IP, el agente y el equipo que iniciaron el flujo para
mostrarlos en la página de confirmación.
"""

import hashlib
import secrets
import sqlite3
import string
from datetime import datetime, timedelta
from typing import Dict, Optional

# Alfabeto sin caracteres ambiguos al teclear (0/O, 1/I).
_ALFABETO_CODIGO = "".join(c for c in (string.ascii_uppercase + string.digits) if c not in "01OI")

_COLUMNAS_NUEVAS = ("ip_origen", "agente_origen", "host_origen", "sesion_confirmacion")


def hash_device_code(device_code: str) -> str:
    """Lo que se guarda y se busca: el SHA-256 del device_code, nunca el valor."""
    return "sha256:" + hashlib.sha256(device_code.encode("utf-8")).hexdigest()


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
    columnas = {fila[1] for fila in conn.execute("PRAGMA table_info(codigos_dispositivo)")}
    for columna in _COLUMNAS_NUEVAS:
        if columna not in columnas:
            conn.execute(f"ALTER TABLE codigos_dispositivo ADD COLUMN {columna} TEXT")
    if "token" in columnas:
        # Bases anteriores: ningún token en claro sobrevive a la migración.
        conn.execute("UPDATE codigos_dispositivo SET token = NULL WHERE token IS NOT NULL")
        conn.commit()


def _generar_codigo_legible() -> str:
    """8 caracteres agrupados 'XXXX-XXXX' — corto y fácil de teclear desde el navegador."""
    raw = "".join(secrets.choice(_ALFABETO_CODIGO) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


def _recortar(valor, largo: int) -> Optional[str]:
    if not valor:
        return None
    return str(valor)[:largo]


def insert_device_code(conn: sqlite3.Connection, fecha_expiracion: str, origen: Optional[Dict] = None) -> Dict:
    """
    CA1 — Crea un nuevo código PENDIENTE con su device_code (credencial
    secreta y larga que solo conoce quien inició el flujo, usada para el
    polling — el codigo corto que ve el humano NO alcanza para consultar
    el estado, así nadie puede "adivinar" el código de otra persona y
    robarle el token por esa vía).

    `origen` (opcional): {'ip', 'agente', 'host'} de quien inició el flujo (CAN-S2).

    Returns:
        Dict: {codigo, device_code, fecha_creacion, fecha_expiracion}. El
        device_code en claro solo existe en este valor de retorno.
    """
    _ensure_device_codes_table(conn)
    device_code = secrets.token_urlsafe(32)
    fecha_creacion = datetime.utcnow().isoformat()
    codigo = _generar_codigo_legible()
    origen = origen or {}

    cursor = conn.cursor()
    for _ in range(5):  # colisión del código corto: extremadamente improbable, pero es la PK
        try:
            cursor.execute(
                "INSERT INTO codigos_dispositivo "
                "(codigo, device_code, estado, fecha_creacion, fecha_expiracion, ip_origen, agente_origen, host_origen) "
                "VALUES (?, ?, 'PENDIENTE', ?, ?, ?, ?, ?)",
                (codigo, hash_device_code(device_code), fecha_creacion, fecha_expiracion,
                 _recortar(origen.get("ip"), 64), _recortar(origen.get("agente"), 200),
                 _recortar(origen.get("host"), 120)),
            )
            conn.commit()
            break
        except sqlite3.IntegrityError:
            conn.rollback()
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
    row = conn.execute("SELECT * FROM codigos_dispositivo WHERE device_code = ?",
                       (hash_device_code(device_code),)).fetchone()
    return dict(row) if row else None


def confirmar_codigo(conn: sqlite3.Connection, codigo: str, usuario_id: str, sesion_id: Optional[str] = None) -> bool:
    """CA2 — Asocia el código a usuario_id. Solo aplica si seguía PENDIENTE. No guarda ningún token."""
    _ensure_device_codes_table(conn)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE codigos_dispositivo SET estado = 'CONFIRMADO', usuario_id = ?, sesion_confirmacion = ?, token = NULL "
        "WHERE codigo = ? AND estado = 'PENDIENTE'",
        (usuario_id, sesion_id, codigo),
    )
    conn.commit()
    return cursor.rowcount > 0


def marcar_consumido_si_confirmado(conn: sqlite3.Connection, codigo: str) -> bool:
    """
    Pasa el código de CONFIRMADO a CONSUMIDO de forma atómica. Solo el polling
    que gana esta transición recibe un token: dos consultas simultáneas con el
    mismo device_code nunca obtienen dos tokens.
    """
    _ensure_device_codes_table(conn)
    cursor = conn.execute(
        "UPDATE codigos_dispositivo SET estado = 'CONSUMIDO', token = NULL WHERE codigo = ? AND estado = 'CONFIRMADO'",
        (codigo,),
    )
    conn.commit()
    return cursor.rowcount > 0


def marcar_consumido(conn: sqlite3.Connection, device_code: str) -> None:
    """Marca el código como CONSUMIDO (el token ya se entregó)."""
    _ensure_device_codes_table(conn)
    conn.execute(
        "UPDATE codigos_dispositivo SET estado = 'CONSUMIDO', token = NULL WHERE device_code = ?",
        (hash_device_code(device_code),),
    )
    conn.commit()


def marcar_expirado(conn: sqlite3.Connection, device_code: str) -> None:
    _ensure_device_codes_table(conn)
    conn.execute(
        "UPDATE codigos_dispositivo SET estado = 'EXPIRADO' WHERE device_code = ?",
        (hash_device_code(device_code),),
    )
    conn.commit()


def marcar_expirado_por_codigo(conn: sqlite3.Connection, codigo: str) -> None:
    _ensure_device_codes_table(conn)
    conn.execute("UPDATE codigos_dispositivo SET estado = 'EXPIRADO' WHERE codigo = ?", (codigo,))
    conn.commit()


def purgar_codigos_vencidos(conn: sqlite3.Connection, antes_de: Optional[str] = None) -> int:
    """
    SRV-D1 — Borra los códigos que vencieron hace más de un día y ya no
    pueden usarse. No son eventos de auditoría: la confirmación y la
    generación del token quedan en audit_log.
    """
    _ensure_device_codes_table(conn)
    limite = antes_de or (datetime.utcnow() - timedelta(days=1)).isoformat()
    cursor = conn.execute("DELETE FROM codigos_dispositivo WHERE fecha_expiracion < ?", (limite,))
    conn.commit()
    return cursor.rowcount
