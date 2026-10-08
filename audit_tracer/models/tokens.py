"""
tokens.py — Modelo de acceso a datos para la gestión de tokens personales de acceso.
HU-5.5 (PDGTRAZDSA-127, PDGTRAZDSA-128, PDGTRAZDSA-129, PDGTRAZDSA-130).
"""

import sqlite3
import uuid
from datetime import datetime
from typing import Dict, List, Optional


def _ensure_tokens_table(conn: sqlite3.Connection) -> None:
    """Garantiza que la tabla tokens_acceso e índices existan en la conexión."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tokens_acceso (
            token_id          TEXT     PRIMARY KEY,
            usuario_id        TEXT     NOT NULL,
            token             TEXT     NOT NULL UNIQUE,
            fecha_creacion    TEXT     NOT NULL,
            fecha_expiracion  TEXT     NOT NULL,
            estado            TEXT     NOT NULL DEFAULT 'ACTIVO',
            creado_por        TEXT     NOT NULL DEFAULT 'LOGIN',
            FOREIGN KEY (usuario_id) REFERENCES usuarios(usuario_id)
        );
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens_acceso(token);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_usuario ON tokens_acceso(usuario_id);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_tokens_estado ON tokens_acceso(estado);")


def insert_token(conn: sqlite3.Connection, token_data: Dict) -> str:
    """
    Inserta un nuevo token en la base de datos.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        token_data (Dict): Diccionario con datos del token.
            Campos esperados:
              - token (str, obligatorio)
              - usuario_id (str, obligatorio)
              - fecha_creacion (str ISO 8601, opcional)
              - fecha_expiracion (str ISO 8601, obligatorio)
              - estado (str, opcional, por defecto 'ACTIVO')
              - creado_por (str, opcional, por defecto 'LOGIN')
              - token_id (str, opcional)

    Returns:
        str: token_id asignado.
    """
    token_id = token_data.get("token_id") or str(uuid.uuid4())
    usuario_id = token_data["usuario_id"]
    token = token_data["token"]
    fecha_creacion = token_data.get("fecha_creacion") or datetime.utcnow().isoformat()
    fecha_expiracion = token_data["fecha_expiracion"]
    estado = token_data.get("estado", "ACTIVO")
    creado_por = token_data.get("creado_por", "LOGIN")

    _ensure_tokens_table(conn)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO tokens_acceso (
            token_id, usuario_id, token, fecha_creacion, fecha_expiracion, estado, creado_por
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (token_id, usuario_id, token, fecha_creacion, fecha_expiracion, estado, creado_por)
    )
    conn.commit()
    return token_id


def get_token_by_value(conn: sqlite3.Connection, token_str: str) -> Optional[Dict]:
    """
    Obtiene un registro de token por su valor de cadena de texto.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        token_str (str): Cadena del token.

    Returns:
        Optional[Dict]: Registro del token o None si no existe.
    """
    _ensure_tokens_table(conn)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tokens_acceso WHERE token = ?", (token_str,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_token_by_id(conn: sqlite3.Connection, token_id: str) -> Optional[Dict]:
    """
    Obtiene un registro de token por su ID único.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        token_id (str): ID del token.

    Returns:
        Optional[Dict]: Registro del token o None si no existe.
    """
    _ensure_tokens_table(conn)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tokens_acceso WHERE token_id = ?", (token_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_tokens_by_user(
    conn: sqlite3.Connection,
    usuario_id: str,
    solo_activos: bool = False
) -> List[Dict]:
    """
    Obtiene todos los tokens asociados a un usuario.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        usuario_id (str): ID del usuario.
        solo_activos (bool): Si es True, filtra únicamente con estado 'ACTIVO'.

    Returns:
        List[Dict]: Lista de tokens ordenados por fecha de creación descendente.
    """
    _ensure_tokens_table(conn)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if solo_activos:
        cursor.execute(
            """
            SELECT * FROM tokens_acceso 
            WHERE usuario_id = ? AND estado = 'ACTIVO'
            ORDER BY fecha_creacion DESC
            """,
            (usuario_id,)
        )
    else:
        cursor.execute(
            """
            SELECT * FROM tokens_acceso 
            WHERE usuario_id = ? 
            ORDER BY fecha_creacion DESC
            """,
            (usuario_id,)
        )
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def get_all_tokens_with_user_info(
    conn: sqlite3.Connection,
    usuario_id: Optional[str] = None,
    estado: Optional[str] = None
) -> List[Dict]:
    """
    Obtiene todos los tokens con la información de usuario asociada (email, rol).

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        usuario_id (Optional[str]): Filtro por ID de usuario.
        estado (Optional[str]): Filtro por estado ('ACTIVO', 'REVOCADO', 'EXPIRADO').

    Returns:
        List[Dict]: Lista de tokens con datos del usuario.
    """
    _ensure_tokens_table(conn)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    query = """
        SELECT 
            t.token_id,
            t.usuario_id,
            t.token,
            t.fecha_creacion,
            t.fecha_expiracion,
            t.estado,
            t.creado_por,
            u.email,
            u.rol,
            u.activo as usuario_activo
        FROM tokens_acceso t
        LEFT JOIN usuarios u ON t.usuario_id = u.usuario_id
        WHERE 1=1
    """
    params = []
    
    if usuario_id:
        query += " AND t.usuario_id = ?"
        params.append(usuario_id)
        
    if estado:
        query += " AND t.estado = ?"
        params.append(estado.upper())
        
    query += " ORDER BY t.fecha_creacion DESC"
    
    cursor.execute(query, tuple(params))
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


def update_token_status(conn: sqlite3.Connection, token_id: str, nuevo_estado: str) -> bool:
    """
    Actualiza el estado de un token ('ACTIVO', 'REVOCADO', 'EXPIRADO').

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        token_id (str): ID del token.
        nuevo_estado (str): Nuevo estado.

    Returns:
        bool: True si se actualizó algún registro, False en caso contrario.
    """
    _ensure_tokens_table(conn)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE tokens_acceso SET estado = ? WHERE token_id = ?",
        (nuevo_estado.upper(), token_id)
    )
    conn.commit()
    return cursor.rowcount > 0


def revoke_token_by_id(conn: sqlite3.Connection, token_id: str) -> bool:
    """
    Revoca inmediatamente un token por su ID.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        token_id (str): ID del token.

    Returns:
        bool: True si fue revocado, False si no se encontró.
    """
    return update_token_status(conn, token_id, "REVOCADO")


def revoke_token_by_value(conn: sqlite3.Connection, token_str: str) -> bool:
    """
    Revoca inmediatamente un token por su valor de cadena.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        token_str (str): Cadena del token.

    Returns:
        bool: True si fue revocado, False si no se encontró.
    """
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE tokens_acceso SET estado = 'REVOCADO' WHERE token = ?",
        (token_str,)
    )
    conn.commit()
    return cursor.rowcount > 0
