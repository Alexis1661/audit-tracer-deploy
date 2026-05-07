import sqlite3
import uuid
from typing import Optional, Dict
from ..utils.hashing import hash_password

def create_user(conn: sqlite3.Connection, email: str, password: str, rol: str) -> str:
    """
    Creates a new user in the database.

    Args:
        conn (sqlite3.Connection): Database connection.
        email (str): User email.
        password (str): Plain text password.
        rol (str): User role.

    Returns:
        str: The newly created user's ID (UUID).

    Raises:
        ValueError: If email is already registered.
    """
    user_id = str(uuid.uuid4())
    hashed_pwd = hash_password(password)
    
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO usuarios (usuario_id, email, password_hash, rol, activo, intentos_fallidos) VALUES (?, ?, ?, ?, 1, 0)",
            (user_id, email, hashed_pwd, rol)
        )
        conn.commit()
        return user_id
    except sqlite3.IntegrityError as e:
        if "UNIQUE constraint failed: usuarios.email" in str(e):
            raise ValueError(f"El email {email} ya se encuentra registrado.")
        raise e

def get_user_by_email(conn: sqlite3.Connection, email: str) -> Optional[Dict]:
    """
    Retrieves a user by email.

    Args:
        conn (sqlite3.Connection): Database connection.
        email (str): User email.

    Returns:
        Optional[Dict]: User data dictionary or None if not found.
    """
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE email = ?", (email,))
    row = cursor.fetchone()
    return dict(row) if row else None

def increment_failed_attempts(conn: sqlite3.Connection, usuario_id: str) -> int:
    """
    Increments the failed login attempts for a user.

    Args:
        conn (sqlite3.Connection): Database connection.
        usuario_id (str): User ID.

    Returns:
        int: Updated number of failed attempts.
    """
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE usuarios SET intentos_fallidos = intentos_fallidos + 1 WHERE usuario_id = ?",
        (usuario_id,)
    )
    conn.commit()
    
    cursor.execute("SELECT intentos_fallidos FROM usuarios WHERE usuario_id = ?", (usuario_id,))
    result = cursor.fetchone()
    return result[0] if result else 0

def reset_failed_attempts(conn: sqlite3.Connection, usuario_id: str):
    """
    Resets the failed login attempts to 0.

    Args:
        conn (sqlite3.Connection): Database connection.
        usuario_id (str): User ID.
    """
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET intentos_fallidos = 0 WHERE usuario_id = ?", (usuario_id,))
    conn.commit()

def block_user(conn: sqlite3.Connection, usuario_id: str):
    """
    Blocks a user by setting activo = 0.

    Args:
        conn (sqlite3.Connection): Database connection.
        usuario_id (str): User ID.
    """
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET activo = 0 WHERE usuario_id = ?", (usuario_id,))
    conn.commit()

def get_all_users(conn: sqlite3.Connection) -> list:
    """Retrieves all users from the database."""
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT usuario_id, email, rol, activo FROM usuarios")
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

def get_user_by_id(conn: sqlite3.Connection, usuario_id: str) -> Optional[Dict]:
    """Retrieves a user by ID."""
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM usuarios WHERE usuario_id = ?", (usuario_id,))
    row = cursor.fetchone()
    return dict(row) if row else None

def update_user_role(conn: sqlite3.Connection, usuario_id: str, new_role: str):
    """Updates the role of a user."""
    cursor = conn.cursor()
    cursor.execute("UPDATE usuarios SET rol = ? WHERE usuario_id = ?", (new_role, usuario_id))
    conn.commit()

def count_active_admins(conn: sqlite3.Connection) -> int:
    """Counts the number of active administrators."""
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM usuarios WHERE rol = 'ADMIN' AND activo = 1")
    return cursor.fetchone()[0]
