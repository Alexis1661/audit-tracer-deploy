import sqlite3
from ..models.usuarios import create_user
from ..models.audit_log import insert_event
from ..utils.session import generate_session_id
from datetime import datetime

VALID_ROLES = ['ADMIN', 'ANALISTA', 'AUDITOR', 'CIENTIFICO_DATOS']

def register_user(conn: sqlite3.Connection, email: str, password: str, rol: str, admin_id: str) -> str:
    """
    Registers a new user in the system.

    Args:
        conn (sqlite3.Connection): Database connection.
        email (str): Email for the new user.
        password (str): Password for the new user.
        rol (str): Role for the new user.
        admin_id (str): ID of the admin performing the registration.

    Returns:
        str: The newly created user ID.

    Raises:
        ValueError: If role is invalid or email already exists.
    """
    if rol not in VALID_ROLES:
        raise ValueError(f"Rol inválido: {rol}. Roles permitidos: {', '.join(VALID_ROLES)}")

    # Create the user (this handles email duplication check and hashing)
    new_user_id = create_user(conn, email, password, rol)

    # Log the event
    event = {
        'usuario_id': admin_id,
        'sesion_id': generate_session_id(),
        'timestamp': datetime.utcnow().isoformat(),
        'tipo_accion': 'CREACION_USUARIO',
        'contexto_ejecucion': new_user_id,
        'nivel_alerta': 'NORMAL'
    }
    insert_event(conn, event)

    return new_user_id
