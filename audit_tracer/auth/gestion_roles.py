import sqlite3
from ..models.usuarios import get_user_by_id, update_user_role, count_active_admins
from ..models.audit_log import insert_event
from ..utils.session import generate_session_id
from datetime import datetime

VALID_ROLES = ['ADMIN', 'ANALISTA', 'AUDITOR', 'CIENTIFICO_DATOS']

def assign_role(conn: sqlite3.Connection, admin_id: str, target_usuario_id: str, new_role: str):
    """
    Assigns or modifies the role of a user.
    Includes validation and audit logging.
    """
    if new_role not in VALID_ROLES:
        raise ValueError(f"Rol inválido: {new_role}. Roles permitidos: {', '.join(VALID_ROLES)}")

    # Get target user to check current role
    user = get_user_by_id(conn, target_usuario_id)
    if not user:
        raise ValueError("El usuario destino no existe.")

    old_role = user['rol']
    
    # CA6: Protection of last active admin
    if old_role == 'ADMIN' and new_role != 'ADMIN':
        active_admins = count_active_admins(conn)
        if active_admins <= 1:
            raise ValueError("No es posible cambiar el rol del único administrador activo del sistema.")

    # Update role
    update_user_role(conn, target_usuario_id, new_role)

    # CA5: Log change in audit_log
    event = {
        'usuario_id': admin_id,
        'sesion_id': generate_session_id(),
        'timestamp': datetime.utcnow().isoformat(),
        'tipo_accion': 'MODIFICACION_ROL',
        'contexto_ejecucion': f"Usuario: {target_usuario_id} | {old_role} -> {new_role}",
        'nivel_alerta': 'ADVERTENCIA' if new_role == 'ADMIN' or old_role == 'ADMIN' else 'NORMAL'
    }
    insert_event(conn, event)
    
    return True
