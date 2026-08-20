import pytest
import os
from audit_tracer.db import get_connection
from audit_tracer.auth.registro import register_user
from audit_tracer.models.usuarios import get_user_by_email
from audit_tracer.models.audit_log import get_events
from audit_tracer.utils.hashing import verify_password

@pytest.fixture
def db_conn():
    conn = get_connection(":memory:")
    yield conn
    conn.close()

def test_register_user_success(db_conn):
    """register_user() crea usuario con todos los campos correctos y registra el evento."""
    admin_id = "admin_uuid"
    email = "test@example.com"
    pwd = "password123"
    rol = "ANALISTA"
    
    user_id = register_user(db_conn, email, pwd, rol, admin_id)
    assert user_id is not None
    
    # Verify user data
    user = get_user_by_email(db_conn, email)
    assert user['usuario_id'] == user_id
    assert user['rol'] == rol
    assert user['activo'] == 1
    assert verify_password(pwd, user['password_hash'])
    
    # Verify event in audit_log
    events = get_events(db_conn, tipo_accion='CREACION_USUARIO')
    assert len(events) == 1
    assert events[0]['usuario_id'] == admin_id
    assert events[0]['contexto_ejecucion'] == user_id

def test_register_duplicate_email(db_conn):
    """No permite emails duplicados (ValueError)."""
    register_user(db_conn, "test@example.com", "pwd", "ANALISTA", "admin")
    with pytest.raises(ValueError, match="ya se encuentra registrado"):
        register_user(db_conn, "test@example.com", "pwd2", "AUDITOR", "admin")

def test_register_invalid_rol(db_conn):
    """ValueError si rol inválido."""
    with pytest.raises(ValueError, match="Rol inválido"):
        register_user(db_conn, "test@example.com", "pwd", "HACKER", "admin")
