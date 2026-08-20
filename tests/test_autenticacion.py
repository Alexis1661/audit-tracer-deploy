import pytest
import os
from audit_tracer.db import get_connection
from audit_tracer.auth.registro import register_user
from audit_tracer.auth.autenticacion import login
from audit_tracer.models.usuarios import get_user_by_email
from audit_tracer.models.audit_log import get_events

@pytest.fixture
def db_conn():
    conn = get_connection(":memory:")
    yield conn
    conn.close()

def test_login_success(db_conn):
    """Login exitoso retorna success=True con usuario_id, rol, sesion_id y registra evento."""
    email = "user@test.com"
    pwd = "secretpassword"
    user_id = register_user(db_conn, email, pwd, "CIENTIFICO_DATOS", "admin")
    
    sesion_id = "session123"
    result = login(db_conn, email, pwd, sesion_id)
    
    assert result['success'] is True
    assert result['usuario_id'] == user_id
    assert result['rol'] == "CIENTIFICO_DATOS"
    assert result['sesion_id'] == sesion_id
    
    # Check audit log
    events = get_events(db_conn, tipo_accion='INICIO_SESION', usuario_id=user_id)
    assert len(events) == 1

def test_login_invalid_credentials(db_conn):
    """Login incorrecto retorna success=False con mensaje genérico y registra evento."""
    email = "user@test.com"
    register_user(db_conn, email, "real_pwd", "ANALISTA", "admin")
    
    result = login(db_conn, email, "wrong_pwd", "session_fail")
    assert result['success'] is False
    assert result['message'] == 'Credenciales inválidas'
    
    # Check audit log
    user = get_user_by_email(db_conn, email)
    events = get_events(db_conn, tipo_accion='ACCESO_FALLIDO', usuario_id=user['usuario_id'])
    assert len(events) == 1

def test_user_blocking(db_conn):
    """5 intentos fallidos -> usuario bloqueado (activo=0)."""
    email = "blocked@test.com"
    register_user(db_conn, email, "pwd", "ANALISTA", "admin")
    user = get_user_by_email(db_conn, email)
    user_id = user['usuario_id']
    
    for i in range(4):
        result = login(db_conn, email, "wrong", f"s{i}")
        assert result['success'] is False
        assert "bloqueada" not in result['message']
    
    # 5th attempt
    result = login(db_conn, email, "wrong", "s4")
    assert result['success'] is False
    assert "bloqueada" in result['message']
    
    # Verify in DB
    user_after = get_user_by_email(db_conn, email)
    assert user_after['activo'] == 0
    
    # Verify critical event
    events = get_events(db_conn, nivel_alerta='CRITICO', usuario_id=user_id)
    assert len(events) == 1
    assert "5 intentos fallidos" in events[0]['motivo_alerta']
