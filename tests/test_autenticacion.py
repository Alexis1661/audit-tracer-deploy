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

    # Verify critical events: el intento #4 ya dispara CRITICO por la ventana
    # de tiempo (HU-4.4 CA1-a: >3 intentos fallidos en <5 min), y el #5 por
    # el bloqueo de cuenta (contador acumulado).
    events = get_events(db_conn, nivel_alerta='CRITICO', usuario_id=user_id)
    assert len(events) == 2
    motivos = [e['motivo_alerta'] for e in events]
    assert any("5 intentos fallidos" in m for m in motivos)
    assert any("minutos" in m for m in motivos)


def test_intentos_fallidos_en_ventana_de_tiempo_genera_critico(db_conn):
    """HU-4.4 CA1-a: más de 3 intentos fallidos del mismo usuario en <5 min -> CRITICO."""
    email = "ventana@test.com"
    register_user(db_conn, email, "pwd", "ANALISTA", "admin")
    user = get_user_by_email(db_conn, email)
    user_id = user['usuario_id']

    # 3 intentos fallidos: todavía no debe ser CRITICO por ventana de tiempo
    for i in range(3):
        result = login(db_conn, email, "wrong", f"s{i}")
        assert result['success'] is False

    events = get_events(db_conn, nivel_alerta='CRITICO', usuario_id=user_id)
    assert len(events) == 0

    # 4to intento fallido, dentro de la ventana de 5 minutos -> CRITICO
    result = login(db_conn, email, "wrong", "s3")
    assert result['success'] is False
    assert "bloqueada" not in result['message']  # el bloqueo por cuenta ocurre en el 5to

    events = get_events(db_conn, nivel_alerta='CRITICO', usuario_id=user_id)
    assert len(events) == 1
    assert "intentos fallidos en menos de" in events[0]['motivo_alerta']


# ──────────────────────────────────────────────────────────────
# HU-2.5 CA2 — Login con email no registrado (usuario no identificable)
# ──────────────────────────────────────────────────────────────

def test_login_email_no_registrado_se_marca_desconocido_y_critico(db_conn):
    """CA2: email inexistente -> no hay usuario que autenticar, se registra
    DESCONOCIDO con nivel_alerta=CRITICO, y el evento no se pierde."""
    result = login(db_conn, "no_existe@test.com", "cualquiera", "sesion_x")

    assert result['success'] is False
    assert result['message'] == 'Credenciales inválidas'

    events = get_events(db_conn, usuario_id='DESCONOCIDO', tipo_accion='ACCESO_FALLIDO')
    assert len(events) == 1
    assert events[0]['sesion_id'] == 'sesion_x'
    assert events[0]['nivel_alerta'] == 'CRITICO'
