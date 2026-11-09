import pytest
import os
import sqlite3

import app as app_module
from conftest import crear_sesion_web
from audit_tracer.db import get_central_connection, get_connection
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

def test_email_duplicado_no_deja_transaccion_abierta(db_conn):
    """Un correo repetido no debe retener el bloqueo de escritura de la base."""
    register_user(db_conn, "test@example.com", "pwd", "ANALISTA", "admin")
    with pytest.raises(ValueError):
        register_user(db_conn, "test@example.com", "pwd2", "AUDITOR", "admin")
    assert not db_conn.in_transaction


@pytest.fixture
def cliente_admin(monkeypatch, tmp_path):
    """Dashboard real con una sesión ADMIN sobre una base central temporal."""
    ruta = str(tmp_path / "central.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(ruta))
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        crear_sesion_web(client, "admin-1", "ADMIN", "admin@example.test")
        yield client, ruta


def _crear_por_formulario(client, email):
    return client.post("/admin/usuarios/nuevo", data={
        "email": email, "password": "Password123!", "confirmar_password": "Password123!", "rol": "ANALISTA",
    })


def test_crear_usuario_redirige_al_listado(cliente_admin):
    client, ruta = cliente_admin
    respuesta = _crear_por_formulario(client, "nuevo@example.test")
    assert respuesta.status_code == 302
    assert respuesta.headers["Location"].endswith("/admin/usuarios")
    conn = get_central_connection(ruta)
    try:
        assert get_user_by_email(conn, "nuevo@example.test") is not None
    finally:
        conn.close()


def test_correo_repetido_no_bloquea_la_base_central(cliente_admin):
    client, ruta = cliente_admin
    _crear_por_formulario(client, "repetido@example.test")
    respuesta = _crear_por_formulario(client, "repetido@example.test")
    assert respuesta.status_code == 200
    assert "ya se encuentra registrado" in respuesta.get_data(as_text=True)

    otra = sqlite3.connect(ruta, timeout=0.2)
    try:
        otra.execute("BEGIN IMMEDIATE")  # lanza "database is locked" si quedó una escritura abierta
        otra.rollback()
    finally:
        otra.close()


def test_register_invalid_rol(db_conn):
    """ValueError si rol inválido."""
    with pytest.raises(ValueError, match="Rol inválido"):
        register_user(db_conn, "test@example.com", "pwd", "HACKER", "admin")
