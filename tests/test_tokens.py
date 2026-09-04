"""
test_tokens.py — Suite de pruebas unitarias y de integración para HU-5.5.
Generación, validación, expiración y revocación de tokens personales de acceso.
(PDGTRAZDSA-127, PDGTRAZDSA-128, PDGTRAZDSA-129, PDGTRAZDSA-130, PDGTRAZDSA-131).
"""

import json
import os
import sqlite3
import pytest
from datetime import datetime, timedelta

from audit_tracer.db import get_connection
from audit_tracer.models.usuarios import create_user, block_user
from audit_tracer.models.tokens import (
    insert_token,
    get_token_by_value,
    get_token_by_id,
    get_tokens_by_user,
    get_all_tokens_with_user_info,
    update_token_status,
    revoke_token_by_id,
    revoke_token_by_value,
)
from audit_tracer.auth.tokens import (
    generar_token,
    validar_token,
    revocar_token,
    listar_tokens,
    generar_token_seguro,
    DEFAULT_TOKEN_EXPIRATION_DAYS,
)
from audit_tracer.auth.autenticacion import login
from audit_tracer.models.audit_log import get_events
from app import app


@pytest.fixture
def db_conn():
    """Crea una base de datos SQLite temporal en memoria / archivo temporal para cada test."""
    test_db = "test_tokens.db"
    if os.path.exists(test_db):
        os.remove(test_db)

    conn = get_connection(test_db)
    yield conn

    conn.close()
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except PermissionError:
            pass


@pytest.fixture
def sample_user(db_conn):
    """Crea un usuario de prueba en la BD."""
    user_id = create_user(db_conn, "analista_test@hospital.com", "Password123!", "ANALISTA")
    return user_id, "analista_test@hospital.com"


@pytest.fixture
def sample_admin(db_conn):
    """Crea un administrador de prueba en la BD."""
    admin_id = create_user(db_conn, "admin_test@hospital.com", "AdminPass123!", "ADMIN")
    return admin_id, "admin_test@hospital.com"


# ═══════════════════════════════════════════════════════════════════════════════
# 1. ESQUEMA Y MODELO DE DATOS (PDGTRAZDSA-127)
# ═══════════════════════════════════════════════════════════════════════════════

def test_esquema_tokens_tabla_creada(db_conn):
    """Verifica que la tabla tokens_acceso existe con las columnas requeridas."""
    cursor = db_conn.cursor()
    cursor.execute("PRAGMA table_info(tokens_acceso)")
    columns = {row[1] for row in cursor.fetchall()}
    
    assert "token_id" in columns
    assert "usuario_id" in columns
    assert "token" in columns
    assert "fecha_creacion" in columns
    assert "fecha_expiracion" in columns
    assert "estado" in columns
    assert "creado_por" in columns


def test_model_insert_and_get_token(db_conn, sample_user):
    """Prueba inserción y obtención básica mediante el modelo."""
    user_id, _ = sample_user
    token_str = "tk_test_model_123456789"
    ahora = datetime.utcnow().isoformat()
    exp = (datetime.utcnow() + timedelta(days=30)).isoformat()

    token_id = insert_token(db_conn, {
        "usuario_id": user_id,
        "token": token_str,
        "fecha_creacion": ahora,
        "fecha_expiracion": exp,
        "estado": "ACTIVO",
        "creado_por": "LOGIN"
    })

    assert token_id is not None
    
    by_val = get_token_by_value(db_conn, token_str)
    assert by_val is not None
    assert by_val["token_id"] == token_id
    assert by_val["usuario_id"] == user_id
    assert by_val["estado"] == "ACTIVO"

    by_id = get_token_by_id(db_conn, token_id)
    assert by_id is not None
    assert by_id["token"] == token_str


# ═══════════════════════════════════════════════════════════════════════════════
# 2. GENERACIÓN SEGURA DE TOKENS (PDGTRAZDSA-128 / CA1 & CA2)
# ═══════════════════════════════════════════════════════════════════════════════

def test_generar_token_seguro_formato():
    """Valida formato y aleatoriedad del token seguro."""
    token1 = generar_token_seguro()
    token2 = generar_token_seguro()

    assert token1.startswith("tk_")
    assert token2.startswith("tk_")
    assert token1 != token2
    assert len(token1) > 20


def test_generar_token_exitoso_expiracion_default_30_dias(db_conn, sample_user):
    """CA2: Verifica generación con expiración por defecto de 30 días."""
    user_id, _ = sample_user
    antes = datetime.utcnow()

    token_info = generar_token(db_conn, user_id)
    despues = datetime.utcnow()

    assert token_info["token_id"] is not None
    assert token_info["token"].startswith("tk_")
    assert token_info["estado"] == "ACTIVO"
    assert token_info["usuario_id"] == user_id

    # Comprobar que la expiración es aproximadamente +30 días
    exp_dt = datetime.fromisoformat(token_info["fecha_expiracion"])
    diferencia_dias = (exp_dt - antes).total_seconds() / (24 * 3600)
    assert 29.9 <= diferencia_dias <= 30.1


def test_generar_token_expiracion_configurable(db_conn, sample_user):
    """CA2: Verifica generación con días de expiración configurables."""
    user_id, _ = sample_user
    antes = datetime.utcnow()

    token_info = generar_token(db_conn, user_id, dias_expiracion=15)
    exp_dt = datetime.fromisoformat(token_info["fecha_expiracion"])
    diferencia_dias = (exp_dt - antes).total_seconds() / (24 * 3600)

    assert 14.9 <= diferencia_dias <= 15.1


def test_generar_token_usuario_inexistente_falla(db_conn):
    """Verifica que generar token para un usuario inválido lanza ValueError."""
    with pytest.raises(ValueError, match="Usuario con ID .* no encontrado"):
        generar_token(db_conn, "usuario_fantasma_uuid")


def test_generacion_token_registra_evento_en_audit_log(db_conn, sample_user):
    """Verifica que la generación de token queda auditada."""
    user_id, email = sample_user
    token_info = generar_token(db_conn, user_id, creado_por="ADMIN", sesion_id="SES-GEN-01")

    events = get_events(db_conn, tipo_accion="GENERACION_TOKEN")
    assert len(events) >= 1
    assert any("GENERACION_TOKEN" == e["tipo_accion"] and email in e.get("contexto_ejecucion", "") for e in events)


# ═══════════════════════════════════════════════════════════════════════════════
# 3. VALIDACIÓN DE TOKENS (PDGTRAZDSA-129 / CA5)
# ═══════════════════════════════════════════════════════════════════════════════

def test_validar_token_activo_y_vigente(db_conn, sample_user):
    """Valida un token activo y dentro de su ventana de vigencia."""
    user_id, _ = sample_user
    token_info = generar_token(db_conn, user_id, dias_expiracion=10)

    valido, mensaje, data = validar_token(db_conn, token_info["token"])
    assert valido is True
    assert "activo y vigente" in mensaje.lower()
    assert data["token_id"] == token_info["token_id"]
    assert data["estado"] == "ACTIVO"


def test_validar_token_inexistente_o_invalido(db_conn):
    """Verifica rechazo de token inexistente o vacío."""
    valido, mensaje, data = validar_token(db_conn, "tk_no_existe_123456")
    assert valido is False
    assert "inexistente" in mensaje.lower()
    assert data is None

    valido_empty, _, _ = validar_token(db_conn, "")
    assert valido_empty is False

    valido_none, _, _ = validar_token(db_conn, None)
    assert valido_none is False


def test_validar_token_expirado_se_rechaza_y_actualiza_estado(db_conn, sample_user):
    """CA5: Un token cuya fecha de expiración pasó es rechazado y marcado como EXPIRADO."""
    user_id, _ = sample_user
    fecha_pasada = (datetime.utcnow() - timedelta(days=2)).isoformat()
    fecha_creacion = (datetime.utcnow() - timedelta(days=32)).isoformat()

    token_str = "tk_expirado_mock_123"
    token_id = insert_token(db_conn, {
        "usuario_id": user_id,
        "token": token_str,
        "fecha_creacion": fecha_creacion,
        "fecha_expiracion": fecha_pasada,
        "estado": "ACTIVO",
        "creado_por": "LOGIN"
    })

    valido, mensaje, data = validar_token(db_conn, token_str)
    assert valido is False
    assert "expirado" in mensaje.lower()

    # Comprobar que en base de datos quedó actualizado a 'EXPIRADO'
    stored = get_token_by_id(db_conn, token_id)
    assert stored["estado"] == "EXPIRADO"


def test_validar_token_usuario_bloqueado_es_rechazado(db_conn, sample_user):
    """Si el usuario está bloqueado/inactivo, el token es rechazado."""
    user_id, _ = sample_user
    token_info = generar_token(db_conn, user_id)

    block_user(db_conn, user_id)

    valido, mensaje, _ = validar_token(db_conn, token_info["token"])
    assert valido is False
    assert "bloqueado" in mensaje.lower() or "inactivo" in mensaje.lower()


# ═══════════════════════════════════════════════════════════════════════════════
# 4. REVOCACIÓN DE TOKENS (PDGTRAZDSA-130 / CA4 & CA5)
# ═══════════════════════════════════════════════════════════════════════════════

def test_revocar_token_por_id_inmediato(db_conn, sample_user, sample_admin):
    """CA4: Revocación manual inmediata por token_id."""
    user_id, _ = sample_user
    admin_id, _ = sample_admin
    token_info = generar_token(db_conn, user_id)
    token_id = token_info["token_id"]

    exito, msg = revocar_token(db_conn, token_id, admin_id=admin_id, sesion_id="SES-REV-01")
    assert exito is True
    assert "revocado exitosamente" in msg

    # Verificar que el estado en BD cambió
    record = get_token_by_id(db_conn, token_id)
    assert record["estado"] == "REVOCADO"

    # CA5: Un token revocado se rechaza de inmediato
    valido, motivo, _ = validar_token(db_conn, token_info["token"])
    assert valido is False
    assert "revocado" in motivo.lower()


def test_revocar_token_por_valor_inmediato(db_conn, sample_user):
    """CA4: Revocación manual por valor literal de token."""
    user_id, _ = sample_user
    token_info = generar_token(db_conn, user_id)
    token_str = token_info["token"]

    exito, _ = revocar_token(db_conn, token_str)
    assert exito is True

    valido, motivo, _ = validar_token(db_conn, token_str)
    assert valido is False
    assert "revocado" in motivo.lower()


def test_revocar_token_registra_evento_en_audit_log(db_conn, sample_user, sample_admin):
    """Verifica que la revocación se registra en audit_log."""
    user_id, _ = sample_user
    admin_id, _ = sample_admin
    token_info = generar_token(db_conn, user_id)

    revocar_token(db_conn, token_info["token_id"], admin_id=admin_id, sesion_id="SES-REV-02")

    events = get_events(db_conn, tipo_accion="REVOCACION_TOKEN")
    assert len(events) >= 1
    assert any(token_info["token_id"] in e.get("contexto_ejecucion", "") for e in events)


# ═══════════════════════════════════════════════════════════════════════════════
# 5. INTEGRACIÓN CON FLUJO DE LOGIN (CA1) Y LISTADO (CA3)
# ═══════════════════════════════════════════════════════════════════════════════

def test_login_genera_token_personal_unico(db_conn):
    """CA1: Al completar exitosamente login, se genera un token único por usuario."""
    user_id = create_user(db_conn, "medico1@hospital.com", "ClaveSegura123!", "ANALISTA")

    res = login(db_conn, "medico1@hospital.com", "ClaveSegura123!", "SES-LOGIN-01")
    assert res["success"] is True
    assert "token" in res
    assert res["token"].startswith("tk_")
    assert "token_expiracion" in res

    # Validar que el token generado funciona inmediatamente
    valido, _, _ = validar_token(db_conn, res["token"])
    assert valido is True


def test_listar_tokens_con_filtros(db_conn):
    """CA3 [PDGTRAZDSA-131]: Lista tokens con filtros de usuario y estado."""
    u1 = create_user(db_conn, "u1@hosp.com", "Pass123456!", "ANALISTA")
    u2 = create_user(db_conn, "u2@hosp.com", "Pass123456!", "AUDITOR")

    t1 = generar_token(db_conn, u1)
    t2 = generar_token(db_conn, u2)
    t3 = generar_token(db_conn, u1)

    revocar_token(db_conn, t3["token_id"])

    # Listar todos
    todos = listar_tokens(db_conn)
    assert len(todos) >= 3

    # Filtrar por usuario u1
    tokens_u1 = listar_tokens(db_conn, usuario_id=u1)
    assert len(tokens_u1) == 2
    assert all(t["usuario_id"] == u1 for t in tokens_u1)

    # Filtrar por estado ACTIVO
    activos = listar_tokens(db_conn, estado="ACTIVO")
    assert all(t["estado"] == "ACTIVO" for t in activos)

    # Filtrar por estado REVOCADO
    revocados = listar_tokens(db_conn, estado="REVOCADO")
    assert any(t["token_id"] == t3["token_id"] for t in revocados)


# ═══════════════════════════════════════════════════════════════════════════════
# 6. ENDPOINTS FLASK Y ACCIONES DEL DASHBOARD (PDGTRAZDSA-130 & 131)
# ═══════════════════════════════════════════════════════════════════════════════

@pytest.fixture
def client():
    """Cliente de pruebas de Flask configurado con una BD de prueba dedicada."""
    test_db = "test_tokens_flask.db"
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except PermissionError:
            pass

    # Inicializar BD
    conn = get_connection(test_db)
    conn.close()

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    import app as app_module
    original_get_db = app_module.get_db
    app_module.get_db = lambda: get_connection(test_db)

    with app.test_client() as test_client:
        test_client.test_db_path = test_db
        yield test_client

    app_module.get_db = original_get_db
    if os.path.exists(test_db):
        try:
            os.remove(test_db)
        except PermissionError:
            pass


def test_endpoint_admin_tokens_requiere_login(client):
    """Ruta /admin/tokens redirige si no hay sesión."""
    resp = client.get("/admin/tokens")
    assert resp.status_code == 302
    assert "/login" in resp.headers["Location"]


def test_endpoint_admin_tokens_requiere_rol_admin(client):
    """Ruta /admin/tokens redirige a dashboard si el rol no es ADMIN."""
    conn = get_connection(client.test_db_path)
    user_id = create_user(conn, "analista_route@hosp.com", "Password123!", "ANALISTA")
    conn.close()

    with client.session_transaction() as sess:
        sess["usuario_id"] = user_id
        sess["rol"] = "ANALISTA"
        sess["nombre"] = "analista_route@hosp.com"

    resp = client.get("/admin/tokens")
    assert resp.status_code == 302
    assert "/dashboard" in resp.headers["Location"]


def test_endpoint_admin_tokens_acceso_permitido_admin(client):
    """Ruta /admin/tokens muestra el listado y métricas para ADMIN."""
    conn = get_connection(client.test_db_path)
    admin_id = create_user(conn, "admin_route@hosp.com", "AdminPass123!", "ADMIN")
    generar_token(conn, admin_id)
    conn.close()

    with client.session_transaction() as sess:
        sess["usuario_id"] = admin_id
        sess["rol"] = "ADMIN"
        sess["nombre"] = "admin_route@hosp.com"

    resp = client.get("/admin/tokens")
    assert resp.status_code == 200
    assert b"Tokens Personales de Acceso" in resp.data
    assert b"Tokens Activos y Vigentes" in resp.data


def test_endpoint_admin_nuevo_token_post(client):
    """Generación manual de token desde el formulario de administración."""
    conn = get_connection(client.test_db_path)
    admin_id = create_user(conn, "admin_new_tk@hosp.com", "AdminPass123!", "ADMIN")
    user_id = create_user(conn, "user_new_tk@hosp.com", "UserPass123!", "ANALISTA")
    conn.close()

    with client.session_transaction() as sess:
        sess["usuario_id"] = admin_id
        sess["rol"] = "ADMIN"
        sess["nombre"] = "admin_new_tk@hosp.com"
        sess["sesion_id"] = "SES-ADM-01"

    resp = client.post("/admin/tokens/nuevo", data={
        "usuario_id": user_id,
        "dias_expiracion": "60"
    }, follow_redirects=True)

    assert resp.status_code == 200
    conn = get_connection(client.test_db_path)
    tokens = get_tokens_by_user(conn, user_id)
    conn.close()
    assert len(tokens) >= 1
    assert tokens[0]["creado_por"] == "ADMIN"


def test_endpoint_admin_revocar_token_post(client):
    """CA4: Revocación manual de un token mediante POST desde el dashboard."""
    conn = get_connection(client.test_db_path)
    admin_id = create_user(conn, "admin_rev_tk@hosp.com", "AdminPass123!", "ADMIN")
    user_id = create_user(conn, "user_rev_tk@hosp.com", "UserPass123!", "ANALISTA")
    token_info = generar_token(conn, user_id)
    conn.close()

    with client.session_transaction() as sess:
        sess["usuario_id"] = admin_id
        sess["rol"] = "ADMIN"
        sess["nombre"] = "admin_rev_tk@hosp.com"
        sess["sesion_id"] = "SES-ADM-02"

    resp = client.post(f"/admin/tokens/revocar/{token_info['token_id']}", follow_redirects=True)
    assert resp.status_code == 200

    conn = get_connection(client.test_db_path)
    record = get_token_by_id(conn, token_info["token_id"])
    conn.close()
    assert record["estado"] == "REVOCADO"


def test_api_validar_token_endpoint(client):
    """CA5: Endpoint API /api/tokens/validar responde con JSON correcto."""
    conn = get_connection(client.test_db_path)
    user_id = create_user(conn, "api_user@hosp.com", "ApiPass123!", "ANALISTA")
    token_info = generar_token(conn, user_id)
    conn.close()

    # 1. Token válido vía body JSON
    resp = client.post("/api/tokens/validar", json={"token": token_info["token"]})
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["valido"] is True
    assert data["estado"] == "ACTIVO"
    assert data["usuario_id"] == user_id

    # 2. Token válido vía Header Bearer
    resp_bearer = client.post(
        "/api/tokens/validar",
        headers={"Authorization": f"Bearer {token_info['token']}"}
    )
    assert resp_bearer.status_code == 200
    assert resp_bearer.get_json()["valido"] is True

    # 3. Revocar token y comprobar rechazo en API
    conn = get_connection(client.test_db_path)
    revocar_token(conn, token_info["token_id"])
    conn.close()

    resp_rev = client.post("/api/tokens/validar", json={"token": token_info["token"]})
    assert resp_rev.status_code == 401
    data_rev = resp_rev.get_json()
    assert data_rev["valido"] is False
    assert data_rev["estado"] == "REVOCADO"


def test_api_revocar_token_endpoint(client):
    """Endpoint API /api/tokens/revocar permite revocar token vía JSON."""
    conn = get_connection(client.test_db_path)
    admin_id = create_user(conn, "api_admin@hosp.com", "AdminPass123!", "ADMIN")
    user_id = create_user(conn, "api_user2@hosp.com", "UserPass123!", "ANALISTA")
    token_info = generar_token(conn, user_id)
    conn.close()

    with client.session_transaction() as sess:
        sess["usuario_id"] = admin_id
        sess["rol"] = "ADMIN"
        sess["nombre"] = "api_admin@hosp.com"

    resp = client.post("/api/tokens/revocar", json={"token_id": token_info["token_id"]})
    assert resp.status_code == 200
    assert resp.get_json()["success"] is True

    # Verificar que quedó revocado
    conn = get_connection(client.test_db_path)
    valido, _, _ = validar_token(conn, token_info["token"])
    conn.close()
    assert valido is False

