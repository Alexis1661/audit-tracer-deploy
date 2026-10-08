"""
tests/test_device_login.py
=============================
Pruebas unitarias e integración — HU-5.7: Autenticación de la librería
mediante token personal (login por código de dispositivo).

Cubre (DoD explícito):
  - Generación de código (CA1)
  - Confirmación (CA2)
  - Polling exitoso (CA3)
  - Timeout de confirmación (CA3)
  - Caché local y reutilización sin pedir login de nuevo (CA4)
  - Token cacheado expirado -> nuevo login automático (CA5)
"""

import json
import time
import uuid

import pytest
import requests

import app as app_module
from audit_tracer.db import get_connection, get_central_connection
from audit_tracer.models.usuarios import create_user
from audit_tracer.auth.device_codes import (
    iniciar_login_dispositivo,
    confirmar_codigo,
    consultar_estado,
    CODIGO_EXPIRACION_MINUTOS,
)
from audit_tracer.models.device_codes import get_by_codigo, get_by_device_code
import audit_tracer.device_login as device_login_module
from audit_tracer.device_login import device_login


# ──────────────────────────────────────────────────────────────
# FIXTURES
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def conn(tmp_path):
    """Conexión aislada — el modelo/lógica de negocio no distingue local de central."""
    c = get_connection(str(tmp_path / "device_codes_test.db"))
    yield c
    c.close()


@pytest.fixture
def usuario(conn):
    return create_user(conn, "colab_user@test.com", "Password123!", "CIENTIFICO_DATOS")


class FakeResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(f"HTTP {self.status_code}")

    def json(self):
        return self._json_data


# ──────────────────────────────────────────────────────────────
# CA1 — Generación de código
# ──────────────────────────────────────────────────────────────

class TestGeneracionCodigo:
    def test_iniciar_login_crea_codigo_pendiente(self, conn):
        datos = iniciar_login_dispositivo(conn)

        assert datos["codigo"]
        assert datos["device_code"]
        assert datos["codigo"] != datos["device_code"]  # nunca deben coincidir

        registro = get_by_codigo(conn, datos["codigo"])
        assert registro["estado"] == "PENDIENTE"
        assert registro["usuario_id"] is None
        assert registro["token"] is None

    def test_codigo_es_corto_y_legible(self, conn):
        datos = iniciar_login_dispositivo(conn)
        # 'XXXX-XXXX': 8 caracteres + 1 guión.
        assert len(datos["codigo"]) == 9
        assert datos["codigo"][4] == "-"

    def test_device_code_es_largo_y_no_adivinable_desde_el_codigo_corto(self, conn):
        """El código corto (lo que ve un humano) no debe alcanzar para hacer polling."""
        datos = iniciar_login_dispositivo(conn)
        assert len(datos["device_code"]) > 30
        assert get_by_device_code(conn, datos["codigo"]) is None  # el codigo corto NO es un device_code válido

    def test_cada_llamada_genera_un_codigo_distinto(self, conn):
        d1 = iniciar_login_dispositivo(conn)
        d2 = iniciar_login_dispositivo(conn)
        assert d1["codigo"] != d2["codigo"]
        assert d1["device_code"] != d2["device_code"]

    def test_fecha_expiracion_respeta_la_ventana_configurada(self, conn):
        from datetime import datetime
        datos = iniciar_login_dispositivo(conn)
        creacion = datetime.fromisoformat(datos["fecha_creacion"])
        expiracion = datetime.fromisoformat(datos["fecha_expiracion"])
        assert (expiracion - creacion).total_seconds() == pytest.approx(CODIGO_EXPIRACION_MINUTOS * 60, abs=1)


# ──────────────────────────────────────────────────────────────
# CA2 — Confirmación
# ──────────────────────────────────────────────────────────────

class TestConfirmacion:
    def test_confirmar_codigo_valido_genera_token_y_marca_confirmado(self, conn, usuario):
        datos = iniciar_login_dispositivo(conn)
        exito, mensaje = confirmar_codigo(conn, datos["codigo"], usuario, sesion_id="s-web")

        assert exito is True
        registro = get_by_codigo(conn, datos["codigo"])
        assert registro["estado"] == "CONFIRMADO"
        assert registro["usuario_id"] == usuario
        assert registro["token"]  # el token queda listo para que el polling lo recoja

    def test_confirmar_codigo_inexistente_falla(self, conn, usuario):
        exito, mensaje = confirmar_codigo(conn, "ZZZZ-9999", usuario)
        assert exito is False
        assert "inválido" in mensaje.lower()

    def test_confirmar_codigo_ya_confirmado_no_se_puede_reconfirmar(self, conn, usuario):
        datos = iniciar_login_dispositivo(conn)
        confirmar_codigo(conn, datos["codigo"], usuario)

        exito2, mensaje2 = confirmar_codigo(conn, datos["codigo"], usuario)
        assert exito2 is False
        assert "ya fue usado" in mensaje2.lower()

    def test_confirmar_codigo_expirado_falla_y_lo_marca_expirado(self, conn, usuario, monkeypatch):
        datos = iniciar_login_dispositivo(conn)
        # Forzar expiración retrocediendo la fecha_expiracion ya guardada.
        conn.execute(
            "UPDATE codigos_dispositivo SET fecha_expiracion = '2000-01-01T00:00:00' WHERE codigo = ?",
            (datos["codigo"],),
        )
        conn.commit()

        exito, mensaje = confirmar_codigo(conn, datos["codigo"], usuario)
        assert exito is False
        assert "expiró" in mensaje.lower()

        registro = get_by_device_code(conn, datos["device_code"])
        assert registro["estado"] == "EXPIRADO"

    def test_confirmar_registra_evento_de_auditoria(self, conn, usuario):
        from audit_tracer.models.audit_log import get_events
        datos = iniciar_login_dispositivo(conn)
        confirmar_codigo(conn, datos["codigo"], usuario, sesion_id="s-web")

        eventos = get_events(conn, usuario_id=usuario, tipo_accion="CONFIRMACION_LOGIN_DISPOSITIVO")
        assert len(eventos) == 1


# ──────────────────────────────────────────────────────────────
# CA3 — Consulta de estado (lado del polling)
# ──────────────────────────────────────────────────────────────

class TestConsultarEstado:
    def test_estado_pendiente_antes_de_confirmar(self, conn):
        datos = iniciar_login_dispositivo(conn)
        resultado = consultar_estado(conn, datos["device_code"])
        assert resultado["estado"] == "PENDIENTE"

    def test_estado_confirmado_entrega_el_token_una_sola_vez(self, conn, usuario):
        datos = iniciar_login_dispositivo(conn)
        confirmar_codigo(conn, datos["codigo"], usuario)

        primera = consultar_estado(conn, datos["device_code"])
        assert primera["estado"] == "CONFIRMADO"
        assert primera["token"]
        assert primera["usuario_id"] == usuario

        # Segunda consulta con el mismo device_code: el token ya se entregó.
        segunda = consultar_estado(conn, datos["device_code"])
        assert segunda["estado"] == "CONSUMIDO"
        assert "token" not in segunda

    def test_estado_de_device_code_inexistente(self, conn):
        resultado = consultar_estado(conn, "device-code-que-no-existe")
        assert resultado["estado"] == "INVALIDO"

    def test_estado_expirado_si_paso_la_ventana_sin_confirmar(self, conn):
        datos = iniciar_login_dispositivo(conn)
        conn.execute(
            "UPDATE codigos_dispositivo SET fecha_expiracion = '2000-01-01T00:00:00' WHERE codigo = ?",
            (datos["codigo"],),
        )
        conn.commit()

        resultado = consultar_estado(conn, datos["device_code"])
        assert resultado["estado"] == "EXPIRADO"


# ──────────────────────────────────────────────────────────────
# Endpoint HTTP: /api/auth/dispositivo/iniciar, /auth/dispositivo,
# /api/auth/dispositivo/estado (Flask test client, base central real)
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def api_client(monkeypatch, tmp_path):
    db_path = str(tmp_path / "central_device_test.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client, db_path


@pytest.fixture
def usuario_logueado(api_client):
    """Cliente Flask con una sesión de dashboard ya autenticada."""
    client, db_path = api_client
    conn = get_central_connection(db_path)
    user_id = create_user(conn, "analista@test.com", "Password123!", "ANALISTA")
    conn.close()

    with client.session_transaction() as sess:
        sess["usuario_id"] = user_id
        sess["rol"] = "ANALISTA"
        sess["nombre"] = "Analista Test"
        sess["sesion_id"] = "s_web_test"

    return client, db_path, user_id


class TestEndpointIniciar:
    def test_iniciar_devuelve_codigo_y_url_de_activacion(self, api_client):
        client, _ = api_client
        resp = client.post("/api/auth/dispositivo/iniciar")

        assert resp.status_code == 201
        body = resp.get_json()
        assert body["codigo"]
        assert body["device_code"]
        assert body["codigo"] in body["url_activacion"]
        assert body["expira_en_segundos"] > 0
        assert body["intervalo_polling"] > 0

    def test_no_requiere_autenticacion(self, api_client):
        """CA1: nadie tiene un token todavía en este paso."""
        client, _ = api_client
        resp = client.post("/api/auth/dispositivo/iniciar")
        assert resp.status_code == 201


class TestEndpointConfirmarDispositivo:
    def test_get_requiere_login(self, api_client):
        client, _ = api_client
        resp = client.get("/auth/dispositivo?codigo=ABCD-1234")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]
        assert "next=" in resp.headers["Location"]

    def test_get_precarga_el_codigo_de_la_query_string(self, usuario_logueado):
        client, _, _ = usuario_logueado
        resp = client.get("/auth/dispositivo?codigo=ABCD-1234")
        assert resp.status_code == 200
        assert b"ABCD-1234" in resp.data

    def test_post_confirma_codigo_valido(self, usuario_logueado):
        client, db_path, user_id = usuario_logueado
        conn = get_central_connection(db_path)
        datos = iniciar_login_dispositivo(conn)
        conn.close()

        resp = client.post("/auth/dispositivo", data={"codigo": datos["codigo"]})
        assert resp.status_code == 200
        assert "Confirmado".encode() in resp.data or b"notebook" in resp.data

        conn = get_central_connection(db_path)
        registro = get_by_codigo(conn, datos["codigo"])
        conn.close()
        assert registro["estado"] == "CONFIRMADO"
        assert registro["usuario_id"] == user_id

    def test_post_codigo_invalido_muestra_error(self, usuario_logueado):
        client, _, _ = usuario_logueado
        resp = client.post("/auth/dispositivo", data={"codigo": "ZZZZ-0000"})
        assert resp.status_code == 200
        assert b"lido" in resp.data  # "inválido" (evita depender del encoding exacto de la tilde)

    def test_post_requiere_login(self, api_client):
        client, _ = api_client
        resp = client.post("/auth/dispositivo", data={"codigo": "ABCD-1234"})
        assert resp.status_code == 302


class TestEndpointEstado:
    def test_estado_pendiente_por_http(self, api_client):
        client, db_path = api_client
        conn = get_central_connection(db_path)
        datos = iniciar_login_dispositivo(conn)
        conn.close()

        resp = client.get(f"/api/auth/dispositivo/estado?device_code={datos['device_code']}")
        assert resp.status_code == 200
        assert resp.get_json()["estado"] == "PENDIENTE"

    def test_estado_confirmado_por_http_entrega_token(self, usuario_logueado):
        client, db_path, user_id = usuario_logueado
        conn = get_central_connection(db_path)
        datos = iniciar_login_dispositivo(conn)
        confirmar_codigo(conn, datos["codigo"], user_id)
        conn.close()

        resp = client.get(f"/api/auth/dispositivo/estado?device_code={datos['device_code']}")
        assert resp.status_code == 200
        body = resp.get_json()
        assert body["estado"] == "CONFIRMADO"
        assert body["token"]
        assert body["usuario_id"] == user_id

        # Reintento con el mismo device_code: 410, sin token.
        resp2 = client.get(f"/api/auth/dispositivo/estado?device_code={datos['device_code']}")
        assert resp2.status_code == 410

    def test_estado_device_code_inexistente_responde_404(self, api_client):
        client, _ = api_client
        resp = client.get("/api/auth/dispositivo/estado?device_code=no-existe")
        assert resp.status_code == 404

    def test_estado_sin_device_code_responde_400(self, api_client):
        client, _ = api_client
        resp = client.get("/api/auth/dispositivo/estado")
        assert resp.status_code == 400


# ──────────────────────────────────────────────────────────────
# Cliente: device_login() (CA1, CA3, CA4, CA5) — requests mockeado
# ──────────────────────────────────────────────────────────────

class TestDeviceLoginCliente:
    def _mock_iniciar(self, monkeypatch, codigo="ABCD-1234", device_code="dc-secreto", intervalo=0.01):
        def _post(url, *a, **k):
            if url.endswith("/api/auth/dispositivo/iniciar"):
                return FakeResponse(201, {
                    "codigo": codigo, "device_code": device_code,
                    "url_activacion": f"https://central.example.org/auth/dispositivo?codigo={codigo}",
                    "expira_en_segundos": 600, "intervalo_polling": intervalo,
                })
            raise AssertionError(f"POST inesperado a {url}")
        monkeypatch.setattr(device_login_module.requests, "post", _post)

    # ── CA3: polling exitoso ──
    def test_polling_exitoso_cachea_el_token(self, monkeypatch, tmp_path):
        self._mock_iniciar(monkeypatch)
        respuestas = iter([
            {"estado": "PENDIENTE"},
            {"estado": "PENDIENTE"},
            {"estado": "CONFIRMADO", "token": "tk_recibido", "usuario_id": "u1"},
        ])
        monkeypatch.setattr(
            device_login_module.requests, "get",
            lambda *a, **k: FakeResponse(200, next(respuestas)),
        )

        cache_dir = str(tmp_path / "cache")
        resultado = device_login("https://central.example.org", cache_dir=cache_dir, poll_interval=0.01)

        assert resultado["success"] is True
        assert resultado["token"] == "tk_recibido"
        assert resultado["usuario_id"] == "u1"
        assert resultado["origen"] == "device_flow"

        with open(f"{cache_dir}/token_cache.json") as f:
            cacheado = json.load(f)
        assert cacheado["token"] == "tk_recibido"

    # ── CA3: timeout de confirmación ──
    def test_timeout_de_confirmacion(self, monkeypatch, tmp_path):
        self._mock_iniciar(monkeypatch, intervalo=0.01)
        monkeypatch.setattr(
            device_login_module.requests, "get",
            lambda *a, **k: FakeResponse(200, {"estado": "PENDIENTE"}),
        )

        resultado = device_login(
            "https://central.example.org",
            cache_dir=str(tmp_path / "cache"),
            poll_interval=0.01,
            timeout_seconds=0.05,
        )

        assert resultado["success"] is False
        assert resultado["motivo"] == "TIMEOUT"

    def test_codigo_expirado_durante_el_polling_detiene_de_inmediato(self, monkeypatch, tmp_path):
        self._mock_iniciar(monkeypatch, intervalo=0.01)
        monkeypatch.setattr(
            device_login_module.requests, "get",
            lambda *a, **k: FakeResponse(200, {"estado": "EXPIRADO"}),
        )

        resultado = device_login(
            "https://central.example.org",
            cache_dir=str(tmp_path / "cache"),
            poll_interval=0.01,
            timeout_seconds=600,  # no debería llegar a agotarse: EXPIRADO corta antes
        )

        assert resultado["success"] is False
        assert resultado["motivo"] == "EXPIRADO"

    # ── CA4: caché local y reutilización ──
    def test_token_cacheado_valido_evita_repetir_el_flujo(self, monkeypatch, tmp_path):
        cache_dir = str(tmp_path / "cache")
        import os
        os.makedirs(cache_dir, exist_ok=True)
        with open(f"{cache_dir}/token_cache.json", "w") as f:
            json.dump({"token": "tk_cacheado", "usuario_id": "u1"}, f)

        llamadas_iniciar = []
        monkeypatch.setattr(
            device_login_module.requests, "post",
            lambda url, *a, **k: (
                llamadas_iniciar.append(url) if url.endswith("/iniciar") else None,
                FakeResponse(200, {"valido": True, "usuario_id": "u1"}),
            )[1],
        )

        resultado = device_login("https://central.example.org", cache_dir=cache_dir)

        assert resultado["success"] is True
        assert resultado["origen"] == "cache"
        assert resultado["token"] == "tk_cacheado"
        assert llamadas_iniciar == []  # nunca debió iniciar un código nuevo

    # ── CA5: token cacheado inválido/expirado -> nuevo login automático ──
    def test_token_cacheado_invalido_dispara_nuevo_flujo(self, monkeypatch, tmp_path):
        cache_dir = str(tmp_path / "cache")
        import os
        os.makedirs(cache_dir, exist_ok=True)
        with open(f"{cache_dir}/token_cache.json", "w") as f:
            json.dump({"token": "tk_expirado", "usuario_id": "u1"}, f)

        def _post(url, *a, **k):
            if url.endswith("/api/tokens/validar"):
                return FakeResponse(200, {"valido": False, "mensaje": "Token expirado"})
            if url.endswith("/api/auth/dispositivo/iniciar"):
                return FakeResponse(201, {
                    "codigo": "NEWC-0DE1", "device_code": "dc-nuevo",
                    "url_activacion": "https://central.example.org/auth/dispositivo?codigo=NEWC-0DE1",
                    "expira_en_segundos": 600, "intervalo_polling": 0.01,
                })
            raise AssertionError(f"POST inesperado a {url}")

        monkeypatch.setattr(device_login_module.requests, "post", _post)
        monkeypatch.setattr(
            device_login_module.requests, "get",
            lambda *a, **k: FakeResponse(200, {"estado": "CONFIRMADO", "token": "tk_nuevo", "usuario_id": "u2"}),
        )

        resultado = device_login("https://central.example.org", cache_dir=cache_dir, poll_interval=0.01)

        assert resultado["success"] is True
        assert resultado["origen"] == "device_flow"
        assert resultado["token"] == "tk_nuevo"

        with open(f"{cache_dir}/token_cache.json") as f:
            cacheado = json.load(f)
        assert cacheado["token"] == "tk_nuevo"  # el viejo quedó reemplazado, no solo descartado

    def test_force_ignora_el_cache_aunque_sea_valido(self, monkeypatch, tmp_path):
        cache_dir = str(tmp_path / "cache")
        import os
        os.makedirs(cache_dir, exist_ok=True)
        with open(f"{cache_dir}/token_cache.json", "w") as f:
            json.dump({"token": "tk_viejo", "usuario_id": "u1"}, f)

        self._mock_iniciar(monkeypatch, codigo="FORC-E123", device_code="dc-forzado")
        monkeypatch.setattr(
            device_login_module.requests, "get",
            lambda *a, **k: FakeResponse(200, {"estado": "CONFIRMADO", "token": "tk_forzado", "usuario_id": "u1"}),
        )

        resultado = device_login("https://central.example.org", cache_dir=cache_dir, poll_interval=0.01, force=True)
        assert resultado["token"] == "tk_forzado"

    def test_sin_conexion_al_iniciar_no_lanza(self, monkeypatch, tmp_path):
        def _post(*a, **k):
            raise requests.exceptions.ConnectionError("sin red")
        monkeypatch.setattr(device_login_module.requests, "post", _post)

        resultado = device_login("https://central.example.org", cache_dir=str(tmp_path / "cache"))
        assert resultado["success"] is False
        assert resultado["motivo"] == "SIN_CONEXION"


# ──────────────────────────────────────────────────────────────
# Integración extremo a extremo — servidor Flask real, sin mocks
# ──────────────────────────────────────────────────────────────

class TestIntegracionExtremoAExtremo:
    """
    DoD — "El flujo completo de login por código funciona de principio a
    fin en un entorno de prueba tipo Colab": servidor HTTP real (no
    mockeado), device_login() real haciendo polling real por la red.
    """

    def test_flujo_completo_codigo_a_token_cacheado(self, monkeypatch, tmp_path):
        from werkzeug.serving import make_server
        import threading

        central_path = str(tmp_path / "central_e2e.db")
        monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(central_path))

        server = make_server("127.0.0.1", 0, app_module.app)
        port = server.server_port
        hilo = threading.Thread(target=server.serve_forever, daemon=True)
        hilo.start()
        time.sleep(0.2)

        try:
            conn = get_central_connection(central_path)
            user_id = create_user(conn, "colab_e2e@test.com", "Password123!", "CIENTIFICO_DATOS")
            conn.close()

            api_url = f"http://127.0.0.1:{port}"
            resultado_contenedor = {}

            def _confirmar_en_paralelo():
                # Simula al usuario confirmando en el dashboard mientras
                # device_login() sigue haciendo polling en el hilo principal.
                time.sleep(0.3)
                conn2 = get_central_connection(central_path)
                registros = conn2.execute("SELECT codigo FROM codigos_dispositivo WHERE estado = 'PENDIENTE'").fetchall()
                assert len(registros) == 1
                codigo = registros[0][0]
                confirmar_codigo(conn2, codigo, user_id, sesion_id="s-web-e2e")
                conn2.close()

            hilo_confirmacion = threading.Thread(target=_confirmar_en_paralelo, daemon=True)
            hilo_confirmacion.start()

            resultado = device_login(api_url, cache_dir=str(tmp_path / "cache"), poll_interval=0.1, timeout_seconds=10)
            hilo_confirmacion.join(timeout=5)

            assert resultado["success"] is True
            assert resultado["usuario_id"] == user_id
            assert resultado["origen"] == "device_flow"

            # El token quedó cacheado y una segunda llamada lo reutiliza sin volver a pedir código.
            segunda = device_login(api_url, cache_dir=str(tmp_path / "cache"), poll_interval=0.1)
            assert segunda["origen"] == "cache"
            assert segunda["token"] == resultado["token"]
        finally:
            server.shutdown()
            hilo.join(timeout=5)
