"""
tests/test_sync_events.py
===========================
Pruebas unitarias e integración — HU-5.8: Sincronización de eventos hacia
el servidor central.

Cubre:
  CA1: la persistencia local siempre ocurre antes de cualquier intento de
       envío HTTP (insert_event_and_enqueue_sync + try_sync_event).
  CA2: reintentos acotados con backoff ante fallos transitorios; el
       evento queda marcado y disponible para reintento posterior.
  CA3: un evento nunca se pierde mientras no haya confirmación positiva
       del servidor central — permanece en audit_sync_queue.
  CA4: el servidor valida el token del emisor; un rechazo no se reintenta
       en bucle y nunca se expone el valor del token.
  CA5: idempotencia — reintentar el envío de un evento no lo duplica en
       la base central (restricción UNIQUE sobre evento_uuid).
"""

import threading
import time
import uuid

import pytest
import requests
from werkzeug.serving import make_server

import app as app_module
from audit_tracer import sync_client
from audit_tracer.db import get_connection, get_central_connection
from audit_tracer.models.usuarios import create_user
from audit_tracer.auth.tokens import generar_token
from audit_tracer.models.audit_log import (
    insert_event_and_enqueue_sync,
    insert_event_if_new,
    get_event_by_uuid,
    get_pending_sync_events,
    get_sync_queue_summary,
    mark_event_synced,
    mark_event_sync_failed,
)


# ──────────────────────────────────────────────────────────────
# FIXTURES
# ──────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def _reset_sync_client():
    """Aísla el estado global de sync_client entre tests (config + hilo de fondo)."""
    sync_client.stop_background_sync()
    sync_client._config["api_url"] = None
    sync_client._config["token"] = None
    yield
    sync_client.stop_background_sync()
    sync_client._config["api_url"] = None
    sync_client._config["token"] = None


@pytest.fixture(autouse=True)
def _backoff_rapido(monkeypatch):
    """Backoff mínimo para que los tests de reintento no sean lentos."""
    monkeypatch.setattr(sync_client, "BACKOFF_BASE_SEGUNDOS", 0.01)


@pytest.fixture
def local_conn(tmp_path):
    conn = get_connection(str(tmp_path / "local.db"))
    yield conn
    conn.close()


@pytest.fixture
def central_conn(tmp_path):
    conn = get_central_connection(str(tmp_path / "central.db"))
    yield conn
    conn.close()


class FakeResponse:
    def __init__(self, status_code, json_data=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.content = b"1"

    def json(self):
        return self._json_data


def _evento_base(usuario_id="u1", tipo_accion="CARGA"):
    return {
        "evento_uuid": str(uuid.uuid4()),
        "usuario_id": usuario_id,
        "sesion_id": "s1",
        "tipo_accion": tipo_accion,
        "dataset_nombre": "PATIENTS.csv",
    }


# ──────────────────────────────────────────────────────────────
# CA1 / Sub-tarea 2 y 3 — Cola local + evento_uuid
# ──────────────────────────────────────────────────────────────

class TestColaLocal:
    def test_tabla_audit_sync_queue_existe_con_columnas_esperadas(self, local_conn):
        columnas = {row[1] for row in local_conn.execute("PRAGMA table_info(audit_sync_queue)")}
        assert {"event_id", "evento_uuid", "estado", "intentos", "ultimo_intento", "ultimo_error", "sincronizado_en"} <= columnas

    def test_insert_event_and_enqueue_sync_encola_en_pendiente(self, local_conn):
        resultado = insert_event_and_enqueue_sync(local_conn, _evento_base())
        fila = local_conn.execute(
            "SELECT estado, intentos, evento_uuid FROM audit_sync_queue WHERE event_id = ?",
            (resultado["event_id"],),
        ).fetchone()
        assert fila == ("PENDIENTE", 0, resultado["evento_uuid"])

    def test_evento_uuid_no_se_regenera_entre_reintentos(self, local_conn):
        """CA2 — Sub-tarea 3: el mismo evento_uuid se reutiliza en cada reintento, nunca se regenera."""
        resultado = insert_event_and_enqueue_sync(local_conn, _evento_base())
        uuid_original = resultado["evento_uuid"]

        mark_event_sync_failed(local_conn, resultado["event_id"], "fallo simulado", "2026-01-01T00:00:00")
        pendientes = get_pending_sync_events(local_conn)

        assert len(pendientes) == 1
        assert pendientes[0]["evento_uuid"] == uuid_original
        assert pendientes[0]["intentos"] == 1

    def test_get_pending_sync_events_no_incluye_sincronizados(self, local_conn):
        r1 = insert_event_and_enqueue_sync(local_conn, _evento_base("u1"))
        insert_event_and_enqueue_sync(local_conn, _evento_base("u2"))
        mark_event_synced(local_conn, r1["event_id"], "2026-01-01T00:00:00")

        pendientes = get_pending_sync_events(local_conn)
        assert len(pendientes) == 1
        assert pendientes[0]["usuario_id"] == "u2"

    def test_get_sync_queue_summary_cuenta_por_estado(self, local_conn):
        r1 = insert_event_and_enqueue_sync(local_conn, _evento_base("u1"))
        r2 = insert_event_and_enqueue_sync(local_conn, _evento_base("u2"))
        insert_event_and_enqueue_sync(local_conn, _evento_base("u3"))

        mark_event_synced(local_conn, r1["event_id"], "2026-01-01T00:00:00")
        mark_event_sync_failed(local_conn, r2["event_id"], "sin conexión", "2026-01-02T00:00:00")

        resumen = get_sync_queue_summary(local_conn)
        assert resumen["sincronizados"] == 1
        assert resumen["fallidos"] == 1
        assert resumen["pendientes"] == 1
        assert resumen["ultimo_intento"] == "2026-01-02T00:00:00"
        assert resumen["ultimo_error"] == "sin conexión"


# ──────────────────────────────────────────────────────────────
# CA1 — Test 7: SQLite primero, nunca se envía sin persistir antes
# ──────────────────────────────────────────────────────────────

class TestPersistenciaAntesDeRed:
    def test_no_se_llama_http_si_falla_la_persistencia_local(self, local_conn, monkeypatch):
        llamadas_post = []
        monkeypatch.setattr(sync_client.requests, "post", lambda *a, **k: llamadas_post.append(1))

        # Rompe la tabla local para forzar el fallo de insert_event().
        local_conn.execute("DROP TABLE audit_log")

        with pytest.raises(Exception):
            insert_event_and_enqueue_sync(local_conn, _evento_base())

        assert llamadas_post == [], "No debe intentarse ningún envío HTTP si la persistencia local falló"
        # Tampoco debe haber quedado una fila huérfana en la cola.
        total_cola = local_conn.execute("SELECT COUNT(*) FROM audit_sync_queue").fetchone()[0]
        assert total_cola == 0


# ──────────────────────────────────────────────────────────────
# CA2 / CA3 / CA4 / CA5 — Cliente HTTP (requests.post mockeado, sin red real)
# ──────────────────────────────────────────────────────────────

class TestClienteSincronizacion:
    def _configurar(self):
        sync_client.configure_sync("https://central.example.org", "tk_test_123", auto=False)

    # ── Test 1: envío exitoso ──
    def test_envio_exitoso_marca_evento_sincronizado(self, local_conn, monkeypatch):
        self._configurar()
        monkeypatch.setattr(
            sync_client.requests, "post",
            lambda *a, **k: FakeResponse(201, {"status": "creado", "event_id": 42}),
        )

        resultado_insercion = insert_event_and_enqueue_sync(local_conn, _evento_base())
        resultado = sync_client.try_sync_event(local_conn, resultado_insercion["event_id"])

        assert resultado["ok"] is True
        fila = local_conn.execute(
            "SELECT estado FROM audit_sync_queue WHERE event_id = ?", (resultado_insercion["event_id"],)
        ).fetchone()
        assert fila[0] == "SINCRONIZADO"

    # ── Test 2: servidor no disponible ──
    def test_servidor_no_disponible_evento_permanece_pendiente_localmente(self, local_conn, monkeypatch):
        self._configurar()

        def _falla(*a, **k):
            raise requests.exceptions.ConnectionError("no se pudo conectar")

        monkeypatch.setattr(sync_client.requests, "post", _falla)

        resultado_insercion = insert_event_and_enqueue_sync(local_conn, _evento_base())
        resultado = sync_client.try_sync_event(local_conn, resultado_insercion["event_id"])

        assert resultado["ok"] is False
        assert resultado["motivo"] == "SIN_CONEXION"

        fila = local_conn.execute(
            "SELECT estado FROM audit_sync_queue WHERE event_id = ?", (resultado_insercion["event_id"],)
        ).fetchone()
        assert fila[0] == "FALLIDO"  # nunca se borra ni desaparece de la cola
        # El evento auditado en sí sigue intacto en audit_log (inmutable).
        assert local_conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_id = ?", (resultado_insercion["event_id"],)
        ).fetchone()[0] == 1

    # ── Test 3: recuperación de conexión ──
    def test_recuperacion_de_conexion_sincroniza_evento_pendiente(self, local_conn, monkeypatch):
        self._configurar()
        respuestas = iter([
            requests.exceptions.ConnectionError("caído"),
            requests.exceptions.ConnectionError("caído"),
            requests.exceptions.ConnectionError("caído"),
        ])

        def _falla_luego_ok(*a, **k):
            try:
                exc = next(respuestas)
            except StopIteration:
                return FakeResponse(201, {"status": "creado", "event_id": 1})
            raise exc

        monkeypatch.setattr(sync_client.requests, "post", _falla_luego_ok)

        resultado_insercion = insert_event_and_enqueue_sync(local_conn, _evento_base())
        primer_intento = sync_client.try_sync_event(local_conn, resultado_insercion["event_id"])
        assert primer_intento["ok"] is False  # agotó los 3 intentos, todos fallaron

        # "Vuelve la conexión": el próximo POST ya no lanza excepción.
        monkeypatch.setattr(sync_client.requests, "post", lambda *a, **k: FakeResponse(200, {"status": "creado", "event_id": 1}))
        resumen = sync_client.sync_pending_events(local_conn)

        assert resumen["sincronizados"] == 1
        fila = local_conn.execute(
            "SELECT estado FROM audit_sync_queue WHERE event_id = ?", (resultado_insercion["event_id"],)
        ).fetchone()
        assert fila[0] == "SINCRONIZADO"

    # ── Test 4: token inválido ──
    def test_token_invalido_no_reintenta_y_no_elimina_el_evento(self, local_conn, monkeypatch):
        self._configurar()
        llamadas = []

        def _rechazo(*a, **k):
            llamadas.append(1)
            return FakeResponse(401, {"status": "error", "mensaje": "Token inválido"})

        monkeypatch.setattr(sync_client.requests, "post", _rechazo)

        resultado_insercion = insert_event_and_enqueue_sync(local_conn, _evento_base())
        resultado = sync_client.try_sync_event(local_conn, resultado_insercion["event_id"])

        assert resultado["ok"] is False
        assert resultado["motivo"] == "AUTENTICACION"
        assert len(llamadas) == 1, "Un rechazo de autenticación no debe reintentarse (sin retry infinito)"

        fila = local_conn.execute(
            "SELECT estado FROM audit_sync_queue WHERE event_id = ?", (resultado_insercion["event_id"],)
        ).fetchone()
        assert fila[0] == "FALLIDO"
        assert local_conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_id = ?", (resultado_insercion["event_id"],)
        ).fetchone()[0] == 1  # el evento no se elimina silenciosamente

    # ── Test 5: idempotencia (lado cliente) ──
    def test_no_reenvia_un_evento_ya_sincronizado(self, local_conn, monkeypatch):
        self._configurar()
        llamadas = []
        monkeypatch.setattr(
            sync_client.requests, "post",
            lambda *a, **k: (llamadas.append(1), FakeResponse(201, {"status": "creado", "event_id": 1}))[1],
        )

        resultado_insercion = insert_event_and_enqueue_sync(local_conn, _evento_base())
        sync_client.try_sync_event(local_conn, resultado_insercion["event_id"])
        assert len(llamadas) == 1

        # Segundo intento sobre el mismo evento ya SINCRONIZADO: no debe volver a llamar a requests.post.
        resultado2 = sync_client.try_sync_event(local_conn, resultado_insercion["event_id"])
        assert resultado2["motivo"] == "YA_SINCRONIZADO"
        assert len(llamadas) == 1

    def test_sin_configurar_no_llama_http_y_deja_evento_pendiente(self, local_conn, monkeypatch):
        llamadas = []
        monkeypatch.setattr(sync_client.requests, "post", lambda *a, **k: llamadas.append(1))

        resultado_insercion = insert_event_and_enqueue_sync(local_conn, _evento_base())
        resultado = sync_client.try_sync_event(local_conn, resultado_insercion["event_id"])

        assert resultado["motivo"] == "SIN_CONFIGURAR"
        assert llamadas == []
        fila = local_conn.execute(
            "SELECT estado FROM audit_sync_queue WHERE event_id = ?", (resultado_insercion["event_id"],)
        ).fetchone()
        assert fila[0] == "FALLIDO"

    def test_url_no_https_es_rechazada(self):
        with pytest.raises(ValueError):
            sync_client.configure_sync("http://servidor-remoto.example.org", "tk_x", auto=False)

    def test_url_http_localhost_permitida_para_pruebas(self):
        sync_client.configure_sync("http://127.0.0.1:5001", "tk_x", auto=False)
        assert sync_client.is_configured()


# ──────────────────────────────────────────────────────────────
# CA5 — Idempotencia a nivel de base de datos (insert_event_if_new)
# ──────────────────────────────────────────────────────────────

class TestInsertEventIfNew:
    def test_primera_insercion_crea_la_fila(self, central_conn):
        registro, creado = insert_event_if_new(central_conn, _evento_base())
        assert creado is True
        assert registro["event_id"] is not None

    def test_segunda_insercion_con_mismo_evento_uuid_no_duplica(self, central_conn):
        evento = _evento_base()
        registro1, creado1 = insert_event_if_new(central_conn, dict(evento))
        # Reenvío del mismo evento_uuid, como en un reintento del cliente.
        evento_reenviado = dict(evento)
        evento_reenviado["evento_uuid"] = registro1["evento_uuid"]
        registro2, creado2 = insert_event_if_new(central_conn, evento_reenviado)

        assert creado1 is True
        assert creado2 is False
        assert registro1["event_id"] == registro2["event_id"]

        total = central_conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE evento_uuid = ?", (registro1["evento_uuid"],)
        ).fetchone()[0]
        assert total == 1

    def test_falta_evento_uuid_lanza_value_error(self, central_conn):
        evento = _evento_base()
        evento.pop("evento_uuid", None)
        with pytest.raises(ValueError):
            insert_event_if_new(central_conn, evento)

    def test_carrera_concurrente_se_recupera_via_integrity_error(self, central_conn, monkeypatch):
        """
        Simula la carrera real: dos requests llegan casi a la vez para el
        mismo evento_uuid. El SELECT de insert_event_if_new no lo ve
        todavía (monkeypatch fuerza ese camino), pero la restricción
        UNIQUE de la base sí lo detecta en el INSERT — que es la garantía
        real de idempotencia, no el SELECT previo.
        """
        evento = _evento_base()
        registro_ganador, _ = insert_event_if_new(central_conn, dict(evento))

        evento_reenviado = dict(evento)
        evento_reenviado["evento_uuid"] = registro_ganador["evento_uuid"]

        import audit_tracer.models.audit_log as audit_log_module
        original_get_by_uuid = audit_log_module.get_event_by_uuid
        llamadas = {"n": 0}

        def _select_no_ve_la_fila_la_primera_vez(conn, uuid_):
            llamadas["n"] += 1
            if llamadas["n"] == 1:
                return None  # simula la ventana de la carrera
            return original_get_by_uuid(conn, uuid_)

        monkeypatch.setattr(audit_log_module, "get_event_by_uuid", _select_no_ve_la_fila_la_primera_vez)

        registro_perdedor, creado = insert_event_if_new(central_conn, evento_reenviado)

        assert creado is False
        assert registro_perdedor["event_id"] == registro_ganador["event_id"]
        total = central_conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE evento_uuid = ?", (registro_ganador["evento_uuid"],)
        ).fetchone()[0]
        assert total == 1


# ──────────────────────────────────────────────────────────────
# Endpoint receptor: POST /api/eventos/sincronizar
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def api_client(monkeypatch, tmp_path):
    """
    Cliente Flask de pruebas con get_db() redirigido a una base central
    AISLADA (a diferencia de otros tests del repo que sin querer pegan
    contra audit_central.db real, aquí cada test tiene su propio archivo).
    """
    db_path = str(tmp_path / "central_api_test.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        yield client, db_path


@pytest.fixture
def token_activo(api_client):
    _, db_path = api_client
    conn = get_central_connection(db_path)
    user_id = create_user(conn, "colab_user@test.com", "Password123!", "CIENTIFICO_DATOS")
    token_info = generar_token(conn, user_id)
    conn.close()
    return token_info["token"], user_id


class TestEndpointSincronizarEventos:
    def _payload(self, usuario_id="u1", **overrides):
        payload = {
            "evento_uuid": "11111111-1111-1111-1111-111111111111",
            "usuario_id": usuario_id,
            "sesion_id": "s1",
            "timestamp": "2026-01-01T10:00:00",
            "tipo_accion": "CARGA",
            "dataset_nombre": "PATIENTS.csv",
            "columnas_afectadas": '["id","edad"]',
            "nivel_alerta": "NORMAL",
        }
        payload.update(overrides)
        return payload

    def test_token_valido_inserta_evento_y_responde_201(self, api_client, token_activo):
        client, db_path = api_client
        token, user_id = token_activo

        resp = client.post(
            "/api/eventos/sincronizar",
            json=self._payload(usuario_id=user_id),
            headers={"Authorization": f"Bearer {token}"},
        )

        assert resp.status_code == 201
        body = resp.get_json()
        assert body["status"] == "creado"

        conn = get_central_connection(db_path)
        evento = get_event_by_uuid(conn, "11111111-1111-1111-1111-111111111111")
        conn.close()
        assert evento is not None
        assert evento["usuario_id"] == user_id

    def test_mismo_evento_dos_veces_no_duplica_en_la_central(self, api_client, token_activo):
        """CA5 — Test 5 (a nivel de endpoint real, sin mocks)."""
        client, db_path = api_client
        token, user_id = token_activo
        payload = self._payload(usuario_id=user_id)

        resp1 = client.post("/api/eventos/sincronizar", json=payload, headers={"Authorization": f"Bearer {token}"})
        resp2 = client.post("/api/eventos/sincronizar", json=payload, headers={"Authorization": f"Bearer {token}"})

        assert resp1.status_code == 201
        assert resp2.status_code == 200
        assert resp2.get_json()["status"] == "duplicado"

        conn = get_central_connection(db_path)
        total = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE evento_uuid = ?", (payload["evento_uuid"],)
        ).fetchone()[0]
        conn.close()
        assert total == 1

    def test_token_inexistente_responde_401_y_no_inserta(self, api_client):
        client, db_path = api_client
        resp = client.post(
            "/api/eventos/sincronizar",
            json=self._payload(),
            headers={"Authorization": "Bearer tk_no_existe"},
        )
        assert resp.status_code == 401

        conn = get_central_connection(db_path)
        evento = get_event_by_uuid(conn, "11111111-1111-1111-1111-111111111111")
        conn.close()
        assert evento is None

    def test_token_revocado_responde_401(self, api_client, token_activo):
        from audit_tracer.auth.tokens import revocar_token

        client, db_path = api_client
        token, user_id = token_activo

        conn = get_central_connection(db_path)
        revocar_token(conn, token)
        conn.close()

        resp = client.post(
            "/api/eventos/sincronizar",
            json=self._payload(usuario_id=user_id),
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 401

    def test_sin_token_responde_401(self, api_client):
        client, _ = api_client
        resp = client.post("/api/eventos/sincronizar", json=self._payload())
        assert resp.status_code == 401

    # ── CA5: HTTPS obligatorio (excepto localhost/127.0.0.1) ──
    def test_peticion_no_https_fuera_de_localhost_responde_426(self, api_client, token_activo):
        client, db_path = api_client
        token, user_id = token_activo

        resp = client.post(
            "/api/eventos/sincronizar",
            json=self._payload(usuario_id=user_id),
            headers={"Authorization": f"Bearer {token}"},
            base_url="http://servidor-remoto.example.org",
        )

        assert resp.status_code == 426
        assert resp.get_json()["status"] == "error"

        # No debe haber insertado nada: el rechazo por transporte ocurre
        # antes de tocar el token o el payload.
        conn = get_central_connection(db_path)
        evento = get_event_by_uuid(conn, self._payload()["evento_uuid"])
        conn.close()
        assert evento is None

    def test_peticion_no_https_se_rechaza_incluso_sin_token(self, api_client):
        """CA5 se evalúa antes que CA2: no hace falta un token para que el rechazo por
        transporte ya responda — así nunca se procesan credenciales sobre un canal inseguro."""
        client, _ = api_client
        resp = client.post(
            "/api/eventos/sincronizar",
            json=self._payload(),
            base_url="http://servidor-remoto.example.org",
        )
        assert resp.status_code == 426

    def test_peticion_http_en_localhost_se_permite_para_pruebas_y_dev(self, api_client, token_activo):
        """Misma excepción que ya aplica sync_client.py del lado cliente."""
        client, db_path = api_client
        token, user_id = token_activo

        resp = client.post(
            "/api/eventos/sincronizar",
            json=self._payload(usuario_id=user_id),
            headers={"Authorization": f"Bearer {token}"},
            base_url="http://localhost/",
        )

        assert resp.status_code == 201

    def test_payload_incompleto_responde_400(self, api_client, token_activo):
        client, _ = api_client
        token, user_id = token_activo

        payload = self._payload(usuario_id=user_id)
        del payload["tipo_accion"]

        resp = client.post("/api/eventos/sincronizar", json=payload, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 400
        assert resp.get_json()["status"] == "error"

    def test_cuerpo_no_json_responde_400_sin_error_500(self, api_client, token_activo):
        client, _ = api_client
        token, _ = token_activo
        resp = client.post(
            "/api/eventos/sincronizar",
            data="esto no es json",
            content_type="text/plain",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 400

    def test_rechazo_por_token_invalido_queda_registrado_sin_exponer_el_token(self, api_client):
        client, db_path = api_client
        token_secreto = "tk_super_secreto_no_debe_aparecer"

        resp = client.post(
            "/api/eventos/sincronizar",
            json=self._payload(),
            headers={"Authorization": f"Bearer {token_secreto}"},
        )
        assert resp.status_code == 401

        conn = get_central_connection(db_path)
        rechazos = conn.execute(
            "SELECT motivo_fallo, contexto_ejecucion FROM audit_log WHERE tipo_accion = 'SINCRONIZACION_RECHAZADA'"
        ).fetchall()
        conn.close()

        assert len(rechazos) == 1
        for motivo, contexto in rechazos:
            assert token_secreto not in (motivo or "")
            assert token_secreto not in (contexto or "")


# ──────────────────────────────────────────────────────────────
# Integración extremo a extremo — servidor Flask real, sin mocks
# ──────────────────────────────────────────────────────────────

class _ServidorHiloDePrueba(threading.Thread):
    """Servidor Werkzeug real en 127.0.0.1:<puerto libre>, para probar el cliente HTTP sin mocks."""

    def __init__(self, flask_app):
        super().__init__(daemon=True)
        self.server = make_server("127.0.0.1", 0, flask_app)
        self.port = self.server.server_port

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


class TestIntegracionExtremoAExtremo:
    """
    DoD — "Los eventos generados en un entorno de prueba se reflejan
    correctamente en la base central" + "se valida el comportamiento sin
    conexión y la recuperación posterior", con un servidor HTTP real (no
    mockeado) y bases SQLite reales en disco.
    """

    def test_evento_local_llega_a_la_central_real_y_se_recupera_tras_caida(self, monkeypatch, tmp_path):
        central_path = str(tmp_path / "central_e2e.db")
        monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(central_path))

        servidor = _ServidorHiloDePrueba(app_module.app)
        servidor.start()
        time.sleep(0.2)  # margen para que el socket quede escuchando

        try:
            central_conn = get_central_connection(central_path)
            user_id = create_user(central_conn, "colab_e2e@test.com", "Password123!", "CIENTIFICO_DATOS")
            token_info = generar_token(central_conn, user_id)
            central_conn.close()

            local_conn = get_connection(str(tmp_path / "local_e2e.db"))
            sync_client.configure_sync(f"http://127.0.0.1:{servidor.port}", token_info["token"], auto=False)

            # 1) Evento capturado con el servidor arriba -> debe sincronizarse de verdad.
            r1 = insert_event_and_enqueue_sync(local_conn, _evento_base(user_id))
            resultado1 = sync_client.try_sync_event(local_conn, r1["event_id"])
            assert resultado1["ok"] is True

            estado1 = local_conn.execute(
                "SELECT estado FROM audit_sync_queue WHERE event_id = ?", (r1["event_id"],)
            ).fetchone()[0]
            assert estado1 == "SINCRONIZADO"

            conn_verif = get_central_connection(central_path)
            evento_central = get_event_by_uuid(conn_verif, r1["evento_uuid"])
            conn_verif.close()
            assert evento_central is not None
            assert evento_central["usuario_id"] == user_id

            # 2) Servidor "caído": apuntamos a un puerto sin nada escuchando.
            sync_client.configure_sync(f"http://127.0.0.1:1", token_info["token"], auto=False)
            r2 = insert_event_and_enqueue_sync(local_conn, _evento_base(user_id, "CONSULTA"))
            resultado2 = sync_client.try_sync_event(local_conn, r2["event_id"])
            assert resultado2["ok"] is False

            estado2 = local_conn.execute(
                "SELECT estado FROM audit_sync_queue WHERE event_id = ?", (r2["event_id"],)
            ).fetchone()[0]
            assert estado2 == "FALLIDO"  # sigue en la cola, no se perdió

            # 3) Recuperación: el servidor real vuelve a estar disponible, se barre la cola.
            sync_client.configure_sync(f"http://127.0.0.1:{servidor.port}", token_info["token"], auto=False)
            resumen = sync_client.sync_pending_events(local_conn)
            assert resumen["sincronizados"] == 1

            estado2b = local_conn.execute(
                "SELECT estado FROM audit_sync_queue WHERE event_id = ?", (r2["event_id"],)
            ).fetchone()[0]
            assert estado2b == "SINCRONIZADO"

            conn_verif2 = get_central_connection(central_path)
            evento_central2 = get_event_by_uuid(conn_verif2, r2["evento_uuid"])
            total_r1 = conn_verif2.execute(
                "SELECT COUNT(*) FROM audit_log WHERE evento_uuid = ?", (r1["evento_uuid"],)
            ).fetchone()[0]
            total_r2 = conn_verif2.execute(
                "SELECT COUNT(*) FROM audit_log WHERE evento_uuid = ?", (r2["evento_uuid"],)
            ).fetchone()[0]
            conn_verif2.close()
            assert evento_central2 is not None
            assert total_r1 == 1  # sin duplicados pese al reintento
            assert total_r2 == 1  # sin duplicados pese al reintento

            local_conn.close()
        finally:
            servidor.shutdown()
            servidor.join(timeout=5)


# ──────────────────────────────────────────────────────────────
# Sub-tarea 6 — Panel de diagnóstico en el dashboard admin
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def admin_client(monkeypatch, tmp_path):
    db_path = str(tmp_path / "central_admin_test.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        with client.session_transaction() as sess:
            sess["usuario_id"] = "admin1"
            sess["rol"] = "ADMIN"
            sess["nombre"] = "Admin Test"
            sess["sesion_id"] = "s_admin"
        yield client, db_path


class TestDashboardSincronizacion:
    def test_pagina_responde_200_sin_rechazos_registrados(self, admin_client):
        client, _ = admin_client
        resp = client.get("/admin/sincronizacion")
        assert resp.status_code == 200
        assert b"Sincronizaci" in resp.data  # "Sincronización" (evita depender de encoding exacto)

    def test_pagina_no_expone_el_valor_de_un_token_rechazado(self, admin_client):
        client, db_path = admin_client
        token_secreto = "tk_no_debe_verse_en_el_dashboard"

        client.post(
            "/api/eventos/sincronizar",
            json={
                "evento_uuid": str(uuid.uuid4()), "usuario_id": "u1", "sesion_id": "s1",
                "timestamp": "2026-01-01T00:00:00", "tipo_accion": "CARGA",
            },
            headers={"Authorization": f"Bearer {token_secreto}"},
        )

        resp = client.get("/admin/sincronizacion")
        assert resp.status_code == 200
        assert token_secreto.encode() not in resp.data
        assert b"1 en total" in resp.data or b">1<" in resp.data  # al menos un rechazo listado

    def test_requiere_rol_admin(self, monkeypatch, tmp_path):
        db_path = str(tmp_path / "central_no_admin.db")
        monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
        app_module.app.config["TESTING"] = True
        with app_module.app.test_client() as client:
            with client.session_transaction() as sess:
                sess["usuario_id"] = "analista1"
                sess["rol"] = "ANALISTA"
                sess["nombre"] = "Analista Test"
                sess["sesion_id"] = "s1"
            resp = client.get("/admin/sincronizacion")
            assert resp.status_code in (302, 403)
