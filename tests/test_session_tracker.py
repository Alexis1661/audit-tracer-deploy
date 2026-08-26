"""
tests/test_session_tracker.py
==============================
Pruebas unitarias — HU-2.5: Asociar cada evento a un usuario único identificable
(modo librería / notebook, vía SessionTracker.login()/logout()).

CA3: sesion_id se conserva entre login/logout (no se genera una sesión nueva).
CA4: usuario_id del modo librería solo se establece a través de un login
     válido contra auth.autenticacion.login(); antes de eso permanece
     DESCONOCIDO y no puede ser suplantado por un valor arbitrario.
"""

import os
import sqlite3
import pytest

from audit_tracer.session_tracker import SessionTracker
from audit_tracer.auth.registro import register_user
from audit_tracer.models.audit_log import get_events


@pytest.fixture
def tracker_env(monkeypatch, tmp_path):
    """
    Aísla SessionTracker en una BD temporal y devuelve (tracker, conn_a_bd_temporal).
    """
    db_file = str(tmp_path / "audit_trail.db")

    def _mock_get_conn():
        schema_dir = "schema"
        db_exists = os.path.exists(db_file)
        conn = sqlite3.connect(db_file, check_same_thread=False)
        if not db_exists:
            for sql_file in ["usuarios.sql", "audit_log.sql"]:
                path = os.path.join(schema_dir, sql_file)
                if os.path.exists(path):
                    with open(path, encoding="utf-8") as f:
                        conn.executescript(f.read())
            conn.commit()
        return conn

    monkeypatch.setattr("audit_tracer.session_tracker.get_connection", _mock_get_conn)

    tracker = SessionTracker()  # instancia aislada, no el singleton global
    seed_conn = _mock_get_conn()
    yield tracker, seed_conn
    seed_conn.close()


class TestSessionTrackerLogin:
    """CA4: identidad del modo librería solo proviene de un login válido."""

    def test_usuario_inicial_es_desconocido(self, tracker_env):
        """Antes de login(), no hay identidad arbitraria de confianza (ex AUDIT_TRACER_USER)."""
        tracker, _ = tracker_env
        assert tracker.usuario_id == "DESCONOCIDO"

    def test_login_exitoso_actualiza_usuario_id(self, tracker_env):
        tracker, conn = tracker_env
        user_id = register_user(conn, "cientifico@test.com", "pwd12345", "CIENTIFICO_DATOS", "admin")

        result = tracker.login("cientifico@test.com", "pwd12345")

        assert result["success"] is True
        assert tracker.usuario_id == user_id

    def test_login_reutiliza_la_misma_sesion_id(self, tracker_env):
        """CA3: login() no genera una sesion_id nueva; conserva la de la sesión activa."""
        tracker, conn = tracker_env
        register_user(conn, "cientifico2@test.com", "pwd12345", "CIENTIFICO_DATOS", "admin")
        sesion_id_previa = tracker.sesion_id

        result = tracker.login("cientifico2@test.com", "pwd12345")

        assert result["sesion_id"] == sesion_id_previa
        assert tracker.sesion_id == sesion_id_previa

        eventos = get_events(conn, tipo_accion="INICIO_SESION", usuario_id=result["usuario_id"])
        assert len(eventos) == 1
        assert eventos[0]["sesion_id"] == sesion_id_previa

    def test_login_fallido_no_cambia_la_identidad(self, tracker_env):
        """Credenciales inválidas -> el tracker sigue DESCONOCIDO, no queda suplantado."""
        tracker, conn = tracker_env
        register_user(conn, "cientifico3@test.com", "pwd_correcta", "CIENTIFICO_DATOS", "admin")

        result = tracker.login("cientifico3@test.com", "pwd_incorrecta")

        assert result["success"] is False
        assert tracker.usuario_id == "DESCONOCIDO"

    def test_eventos_antes_de_login_quedan_como_desconocido(self, tracker_env):
        """CA2: cualquier evento capturado antes de autenticarse queda DESCONOCIDO/CRITICO."""
        from audit_tracer.models.audit_log import insert_event

        tracker, conn = tracker_env
        insert_event(conn, {
            "usuario_id": tracker.usuario_id,
            "sesion_id": tracker.sesion_id,
            "tipo_accion": "CONSULTA",
        })

        eventos = get_events(conn, usuario_id="DESCONOCIDO")
        assert len(eventos) == 1
        assert eventos[0]["nivel_alerta"] == "CRITICO"
        assert eventos[0]["sesion_id"] == tracker.sesion_id


class TestSessionTrackerLogout:
    """CA4: logout() vuelve a DESCONOCIDO para no atribuir eventos posteriores al usuario anterior."""

    def test_logout_vuelve_a_desconocido(self, tracker_env):
        tracker, conn = tracker_env
        register_user(conn, "cientifico4@test.com", "pwd12345", "CIENTIFICO_DATOS", "admin")
        tracker.login("cientifico4@test.com", "pwd12345")
        assert tracker.usuario_id != "DESCONOCIDO"

        tracker.logout()

        assert tracker.usuario_id == "DESCONOCIDO"

    def test_logout_sin_login_previo_no_falla(self, tracker_env):
        tracker, _ = tracker_env
        tracker.logout()  # no debe lanzar excepción
        assert tracker.usuario_id == "DESCONOCIDO"
