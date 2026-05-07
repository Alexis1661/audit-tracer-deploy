"""
test_control_acceso.py
HU-1.4 — Pruebas unitarias del control de acceso por rol.

Cubre todos los criterios de aceptación:
  CA1  Definición de permisos por módulo
  CA2  Bloqueo y registro en audit_log con ACCESO_DENEGADO
  CA3  Validación en tiempo de ejecución (decorador)
  CA4  Los 4 roles predefinidos con su matriz de permisos

La matriz a probar es:

              captura  consulta  gestion  alertas  exportaciones
ADMIN            ✓        ✓        ✓        ✓          ✓
ANALISTA         ✗        ✓        ✗        ✓          ✓
AUDITOR          ✗        ✓        ✗        ✗          ✓
CIENTIFICO_DATOS ✓        ✗        ✗        ✓          ✗
"""

import os
import pytest
import sqlite3

from audit_tracer.models.audit_log import get_events
from audit_tracer.auth.control_acceso import (
    has_permission,
    requires_role,
    AccesoDenegadoError,
    PERMISSION_MATRIX,
    MODULES,
)


_SCHEMA_DIR = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "schema")
)
_SCHEMA_FILES = ["usuarios.sql", "audit_log.sql"]


@pytest.fixture
def db_conn():
    """SQLite en memoria, schema cargado desde los archivos SQL del proyecto."""
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    for schema_file in _SCHEMA_FILES:
        path = os.path.join(_SCHEMA_DIR, schema_file)
        with open(path, "r", encoding="utf-8") as f:
            conn.executescript(f.read())
    conn.commit()
    yield conn
    conn.close()


class TestPermissionMatrix:
    """CA1: Verifica que la matriz cubra todos los módulos y roles."""

    def test_matrix_contains_all_roles(self):
        expected_roles = {"ADMIN", "ANALISTA", "AUDITOR", "CIENTIFICO_DATOS"}
        assert set(PERMISSION_MATRIX.keys()) == expected_roles

    def test_matrix_uses_valid_modules(self):
        for role, perms in PERMISSION_MATRIX.items():
            for mod in perms:
                assert mod in MODULES, (
                    f"Módulo '{mod}' en rol '{role}' no está en MODULES"
                )

    # ---- ADMIN: acceso total ------------------------------------------------
    def test_admin_has_access_to_captura_eventos(self):
        assert has_permission("ADMIN", "captura_eventos") is True

    def test_admin_has_access_to_consulta_reportes(self):
        assert has_permission("ADMIN", "consulta_reportes") is True

    def test_admin_has_access_to_gestion_usuarios(self):
        assert has_permission("ADMIN", "gestion_usuarios") is True

    def test_admin_has_access_to_visualizacion_alertas(self):
        assert has_permission("ADMIN", "visualizacion_alertas") is True

    def test_admin_has_access_to_exportaciones(self):
        assert has_permission("ADMIN", "exportaciones") is True

    # ---- ANALISTA -----------------------------------------------------------
    def test_analista_can_access_consulta_reportes(self):
        assert has_permission("ANALISTA", "consulta_reportes") is True

    def test_analista_can_access_visualizacion_alertas(self):
        assert has_permission("ANALISTA", "visualizacion_alertas") is True

    def test_analista_can_access_exportaciones(self):
        assert has_permission("ANALISTA", "exportaciones") is True

    def test_analista_cannot_access_captura_eventos(self):
        assert has_permission("ANALISTA", "captura_eventos") is False

    def test_analista_cannot_access_gestion_usuarios(self):
        assert has_permission("ANALISTA", "gestion_usuarios") is False

    # ---- AUDITOR ------------------------------------------------------------
    def test_auditor_can_access_consulta_reportes(self):
        assert has_permission("AUDITOR", "consulta_reportes") is True

    def test_auditor_can_access_exportaciones(self):
        assert has_permission("AUDITOR", "exportaciones") is True

    def test_auditor_cannot_access_captura_eventos(self):
        assert has_permission("AUDITOR", "captura_eventos") is False

    def test_auditor_cannot_access_gestion_usuarios(self):
        assert has_permission("AUDITOR", "gestion_usuarios") is False

    def test_auditor_cannot_access_visualizacion_alertas(self):
        assert has_permission("AUDITOR", "visualizacion_alertas") is False

    # ---- CIENTIFICO_DATOS ---------------------------------------------------
    def test_cientifico_can_access_captura_eventos(self):
        assert has_permission("CIENTIFICO_DATOS", "captura_eventos") is True

    def test_cientifico_can_access_visualizacion_alertas(self):
        assert has_permission("CIENTIFICO_DATOS", "visualizacion_alertas") is True

    def test_cientifico_cannot_access_consulta_reportes(self):
        assert has_permission("CIENTIFICO_DATOS", "consulta_reportes") is False

    def test_cientifico_cannot_access_gestion_usuarios(self):
        assert has_permission("CIENTIFICO_DATOS", "gestion_usuarios") is False

    def test_cientifico_cannot_access_exportaciones(self):
        assert has_permission("CIENTIFICO_DATOS", "exportaciones") is False

    # ---- Rol desconocido ----------------------------------------------------
    def test_unknown_role_denied_all_modules(self):
        for mod in MODULES:
            assert has_permission("INTRUSO", mod) is False


class TestAccessDeniedLogging:
    """CA2: El acceso denegado debe registrarse en audit_log."""

    def _make_restricted_op(self):
        """Operación de prueba que solo ADMIN puede ejecutar."""

        @requires_role(roles=["ADMIN"], modulo="gestion_usuarios")
        def op_admin_only(conn, usuario_id, sesion_id, rol):
            return "ok"

        return op_admin_only

    def test_denied_access_raises_error(self, db_conn):
        op = self._make_restricted_op()
        with pytest.raises(AccesoDenegadoError):
            op(db_conn, "user-1", "session-1", "ANALISTA")

    def test_denied_access_logged_in_audit_log(self, db_conn):
        op = self._make_restricted_op()
        try:
            op(db_conn, "user-1", "session-1", "AUDITOR")
        except AccesoDenegadoError:
            pass

        events = get_events(db_conn, tipo_accion="ACCESO_DENEGADO", usuario_id="user-1")
        assert len(events) == 1
        assert "AUDITOR" in events[0]["contexto_ejecucion"]
        assert "gestion_usuarios" in events[0]["contexto_ejecucion"]

    def test_denied_access_error_message_contains_role_and_module(self, db_conn):
        op = self._make_restricted_op()
        with pytest.raises(AccesoDenegadoError) as exc_info:
            op(db_conn, "u1", "s1", "CIENTIFICO_DATOS")
        assert "CIENTIFICO_DATOS" in str(exc_info.value)
        assert "gestion_usuarios" in str(exc_info.value)

    def test_multiple_denied_events_are_all_logged(self, db_conn):
        op = self._make_restricted_op()
        for i in range(3):
            try:
                op(db_conn, "user-multi", f"session-{i}", "ANALISTA")
            except AccesoDenegadoError:
                pass

        events = get_events(db_conn, tipo_accion="ACCESO_DENEGADO", usuario_id="user-multi")
        assert len(events) == 3

class TestRequiresRoleDecorator:
    """CA3: El decorador valida permisos en cada llamada, no solo al inicio."""

    def test_allowed_role_executes_function(self, db_conn):
        @requires_role(roles=["ANALISTA", "ADMIN"], modulo="consulta_reportes")
        def ver_reportes(conn, usuario_id, sesion_id, rol):
            return "reportes_ok"

        result = ver_reportes(db_conn, "u1", "s1", "ANALISTA")
        assert result == "reportes_ok"

    def test_disallowed_role_is_blocked_at_runtime(self, db_conn):
        @requires_role(roles=["ADMIN"], modulo="gestion_usuarios")
        def gestionar_usuarios(conn, usuario_id, sesion_id, rol):
            return "users_ok"

        with pytest.raises(AccesoDenegadoError):
            gestionar_usuarios(db_conn, "u2", "s2", "AUDITOR")

    def test_role_check_is_per_call_not_once(self, db_conn):
        """Llamar la misma función con distintos roles produce resultados distintos."""

        @requires_role(roles=["ADMIN"], modulo="gestion_usuarios")
        def op(conn, usuario_id, sesion_id, rol):
            return "ejecutado"

        # Primera llamada: ADMIN → OK
        assert op(db_conn, "u1", "s1", "ADMIN") == "ejecutado"

        # Segunda llamada: ANALISTA → denegado
        with pytest.raises(AccesoDenegadoError):
            op(db_conn, "u1", "s2", "ANALISTA")

    def test_decorator_preserves_function_name(self):
        @requires_role(roles=["ADMIN"], modulo="gestion_usuarios")
        def funcion_especial(conn, usuario_id, sesion_id, rol):
            pass

        assert funcion_especial.__name__ == "funcion_especial"

    def test_decorator_exposes_required_roles_metadata(self):
        @requires_role(roles=["AUDITOR", "ADMIN"], modulo="exportaciones")
        def exportar(conn, usuario_id, sesion_id, rol):
            pass

        assert exportar._required_roles == ["AUDITOR", "ADMIN"]
        assert exportar._modulo == "exportaciones"

    def test_kwargs_usage_is_supported(self, db_conn):
        @requires_role(roles=["CIENTIFICO_DATOS"], modulo="captura_eventos")
        def capturar(conn, usuario_id, sesion_id, rol):
            return "capturado"

        result = capturar(
            conn=db_conn,
            usuario_id="u3",
            sesion_id="s3",
            rol="CIENTIFICO_DATOS",
        )
        assert result == "capturado"

    def test_wrong_role_via_kwargs_is_blocked(self, db_conn):
        @requires_role(roles=["CIENTIFICO_DATOS"], modulo="captura_eventos")
        def capturar(conn, usuario_id, sesion_id, rol):
            return "capturado"

        with pytest.raises(AccesoDenegadoError):
            capturar(
                conn=db_conn,
                usuario_id="u4",
                sesion_id="s4",
                rol="AUDITOR",
            )


class TestFullPermissionMatrix:
    """
    CA4: Prueba cada combinación (rol, módulo) contra la matriz esperada.
    Genera exactamente 20 afirmaciones (4 roles × 5 módulos).
    """

    EXPECTED: dict[str, dict[str, bool]] = {
        "ADMIN": {
            "captura_eventos": True,
            "consulta_reportes": True,
            "gestion_usuarios": True,
            "visualizacion_alertas": True,
            "exportaciones": True,
        },
        "ANALISTA": {
            "captura_eventos": False,
            "consulta_reportes": True,
            "gestion_usuarios": False,
            "visualizacion_alertas": True,
            "exportaciones": True,
        },
        "AUDITOR": {
            "captura_eventos": False,
            "consulta_reportes": True,
            "gestion_usuarios": False,
            "visualizacion_alertas": False,
            "exportaciones": True,
        },
        "CIENTIFICO_DATOS": {
            "captura_eventos": True,
            "consulta_reportes": False,
            "gestion_usuarios": False,
            "visualizacion_alertas": True,
            "exportaciones": False,
        },
    }

    @pytest.mark.parametrize(
        "rol,modulo,expected",
        [
            (rol, mod, val)
            for rol, perms in EXPECTED.items()
            for mod, val in perms.items()
        ],
    )
    def test_permission_combination(self, rol, modulo, expected):
        result = has_permission(rol, modulo)
        assert result == expected, (
            f"Fallo en has_permission('{rol}', '{modulo}'): "
            f"esperado {expected}, obtenido {result}"
        )
