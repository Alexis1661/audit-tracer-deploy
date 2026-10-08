"""
tests/test_failed_access.py
============================
Pruebas unitarias — HU-2.4: Registrar intentos fallidos de acceso a datos clínicos

Cubre todos los criterios de aceptación:
  CA1: Registro de ACCESO_FALLIDO ante FileNotFoundError, PermissionError, etc.
  CA2: Campos requeridos: usuario_id, timestamp, dataset_nombre, motivo_fallo, sesion_id
  CA3: Alerta CRITICO tras >3 intentos fallidos del mismo usuario en <5 minutos
  CA4: Consultable en reportes con filtro tipo_accion = ACCESO_FALLIDO

Subtasks validadas:
  PDGTRAZDSA-63 — Interceptar excepciones de acceso
  PDGTRAZDSA-64 — Capturar motivo del fallo
  PDGTRAZDSA-65 — Registro en audit_log
  PDGTRAZDSA-66 — Detección de intentos repetidos
"""

import os
import pytest
import sqlite3
import pandas as pd
from datetime import datetime, timedelta
from unittest.mock import patch

from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import get_events
from audit_tracer import data_capture
from audit_tracer import failed_access
from audit_tracer.failed_access import (
    log_failed_access,
    reset_attempts,
    _failed_attempts,
    _ALERT_THRESHOLD,
    _ALERT_WINDOW_MINUTES,
    intercept_access_failures,
    ACCESS_FAILURE_EXCEPTIONS,
)


# ──────────────────────────────────────────────────────────────
# FIXTURES
# ──────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_db(monkeypatch, tmp_path):
    """
    Crea una BD temporal aislada para cada test.
    Redirige get_connection() en failed_access y data_capture hacia ella.
    """
    db_file = str(tmp_path / "audit_trail_hu24.db")

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

    monkeypatch.setattr("audit_tracer.failed_access.get_connection", _mock_get_conn)
    monkeypatch.setattr("audit_tracer.data_capture.get_connection", _mock_get_conn)

    # Activar interceptor de datos en estado limpio
    data_capture.deactivate()
    data_capture.activate()

    # Reiniciar contadores de intentos fallidos antes de cada test
    reset_attempts()

    yield db_file, _mock_get_conn

    data_capture.deactivate()
    reset_attempts()


@pytest.fixture
def mock_conn(clean_db):
    """Helper: devuelve la función mock_get_conn."""
    _, mock_get_conn = clean_db
    return mock_get_conn


def _get_failed_events(mock_conn_fn):
    """Helper: obtiene todos los eventos ACCESO_FALLIDO de la BD de test."""
    conn = mock_conn_fn()
    events = get_events(conn, tipo_accion="ACCESO_FALLIDO")
    conn.close()
    return events


def _all_events(mock_conn_fn):
    """Helper: obtiene todos los eventos de la BD de test."""
    conn = mock_conn_fn()
    events = get_events(conn)
    conn.close()
    return events


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-63: Interceptar excepciones de acceso (CA1)
# ──────────────────────────────────────────────────────────────

class TestInterceptarExcepciones:
    """CA1 — El sistema registra FileNotFoundError como ACCESO_FALLIDO."""

    def test_file_not_found_genera_acceso_fallido(self, mock_conn):
        """CA1 / PDGTRAZDSA-63: FileNotFoundError → tipo_accion = ACCESO_FALLIDO."""
        exc = FileNotFoundError("No such file: pacientes.csv")
        log_failed_access(
            dataset_nombre="pacientes.csv",
            exc=exc,
            usuario_id="usuario_prueba",
            sesion_id="sesion-abc",
        )

        events = _get_failed_events(mock_conn)
        assert len(events) >= 1
        assert events[-1]["tipo_accion"] == "ACCESO_FALLIDO"

    def test_permission_error_genera_acceso_fallido(self, mock_conn):
        """CA1 / PDGTRAZDSA-63: PermissionError → tipo_accion = ACCESO_FALLIDO."""
        exc = PermissionError("Permission denied: historial.csv")
        log_failed_access(
            dataset_nombre="historial.csv",
            exc=exc,
            usuario_id="usuario_prueba",
            sesion_id="sesion-abc",
        )

        events = _get_failed_events(mock_conn)
        assert len(events) >= 1
        assert events[-1]["tipo_accion"] == "ACCESO_FALLIDO"

    def test_os_error_genera_acceso_fallido(self, mock_conn):
        """CA1 / PDGTRAZDSA-63: OSError → tipo_accion = ACCESO_FALLIDO."""
        exc = OSError("I/O error reading datos.csv")
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=exc,
            usuario_id="usuario_prueba",
            sesion_id="sesion-abc",
        )

        events = _get_failed_events(mock_conn)
        assert len(events) >= 1
        assert events[-1]["tipo_accion"] == "ACCESO_FALLIDO"

    def test_read_csv_archivo_inexistente_genera_acceso_fallido(self, mock_conn):
        """CA1: pd.read_csv() sobre archivo inexistente registra ACCESO_FALLIDO."""
        with pytest.raises(FileNotFoundError):
            pd.read_csv("/ruta/inexistente/dataset_clinico.csv")

        events = _get_failed_events(mock_conn)
        assert len(events) >= 1
        assert events[-1]["tipo_accion"] == "ACCESO_FALLIDO"

    def test_read_csv_dataset_nombre_correcto(self, mock_conn):
        """CA1: el campo dataset_nombre coincide con el nombre del archivo."""
        with pytest.raises(FileNotFoundError):
            pd.read_csv("/ruta/inexistente/PATIENTS.csv")

        events = _get_failed_events(mock_conn)
        assert any("PATIENTS.csv" in e["dataset_nombre"] for e in events)

    def test_access_failure_exceptions_son_los_tipos_correctos(self):
        """PDGTRAZDSA-63: los tipos de fallo están correctamente definidos."""
        assert FileNotFoundError in ACCESS_FAILURE_EXCEPTIONS
        assert PermissionError in ACCESS_FAILURE_EXCEPTIONS
        assert OSError in ACCESS_FAILURE_EXCEPTIONS


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-64: Capturar motivo del fallo (CA2)
# ──────────────────────────────────────────────────────────────

class TestCapturarMotivoFallo:
    """CA2 — El registro incluye motivo_fallo correctamente clasificado."""

    def test_file_not_found_motivo_es_archivo_no_existe(self, mock_conn):
        """CA2 / PDGTRAZDSA-64: FileNotFoundError → motivo = 'archivo no existe'."""
        exc = FileNotFoundError("pacientes.csv")
        log_failed_access(
            dataset_nombre="pacientes.csv",
            exc=exc,
            usuario_id="analista01",
            sesion_id="sesion-xyz",
        )

        events = _get_failed_events(mock_conn)
        assert events[-1]["motivo_fallo"] == "archivo no existe"

    def test_permission_error_motivo_es_permiso_denegado(self, mock_conn):
        """CA2 / PDGTRAZDSA-64: PermissionError → motivo = 'permiso denegado'."""
        exc = PermissionError("historial.csv")
        log_failed_access(
            dataset_nombre="historial.csv",
            exc=exc,
            usuario_id="analista01",
            sesion_id="sesion-xyz",
        )

        events = _get_failed_events(mock_conn)
        assert events[-1]["motivo_fallo"] == "permiso denegado"

    def test_motivo_fallo_nunca_es_nulo(self, mock_conn):
        """CA2: motivo_fallo siempre debe estar presente."""
        exc = OSError("error genérico")
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=exc,
            usuario_id="analista01",
            sesion_id="sesion-xyz",
        )

        events = _get_failed_events(mock_conn)
        assert events[-1]["motivo_fallo"] is not None
        assert len(events[-1]["motivo_fallo"]) > 0


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-65: Registro en audit_log (CA2 — campos requeridos)
# ──────────────────────────────────────────────────────────────

class TestRegistroAuditLog:
    """CA2 — El registro incluye usuario_id, timestamp, dataset_nombre, motivo_fallo, sesion_id."""

    def test_evento_contiene_usuario_id(self, mock_conn):
        """CA2: usuario_id presente en el registro."""
        log_failed_access(
            dataset_nombre="clinicos.csv",
            exc=FileNotFoundError("clinicos.csv"),
            usuario_id="medico01",
            sesion_id="sesion-001",
        )
        events = _get_failed_events(mock_conn)
        assert events[-1]["usuario_id"] == "medico01"

    def test_evento_contiene_timestamp(self, mock_conn):
        """CA2: timestamp presente y no nulo."""
        log_failed_access(
            dataset_nombre="clinicos.csv",
            exc=FileNotFoundError("clinicos.csv"),
            usuario_id="medico01",
            sesion_id="sesion-001",
        )
        events = _get_failed_events(mock_conn)
        assert events[-1]["timestamp"] is not None
        assert len(events[-1]["timestamp"]) > 0

    def test_evento_contiene_dataset_nombre(self, mock_conn):
        """CA2: dataset_nombre presente."""
        log_failed_access(
            dataset_nombre="admissions.csv",
            exc=PermissionError("admissions.csv"),
            usuario_id="medico01",
            sesion_id="sesion-001",
        )
        events = _get_failed_events(mock_conn)
        assert events[-1]["dataset_nombre"] == "admissions.csv"

    def test_evento_contiene_motivo_fallo(self, mock_conn):
        """CA2: motivo_fallo presente."""
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=PermissionError("datos.csv"),
            usuario_id="medico01",
            sesion_id="sesion-001",
        )
        events = _get_failed_events(mock_conn)
        assert events[-1]["motivo_fallo"] is not None

    def test_evento_contiene_sesion_id(self, mock_conn):
        """CA2 / DoD: sesion_id presente cuando está disponible."""
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=FileNotFoundError("datos.csv"),
            usuario_id="medico01",
            sesion_id="sesion-TEST-42",
        )
        events = _get_failed_events(mock_conn)
        assert events[-1]["sesion_id"] == "sesion-TEST-42"

    def test_usuario_desconocido_cuando_no_identificable(self, mock_conn, monkeypatch):
        """CA2: cuando no hay sesión activa, usuario_id = 'DESCONOCIDO'."""
        monkeypatch.setattr(
            "audit_tracer.failed_access._get_session",
            lambda: ("DESCONOCIDO", "SIN_SESION"),
        )
        log_failed_access(
            dataset_nombre="secreto.csv",
            exc=PermissionError("secreto.csv"),
        )
        events = _get_failed_events(mock_conn)
        assert events[-1]["usuario_id"] == "DESCONOCIDO"

    def test_evento_tiene_hash_integridad(self, mock_conn):
        """El registro de ACCESO_FALLIDO también debe tener hash SHA-256."""
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=FileNotFoundError("datos.csv"),
            usuario_id="medico01",
            sesion_id="sesion-001",
        )
        events = _get_failed_events(mock_conn)
        h = events[-1]["hash_integridad"]
        assert h is not None
        assert len(h) == 64   # SHA-256 hexdigest


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-66: Detección de intentos repetidos (CA3)
# ──────────────────────────────────────────────────────────────

class TestDeteccionIntentosRepetidos:
    """CA3 — Más de 3 intentos del mismo usuario en <5 min → nivel_alerta = CRITICO."""

    def test_primer_intento_nivel_normal(self, mock_conn):
        """CA3: el primer intento fallido tiene nivel_alerta = NORMAL."""
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=FileNotFoundError("datos.csv"),
            usuario_id="sospechoso01",
            sesion_id="sesion-s",
        )
        events = _get_failed_events(mock_conn)
        assert events[-1]["nivel_alerta"] == "NORMAL"

    def test_tres_intentos_nivel_normal(self, mock_conn):
        """CA3: exactamente 3 intentos aún no disparan CRITICO."""
        for _ in range(3):
            log_failed_access(
                dataset_nombre="datos.csv",
                exc=PermissionError("datos.csv"),
                usuario_id="sospechoso02",
                sesion_id="sesion-s",
            )
        events = [
            e for e in _get_failed_events(mock_conn)
            if e["usuario_id"] == "sospechoso02"
        ]
        # El tercer intento debe ser el último registrado y ser aún NORMAL
        assert events[-1]["nivel_alerta"] == "NORMAL"

    def test_cuatro_intentos_genera_critico(self, mock_conn):
        """CA3: 4 intentos del mismo usuario en la ventana → último es CRITICO."""
        for _ in range(4):
            log_failed_access(
                dataset_nombre="datos.csv",
                exc=PermissionError("datos.csv"),
                usuario_id="sospechoso03",
                sesion_id="sesion-s",
            )
        events = [
            e for e in _get_failed_events(mock_conn)
            if e["usuario_id"] == "sospechoso03"
        ]
        assert events[-1]["nivel_alerta"] == "CRITICO"

    def test_critico_incluye_motivo_alerta(self, mock_conn):
        """CA3: el evento CRITICO debe incluir motivo_alerta descriptivo."""
        for _ in range(4):
            log_failed_access(
                dataset_nombre="datos.csv",
                exc=PermissionError("datos.csv"),
                usuario_id="sospechoso04",
                sesion_id="sesion-s",
            )
        events = [
            e for e in _get_failed_events(mock_conn)
            if e["usuario_id"] == "sospechoso04" and e["nivel_alerta"] == "CRITICO"
        ]
        assert len(events) >= 1
        assert events[-1]["motivo_alerta"] is not None
        assert "intentos" in events[-1]["motivo_alerta"]

    def test_intentos_fuera_de_ventana_no_generan_critico(self, monkeypatch, mock_conn):
        """CA3: intentos anteriores a la ventana de 5 min no cuentan."""
        usuario = "sospechoso05"
        # Insertar 3 intentos "viejos" (fuera de la ventana)
        tiempo_viejo = datetime.utcnow() - timedelta(minutes=_ALERT_WINDOW_MINUTES + 1)
        _failed_attempts[usuario] = [tiempo_viejo] * 3

        # Un cuarto intento ahora (dentro de la ventana)
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=PermissionError("datos.csv"),
            usuario_id=usuario,
            sesion_id="sesion-s",
        )

        events = [
            e for e in _get_failed_events(mock_conn)
            if e["usuario_id"] == usuario
        ]
        # Los 3 viejos no están en BD (fueron solo en memoria), el nuevo debe ser NORMAL
        assert events[-1]["nivel_alerta"] == "NORMAL"

    def test_usuarios_distintos_no_comparten_contador(self, mock_conn):
        """CA3: el conteo de intentos es por usuario, no global."""
        # Usuario A: 4 intentos
        for _ in range(4):
            log_failed_access(
                dataset_nombre="datos.csv",
                exc=PermissionError("datos.csv"),
                usuario_id="usuarioA",
                sesion_id="sesion-a",
            )
        # Usuario B: solo 1 intento
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=PermissionError("datos.csv"),
            usuario_id="usuarioB",
            sesion_id="sesion-b",
        )

        events_b = [
            e for e in _get_failed_events(mock_conn)
            if e["usuario_id"] == "usuarioB"
        ]
        assert events_b[-1]["nivel_alerta"] == "NORMAL"

    def test_reset_reinicia_contador(self, mock_conn):
        """reset_attempts() debe borrar el historial de intentos."""
        for _ in range(4):
            log_failed_access(
                dataset_nombre="datos.csv",
                exc=PermissionError("datos.csv"),
                usuario_id="sospechoso06",
                sesion_id="sesion-s",
            )
        reset_attempts("sospechoso06")

        # Siguiente intento debe volver a NORMAL
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=PermissionError("datos.csv"),
            usuario_id="sospechoso06",
            sesion_id="sesion-s",
        )
        events = [
            e for e in _get_failed_events(mock_conn)
            if e["usuario_id"] == "sospechoso06"
        ]
        assert events[-1]["nivel_alerta"] == "NORMAL"


# ──────────────────────────────────────────────────────────────
# CA4 — Consultable en reportes con filtro tipo_accion = ACCESO_FALLIDO
# ──────────────────────────────────────────────────────────────

class TestConsultabilidadReportes:
    """CA4 — Los eventos ACCESO_FALLIDO son filtrables en audit_log."""

    def test_filtro_tipo_accion_devuelve_solo_fallidos(self, mock_conn):
        """CA4: get_events(tipo_accion='ACCESO_FALLIDO') filtra correctamente."""
        # Registrar un fallo
        log_failed_access(
            dataset_nombre="historial.csv",
            exc=FileNotFoundError("historial.csv"),
            usuario_id="auditor01",
            sesion_id="sesion-audit",
        )
        events = _get_failed_events(mock_conn)
        tipos = {e["tipo_accion"] for e in events}
        assert tipos == {"ACCESO_FALLIDO"}

    def test_eventos_fallidos_no_mezclan_con_cargas(self, mock_conn, tmp_path):
        """CA4: los ACCESO_FALLIDO son separables de los eventos CARGA."""
        # Crear un CSV válido y cargarlo (genera evento CARGA)
        csv_path = str(tmp_path / "valido.csv")
        pd.DataFrame({"col": [1, 2]}).to_csv(csv_path, index=False)
        pd.read_csv(csv_path)

        # Registrar un fallo manual
        log_failed_access(
            dataset_nombre="inexistente.csv",
            exc=FileNotFoundError("inexistente.csv"),
            usuario_id="auditor01",
            sesion_id="sesion-audit",
        )

        all_ev = _all_events(mock_conn)
        cargas = [e for e in all_ev if e["tipo_accion"] == "CARGA"]
        fallidos = [e for e in all_ev if e["tipo_accion"] == "ACCESO_FALLIDO"]

        assert len(cargas) >= 1
        assert len(fallidos) >= 1

    def test_filtro_por_usuario_funciona_en_fallidos(self, mock_conn):
        """CA4: se pueden filtrar ACCESO_FALLIDO por usuario_id."""
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=PermissionError("datos.csv"),
            usuario_id="usuarioX",
            sesion_id="sesion-x",
        )
        log_failed_access(
            dataset_nombre="datos.csv",
            exc=PermissionError("datos.csv"),
            usuario_id="usuarioY",
            sesion_id="sesion-y",
        )

        conn = mock_conn()
        events = get_events(conn, usuario_id="usuarioX", tipo_accion="ACCESO_FALLIDO")
        conn.close()

        assert len(events) == 1
        assert events[0]["usuario_id"] == "usuarioX"


# ──────────────────────────────────────────────────────────────
# Decorador @intercept_access_failures (PDGTRAZDSA-63)
# ──────────────────────────────────────────────────────────────

class TestDecoradorInterceptAccess:
    """Valida el decorador @intercept_access_failures como mecanismo alternativo."""

    def test_decorador_registra_fallo_y_relanza(self, mock_conn):
        """El decorador registra el evento y re-lanza la excepción."""
        @intercept_access_failures(dataset_nombre="clinicos.csv")
        def fn_que_falla():
            raise FileNotFoundError("clinicos.csv")

        with pytest.raises(FileNotFoundError):
            fn_que_falla()

        events = _get_failed_events(mock_conn)
        assert len(events) >= 1
        assert events[-1]["tipo_accion"] == "ACCESO_FALLIDO"

    def test_decorador_extrae_nombre_de_argumento(self, mock_conn):
        """El decorador puede resolver dataset_nombre desde un argumento de la función."""
        @intercept_access_failures(dataset_arg="ruta")
        def cargar(ruta: str):
            raise PermissionError(ruta)

        with pytest.raises(PermissionError):
            cargar(ruta="/datos/ADMISSIONS.csv")

        events = _get_failed_events(mock_conn)
        assert any("ADMISSIONS.csv" in e["dataset_nombre"] for e in events)

    def test_decorador_no_captura_excepciones_no_acceso(self, mock_conn):
        """El decorador no registra ValueError u otras excepciones no relacionadas."""
        @intercept_access_failures(dataset_nombre="datos.csv")
        def fn_valor_error():
            raise ValueError("error lógico")

        with pytest.raises(ValueError):
            fn_valor_error()

        events = _get_failed_events(mock_conn)
        assert len(events) == 0
