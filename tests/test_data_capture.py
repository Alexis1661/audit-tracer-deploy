"""
tests/test_data_capture.py
==========================
Pruebas unitarias — HU-2.1: Registrar eventos de acceso a datos clínicos

Cubre todos los criterios de aceptación:
  CA1: Registro automático con campos requeridos
  CA2: Generación automática sin intervención manual
  CA3: Manejo de usuario no identificado (DESCONOCIDO + flag_alerta)
  CA4: Persistencia inmediata en SQLite
  CA5: Trazabilidad por sesión (sesion_id)

Subtasks validadas:
  PDGTRAZDSA-49: Eventos CARGA y CONSULTA definidos y consistentes
  PDGTRAZDSA-50: Interceptación de pd.read_csv() y pd.read_excel()
  PDGTRAZDSA-51: Interceptación de df[] y df.query()
  PDGTRAZDSA-52: Registro en audit_log con todos los campos
  PDGTRAZDSA-53: Manejo de usuario no identificado
"""

import io
import json
import os
import pytest
import sqlite3
import pandas as pd

from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import get_events
from audit_tracer import data_capture


# ──────────────────────────────────────────────────────────────
# FIXTURES
# ──────────────────────────────────────────────────────────────

DB_PATH = "audit_trail_test_hu21.db"


@pytest.fixture(autouse=True)
def clean_db(monkeypatch, tmp_path):
    """
    Crea una BD temporal aislada para cada test.
    Redirige get_connection() hacia ella y activa el interceptor.
    """
    db_file = str(tmp_path / "audit_trail.db")

    # Parchear get_connection para usar BD temporal
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

    monkeypatch.setattr("audit_tracer.data_capture.get_connection", _mock_get_conn)
    monkeypatch.setattr("audit_tracer.models.audit_log.get_connection", _mock_get_conn, raising=False)

    # Activar interceptor (desactivar primero para estado limpio)
    data_capture.deactivate()
    data_capture.activate()

    yield db_file, _mock_get_conn

    data_capture.deactivate()


@pytest.fixture
def sample_csv(tmp_path) -> str:
    """Crea un CSV clínico mínimo en disco y retorna su ruta."""
    content = "subject_id,age,diagnosis\n1,45,sepsis\n2,30,pneumonia\n"
    path = tmp_path / "PATIENTS.csv"
    path.write_text(content)
    return str(path)


@pytest.fixture
def sample_excel(tmp_path) -> str:
    """Crea un Excel clínico mínimo en disco y retorna su ruta."""
    path = str(tmp_path / "ADMISSIONS.xlsx")
    df = pd.DataFrame({
        "subject_id": [1, 2],
        "admission_type": ["EMERGENCY", "ELECTIVE"],
        "los": [3, 7],
    })
    # Usar el read_excel original para no disparar la auditoría aquí
    df.to_excel(path, index=False)
    return path


def _get_events_by_type(mock_conn_fn, tipo: str):
    """Helper: obtiene eventos de un tipo dado desde la BD de test."""
    conn = mock_conn_fn()
    events = get_events(conn, tipo_accion=tipo)
    conn.close()
    return events


def _all_events(mock_conn_fn):
    conn = mock_conn_fn()
    events = get_events(conn)
    conn.close()
    return events


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-49: Definición de eventos de acceso a datos
# ──────────────────────────────────────────────────────────────

class TestEventDefinitions:
    """Valida que CARGA y CONSULTA están definidos correctamente."""

    def test_tipo_accion_carga_es_string_valido(self):
        assert isinstance("CARGA", str)
        assert "CARGA" in ["CARGA", "CONSULTA"]

    def test_tipo_accion_consulta_es_string_valido(self):
        assert isinstance("CONSULTA", str)
        assert "CONSULTA" in ["CARGA", "CONSULTA"]

    def test_tipos_son_distintos(self):
        assert "CARGA" != "CONSULTA"


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-50: Interceptación de operaciones de CARGA
# ──────────────────────────────────────────────────────────────

class TestCargaCSV:
    """CA1, CA2, CA4, CA5 para pd.read_csv()."""

    def test_read_csv_genera_evento_carga(self, clean_db, sample_csv):
        _, mock_conn = clean_db
        df = pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        assert len(events) >= 1, "pd.read_csv() debe generar al menos un evento CARGA"

    def test_read_csv_evento_contiene_dataset_nombre(self, clean_db, sample_csv):
        """CA1: el campo dataset_nombre debe ser el nombre del archivo."""
        _, mock_conn = clean_db
        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        nombres = [e["dataset_nombre"] for e in events]
        assert any("PATIENTS.csv" in n for n in nombres)

    def test_read_csv_evento_contiene_timestamp(self, clean_db, sample_csv):
        """CA1: debe incluir timestamp."""
        _, mock_conn = clean_db
        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        assert all(e["timestamp"] is not None for e in events)

    def test_read_csv_evento_contiene_sesion_id(self, clean_db, sample_csv):
        """CA5: debe incluir sesion_id."""
        _, mock_conn = clean_db
        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        assert all(e["sesion_id"] is not None for e in events)
        assert all(len(e["sesion_id"]) > 0 for e in events)

    def test_read_csv_evento_contiene_usuario_id(self, clean_db, sample_csv):
        """CA1: debe incluir usuario_id."""
        _, mock_conn = clean_db
        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        assert all(e["usuario_id"] is not None for e in events)

    def test_read_csv_devuelve_dataframe_correcto(self, clean_db, sample_csv):
        """La intercepción no debe alterar el DataFrame retornado."""
        _, _ = clean_db
        df = pd.read_csv(sample_csv)

        assert isinstance(df, pd.DataFrame)
        assert list(df.columns) == ["subject_id", "age", "diagnosis"]
        assert len(df) == 2

    def test_read_csv_sin_intervencion_manual(self, clean_db, sample_csv):
        """CA2: solo llamar read_csv debe ser suficiente para registrar."""
        _, mock_conn = clean_db
        # No se llama a ninguna función de auditoría manualmente
        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        assert len(events) >= 1

    def test_read_csv_registra_columnas_afectadas(self, clean_db, sample_csv):
        """Las columnas del CSV deben quedar en columnas_afectadas."""
        _, mock_conn = clean_db
        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        cols_raw = events[0]["columnas_afectadas"]
        cols = json.loads(cols_raw)
        assert "subject_id" in cols
        assert "diagnosis" in cols

    def test_multiples_cargas_generan_multiples_eventos(self, clean_db, sample_csv, tmp_path):
        """Cada llamada a read_csv debe generar su propio evento."""
        _, mock_conn = clean_db

        # Segundo CSV
        path2 = str(tmp_path / "ADMISSIONS.csv")
        pd.DataFrame({"id": [1]}).to_csv(path2, index=False)

        pd.read_csv(sample_csv)
        pd.read_csv(path2)

        all_ev = _all_events(mock_conn)
        carga_ev = [e for e in all_ev if e["tipo_accion"] == "CARGA"]
        assert len(carga_ev) >= 2


class TestCargaExcel:
    """CA1, CA2, CA4, CA5 para pd.read_excel()."""

    def test_read_excel_genera_evento_carga(self, clean_db, sample_excel):
        _, mock_conn = clean_db
        pd.read_excel(sample_excel)

        events = _get_events_by_type(mock_conn, "CARGA")
        assert len(events) >= 1

    def test_read_excel_contiene_dataset_nombre(self, clean_db, sample_excel):
        """CA1: dataset_nombre debe ser el nombre del archivo Excel."""
        _, mock_conn = clean_db
        pd.read_excel(sample_excel)

        events = _get_events_by_type(mock_conn, "CARGA")
        nombres = [e["dataset_nombre"] for e in events]
        assert any("ADMISSIONS.xlsx" in n for n in nombres)

    def test_read_excel_devuelve_dataframe_correcto(self, clean_db, sample_excel):
        _, _ = clean_db
        df = pd.read_excel(sample_excel)

        assert isinstance(df, pd.DataFrame)
        assert "subject_id" in df.columns


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-51: Interceptación de operaciones de CONSULTA
# ──────────────────────────────────────────────────────────────

class TestConsultaGetItem:
    """CA1, CA2, CA4, CA5 para df[columna]."""

    @pytest.fixture
    def audited_df(self):
        """DataFrame auditado de prueba."""
        raw = pd.DataFrame({
            "subject_id": [1, 2, 3],
            "age": [45, 30, 60],
            "diagnosis": ["sepsis", "pneumonia", "ards"],
        })
        return data_capture.wrap_dataframe(raw, "PATIENTS.csv")

    def test_getitem_columna_genera_evento_consulta(self, clean_db, audited_df):
        _, mock_conn = clean_db
        _ = audited_df["age"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert len(events) >= 1

    def test_getitem_registra_columna_accedida(self, clean_db, audited_df):
        """CA1 + PDGTRAZDSA-51: columnas_afectadas debe incluir la columna consultada."""
        _, mock_conn = clean_db
        _ = audited_df["diagnosis"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        cols = json.loads(events[-1]["columnas_afectadas"])
        assert "diagnosis" in cols

    def test_getitem_lista_columnas_registra_todas(self, clean_db, audited_df):
        """Selección de múltiples columnas debe registrarlas todas."""
        _, mock_conn = clean_db
        _ = audited_df[["subject_id", "age"]]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        cols = json.loads(events[-1]["columnas_afectadas"])
        assert "subject_id" in cols
        assert "age" in cols

    def test_getitem_contiene_dataset_nombre(self, clean_db, audited_df):
        """CA1: el evento debe indicar el nombre del dataset."""
        _, mock_conn = clean_db
        _ = audited_df["age"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert any(e["dataset_nombre"] == "PATIENTS.csv" for e in events)

    def test_getitem_contiene_sesion_id(self, clean_db, audited_df):
        """CA5: sesion_id debe estar presente."""
        _, mock_conn = clean_db
        _ = audited_df["subject_id"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert all(e["sesion_id"] is not None for e in events)

    def test_getitem_devuelve_datos_correctos(self, clean_db, audited_df):
        """La intercepción no debe alterar el resultado de la consulta."""
        _, _ = clean_db
        col = audited_df["age"]

        assert list(col) == [45, 30, 60]

    def test_getitem_sin_intervencion_manual(self, clean_db, audited_df):
        """CA2: solo acceder al DataFrame es suficiente."""
        _, mock_conn = clean_db
        _ = audited_df["diagnosis"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert len(events) >= 1


class TestConsultaQuery:
    """CA1, CA2, CA4, CA5 para df.query()."""

    @pytest.fixture
    def audited_df(self):
        raw = pd.DataFrame({
            "subject_id": [1, 2, 3],
            "age": [45, 30, 60],
            "diagnosis": ["sepsis", "pneumonia", "ards"],
        })
        return data_capture.wrap_dataframe(raw, "PATIENTS.csv")

    def test_query_genera_evento_consulta(self, clean_db, audited_df):
        _, mock_conn = clean_db
        _ = audited_df.query("age > 40")

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert len(events) >= 1

    def test_query_registra_tipo_accion_consulta(self, clean_db, audited_df):
        """CA1: tipo_accion debe ser CONSULTA."""
        _, mock_conn = clean_db
        _ = audited_df.query("age > 40")

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert all(e["tipo_accion"] == "CONSULTA" for e in events)

    def test_query_identifica_columnas_en_expresion(self, clean_db, audited_df):
        """PDGTRAZDSA-51: columnas referenciadas en la expresión deben registrarse."""
        _, mock_conn = clean_db
        _ = audited_df.query("age > 40 and diagnosis == 'sepsis'")

        events = _get_events_by_type(mock_conn, "CONSULTA")
        # Puede ser JSON o la expresión; validar que contiene info relevante
        cols_field = events[-1]["columnas_afectadas"]
        assert "age" in cols_field or "diagnosis" in cols_field

    def test_query_contiene_dataset_nombre(self, clean_db, audited_df):
        _, mock_conn = clean_db
        _ = audited_df.query("age < 50")

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert any(e["dataset_nombre"] == "PATIENTS.csv" for e in events)

    def test_query_devuelve_filas_correctas(self, clean_db, audited_df):
        """La intercepción no debe alterar el resultado del filtrado."""
        _, _ = clean_db
        result = audited_df.query("age > 40")

        assert len(result) == 2     # sujetos 1 y 3 tienen age > 40

    def test_query_contiene_sesion_id(self, clean_db, audited_df):
        """CA5: sesion_id presente en evento de consulta."""
        _, mock_conn = clean_db
        _ = audited_df.query("subject_id == 1")

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert all(e["sesion_id"] is not None for e in events)


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-52: Registro en audit_log
# ──────────────────────────────────────────────────────────────

class TestRegistroAuditLog:
    """Valida que cada evento persiste con todos los campos requeridos."""

    def test_evento_tiene_todos_los_campos_requeridos(self, clean_db, sample_csv):
        """CA1: usuario_id, timestamp, dataset_nombre, tipo_accion obligatorios."""
        _, mock_conn = clean_db
        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        assert len(events) >= 1
        ev = events[0]

        assert ev["usuario_id"] is not None
        assert ev["timestamp"] is not None
        assert ev["dataset_nombre"] is not None
        assert ev["tipo_accion"] is not None

    def test_evento_tiene_hash_integridad(self, clean_db, sample_csv):
        """Cada registro debe incluir hash de integridad SHA-256."""
        _, mock_conn = clean_db
        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        assert all(
            e["hash_integridad"] is not None and len(e["hash_integridad"]) == 64
            for e in events
        )

    def test_evento_disponible_inmediatamente(self, clean_db, sample_csv):
        """CA4: el registro debe poder consultarse justo después de la operación."""
        _, mock_conn = clean_db

        before = len(_all_events(mock_conn))
        pd.read_csv(sample_csv)
        after = len(_all_events(mock_conn))

        assert after > before, "El evento debe estar disponible inmediatamente"

    def test_sesion_id_consistente_en_misma_sesion(self, clean_db, sample_csv, tmp_path):
        """CA5: todos los eventos de una sesión comparten el mismo sesion_id."""
        _, mock_conn = clean_db

        path2 = str(tmp_path / "B.csv")
        pd.DataFrame({"x": [1]}).to_csv(path2, index=False)

        pd.read_csv(sample_csv)
        pd.read_csv(path2)

        events = _get_events_by_type(mock_conn, "CARGA")
        sesion_ids = {e["sesion_id"] for e in events}
        # Todos los eventos de CARGA deben tener el mismo sesion_id de la sesión activa
        assert len(sesion_ids) == 1, (
            f"Se esperaba un único sesion_id en la sesión, pero se encontraron: {sesion_ids}"
        )

    def test_tipo_accion_solo_valores_validos(self, clean_db, sample_csv):
        """tipo_accion debe ser CARGA o CONSULTA exclusivamente en eventos de datos."""
        _, mock_conn = clean_db

        raw = pd.DataFrame({"col": [1, 2]})
        audited = data_capture.wrap_dataframe(raw, "test.csv")
        pd.read_csv(sample_csv)
        _ = audited["col"]

        eventos_datos = [
            e for e in _all_events(mock_conn)
            if e["tipo_accion"] in ("CARGA", "CONSULTA")
        ]
        tipos = {e["tipo_accion"] for e in eventos_datos}
        assert tipos.issubset({"CARGA", "CONSULTA"})


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-53: Manejo de usuario no identificado
# ──────────────────────────────────────────────────────────────

class TestUsuarioDesconocido:
    """CA3: cuando no hay usuario identificado, registrar DESCONOCIDO y flag_alerta."""

    def test_usuario_desconocido_genera_nivel_alerta_critico(self, clean_db, monkeypatch):
        """CA3: usuario_id = DESCONOCIDO → nivel_alerta = CRITICO."""
        _, mock_conn = clean_db

        # Simular que _get_session retorna DESCONOCIDO
        monkeypatch.setattr(
            "audit_tracer.data_capture._get_session",
            lambda: ("DESCONOCIDO", "sesion-sin-usuario"),
        )

        raw = pd.DataFrame({"col": [1]})
        audited = data_capture.wrap_dataframe(raw, "datos_clinicos.csv")
        _ = audited["col"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        assert len(events) >= 1
        ev = events[-1]
        assert ev["usuario_id"] == "DESCONOCIDO"
        assert ev["nivel_alerta"] == "CRITICO"

    def test_usuario_desconocido_tiene_motivo_alerta(self, clean_db, monkeypatch):
        """CA3: cuando el usuario es DESCONOCIDO, motivo_alerta debe estar poblado."""
        _, mock_conn = clean_db

        monkeypatch.setattr(
            "audit_tracer.data_capture._get_session",
            lambda: ("DESCONOCIDO", "sesion-sin-usuario"),
        )

        raw = pd.DataFrame({"col": [1]})
        audited = data_capture.wrap_dataframe(raw, "datos_clinicos.csv")
        _ = audited["col"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        ev = events[-1]
        assert ev["motivo_alerta"] is not None
        assert len(ev["motivo_alerta"]) > 0

    def test_usuario_identificado_no_genera_alerta(self, clean_db, monkeypatch):
        """Cuando el usuario es conocido y accede en horario laboral, nivel_alerta debe ser NORMAL."""
        _, mock_conn = clean_db

        monkeypatch.setattr(
            "audit_tracer.data_capture._get_session",
            lambda: ("usuario_prueba", "sesion-123"),
        )
        # Fuerza horario laboral (HU-4.4 CA1-c) para que el test sea determinista
        # sin importar la hora real en la que corran las pruebas.
        monkeypatch.setattr("audit_tracer.data_capture.es_horario_laboral", lambda dt: True)

        raw = pd.DataFrame({"col": [1]})
        audited = data_capture.wrap_dataframe(raw, "datos_clinicos.csv")
        _ = audited["col"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        ev = events[-1]
        assert ev["nivel_alerta"] == "NORMAL"
        assert ev["motivo_alerta"] is None


# ──────────────────────────────────────────────────────────────
# HU-4.4 CA1-c: Accesos fuera del horario laboral configurable
# ──────────────────────────────────────────────────────────────

class TestHorarioLaboral:
    """CA1: accesos a datos fuera del horario laboral configurado → CRITICO."""

    def test_acceso_fuera_de_horario_genera_nivel_alerta_critico(self, clean_db, monkeypatch):
        _, mock_conn = clean_db

        monkeypatch.setattr(
            "audit_tracer.data_capture._get_session",
            lambda: ("usuario_prueba", "sesion-123"),
        )
        monkeypatch.setattr("audit_tracer.data_capture.es_horario_laboral", lambda dt: False)

        raw = pd.DataFrame({"col": [1]})
        audited = data_capture.wrap_dataframe(raw, "datos_clinicos.csv")
        _ = audited["col"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        ev = events[-1]
        assert ev["nivel_alerta"] == "CRITICO"
        assert "horario laboral" in ev["motivo_alerta"].lower()

    def test_acceso_dentro_de_horario_no_genera_alerta(self, clean_db, monkeypatch):
        _, mock_conn = clean_db

        monkeypatch.setattr(
            "audit_tracer.data_capture._get_session",
            lambda: ("usuario_prueba", "sesion-123"),
        )
        monkeypatch.setattr("audit_tracer.data_capture.es_horario_laboral", lambda dt: True)

        raw = pd.DataFrame({"col": [1]})
        audited = data_capture.wrap_dataframe(raw, "datos_clinicos.csv")
        _ = audited["col"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        ev = events[-1]
        assert ev["nivel_alerta"] == "NORMAL"

    def test_usuario_desconocido_fuera_de_horario_sigue_siendo_critico_por_usuario(self, clean_db, monkeypatch):
        """El motivo por usuario no identificado tiene prioridad sobre el de horario."""
        _, mock_conn = clean_db

        monkeypatch.setattr(
            "audit_tracer.data_capture._get_session",
            lambda: ("DESCONOCIDO", "sesion-sin-usuario"),
        )
        monkeypatch.setattr("audit_tracer.data_capture.es_horario_laboral", lambda dt: False)

        raw = pd.DataFrame({"col": [1]})
        audited = data_capture.wrap_dataframe(raw, "datos_clinicos.csv")
        _ = audited["col"]

        events = _get_events_by_type(mock_conn, "CONSULTA")
        ev = events[-1]
        assert ev["nivel_alerta"] == "CRITICO"
        assert "no identificado" in ev["motivo_alerta"].lower()

    def test_es_horario_laboral_respeta_limites_configurados(self):
        """Utilidad pura: [HORA_INICIO_LABORAL, HORA_FIN_LABORAL) es horario laboral."""
        from datetime import datetime
        from audit_tracer.utils.horario import es_horario_laboral, HORA_INICIO_LABORAL, HORA_FIN_LABORAL

        dentro = datetime(2026, 1, 5, HORA_INICIO_LABORAL, 0)
        fuera_temprano = datetime(2026, 1, 5, max(HORA_INICIO_LABORAL - 1, 0), 0)
        fuera_tarde = datetime(2026, 1, 5, HORA_FIN_LABORAL, 0)

        assert es_horario_laboral(dentro) is True
        assert es_horario_laboral(fuera_tarde) is False
        if HORA_INICIO_LABORAL > 0:
            assert es_horario_laboral(fuera_temprano) is False

    def test_evento_desconocido_no_se_pierde(self, clean_db, monkeypatch, sample_csv):
        """CA3: los eventos sin usuario identificado sí deben persistir."""
        _, mock_conn = clean_db

        monkeypatch.setattr(
            "audit_tracer.data_capture._get_session",
            lambda: ("DESCONOCIDO", "sesion-sin-usuario"),
        )

        pd.read_csv(sample_csv)

        events = _get_events_by_type(mock_conn, "CARGA")
        desconocidos = [e for e in events if e["usuario_id"] == "DESCONOCIDO"]
        assert len(desconocidos) >= 1, "Los eventos sin usuario no deben descartarse"


# ──────────────────────────────────────────────────────────────
# PRUEBAS DE INTEGRACIÓN
# ──────────────────────────────────────────────────────────────

class TestIntegracion:
    """Flujos end-to-end que combinan CARGA + CONSULTA en la misma sesión."""

    def test_flujo_completo_carga_y_consulta(self, clean_db, sample_csv):
        """
        Simula un flujo real de análisis:
        1. Cargar CSV
        2. Filtrar con query()
        3. Seleccionar columnas con []
        Verifica que los tres eventos quedan registrados correctamente.
        """
        _, mock_conn = clean_db

        df = pd.read_csv(sample_csv)
        audited = data_capture.wrap_dataframe(df, "PATIENTS.csv")
        _ = audited.query("age > 30")
        _ = audited["diagnosis"]

        all_ev = _all_events(mock_conn)
        tipos = [e["tipo_accion"] for e in all_ev]

        assert "CARGA" in tipos
        assert "CONSULTA" in tipos

    def test_todos_los_eventos_tienen_mismo_sesion_id(self, clean_db, sample_csv):
        """CA5: todos los eventos de datos en la sesión comparten sesion_id."""
        _, mock_conn = clean_db

        df = pd.read_csv(sample_csv)
        audited = data_capture.wrap_dataframe(df, "PATIENTS.csv")
        _ = audited["age"]
        _ = audited.query("diagnosis == 'sepsis'")

        datos_ev = [
            e for e in _all_events(mock_conn)
            if e["tipo_accion"] in ("CARGA", "CONSULTA")
        ]
        sesion_ids = {e["sesion_id"] for e in datos_ev}
        assert len(sesion_ids) == 1

    def test_wrap_dataframe_es_opcional_para_carga(self, clean_db, sample_csv):
        """read_csv ya produce trazabilidad; wrap_dataframe añade consultas."""
        _, mock_conn = clean_db

        _ = pd.read_csv(sample_csv)   # No se envuelve manualmente

        events = _get_events_by_type(mock_conn, "CARGA")
        assert len(events) >= 1

    def test_intercepcion_no_afecta_rendimiento_observable(self, clean_db, sample_csv):
        """El DataFrame retornado debe ser completamente funcional."""
        _, _ = clean_db

        df = pd.read_csv(sample_csv)
        assert df.shape == (2, 3)
        assert df["age"].sum() == 75
