"""
tests/test_export_capture.py
=============================
Pruebas unitarias — HU-2.3: Registrar eventos de exportación de datos

Cubre todos los criterios de aceptación:
  CA1: Intercepción de to_csv(), to_excel(), to_json(), to_parquet()
       con tipo_accion = EXPORTACION
  CA2: Registro incluye usuario_id, timestamp, dataset_nombre,
       ruta_destino y filas_exportadas
  CA3: Indicador de sobrescritura cuando el archivo destino ya existía
  CA4: Registro de exportaciones por métodos alternativos (audited_open)

Subtareas validadas:
  PDGTRAZDSA-54: Definición de operaciones de exportación
  PDGTRAZDSA-55: Interceptación de operaciones de exportación
  PDGTRAZDSA-56: Captura de información del archivo exportado
  PDGTRAZDSA-57: Registro en audit_log
"""

import json
import os
import sqlite3

import pandas as pd
import pytest

from audit_tracer.models.audit_log import get_events
from audit_tracer import export_capture
from audit_tracer.export_capture import (
    wrap_for_export,
    audited_open,
    UMBRAL_EXPORTACION_MASIVA,
)


# ──────────────────────────────────────────────────────────────
# FIXTURES
# ──────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_db(monkeypatch, tmp_path):
    """
    BD temporal aislada por test.
    Activa/desactiva el interceptor de exportación alrededor de cada test.
    """
    db_file = str(tmp_path / "audit_trail.db")
    schema_dir = "schema"

    def _mock_get_conn():
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

    monkeypatch.setattr("audit_tracer.export_capture.get_connection", _mock_get_conn)
    monkeypatch.setattr("audit_tracer.models.audit_log.get_connection", _mock_get_conn, raising=False)

    export_capture.deactivate()
    export_capture.activate()

    yield db_file, _mock_get_conn

    export_capture.deactivate()


@pytest.fixture
def patients_df() -> pd.DataFrame:
    """DataFrame clínico de prueba (PATIENTS-like)."""
    return pd.DataFrame({
        "subject_id": [1, 2, 3],
        "age": [45, 60, 30],
        "diagnosis": ["sepsis", "pneumonia", "ards"],
    })


@pytest.fixture
def audited(patients_df):
    """DataFrame etiquetado listo para exportar con auditoría."""
    return wrap_for_export(patients_df, "PATIENTS.csv")


def _get_export_events(mock_conn_fn):
    conn = mock_conn_fn()
    events = get_events(conn, tipo_accion="EXPORTACION")
    conn.close()
    return events


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-54/55: Interceptación de exportaciones — CSV
# ──────────────────────────────────────────────────────────────

class TestExportCSV:
    """CA1, CA2 para to_csv()."""

    def test_to_csv_genera_evento_exportacion(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert len(events) == 1
        assert events[0]["tipo_accion"] == "EXPORTACION"

    def test_to_csv_registra_dataset_nombre(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["dataset_nombre"] == "PATIENTS.csv"

    def test_to_csv_registra_ruta_destino(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["ruta_destino"] == destino

    def test_to_csv_registra_filas_exportadas(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["filas_exportadas"] == 3

    def test_to_csv_registra_usuario_y_sesion(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["usuario_id"] is not None
        assert events[0]["sesion_id"] is not None

    def test_to_csv_registra_timestamp(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["timestamp"] is not None

    def test_to_csv_sin_intervencion_manual(self, clean_db, audited, tmp_path):
        """CA1: la auditoría ocurre sin llamar explícitamente a ninguna función extra."""
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        result = audited.to_csv(destino, index=False)

        assert result is None  # comportamiento normal de to_csv con path
        assert len(_get_export_events(mock_conn)) == 1

    def test_to_csv_archivo_nuevo_no_marca_sobrescritura(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "nuevo.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["sobrescritura"] == 0

    def test_multiples_exportaciones_generan_multiples_eventos(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db

        audited.to_csv(str(tmp_path / "a.csv"), index=False)
        audited.to_csv(str(tmp_path / "b.csv"), index=False)

        assert len(_get_export_events(mock_conn)) == 2


# ──────────────────────────────────────────────────────────────
# CA3: Sobrescritura de archivos
# ──────────────────────────────────────────────────────────────

class TestSobrescritura:
    """CA3: indicador de sobrescritura cuando el destino ya existe."""

    def test_sobrescribir_archivo_existente_marca_flag(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "existente.csv")

        # Primera escritura: no existe aún
        audited.to_csv(destino, index=False)
        # Segunda escritura: el archivo ya existe → sobrescritura
        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["sobrescritura"] == 0
        assert events[1]["sobrescritura"] == 1

    def test_archivo_creado_por_fuera_de_pandas_marca_sobrescritura(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = tmp_path / "preexistente.csv"
        destino.write_text("col\n1\n")

        audited.to_csv(str(destino), index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["sobrescritura"] == 1


# ──────────────────────────────────────────────────────────────
# CA1/CA2: Excel, JSON y Parquet
# ──────────────────────────────────────────────────────────────

class TestExportExcel:
    def test_to_excel_genera_evento_exportacion(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.xlsx")

        audited.to_excel(destino, index=False)

        events = _get_export_events(mock_conn)
        assert len(events) == 1
        assert events[0]["tipo_accion"] == "EXPORTACION"
        assert events[0]["ruta_destino"] == destino
        assert events[0]["filas_exportadas"] == 3


class TestExportJSON:
    def test_to_json_genera_evento_exportacion(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.json")

        audited.to_json(destino)

        events = _get_export_events(mock_conn)
        assert len(events) == 1
        assert events[0]["tipo_accion"] == "EXPORTACION"
        assert events[0]["ruta_destino"] == destino
        assert events[0]["filas_exportadas"] == 3


class TestExportParquet:
    def test_to_parquet_genera_evento_exportacion(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.parquet")

        audited.to_parquet(destino, index=False)

        events = _get_export_events(mock_conn)
        assert len(events) == 1
        assert events[0]["tipo_accion"] == "EXPORTACION"
        assert events[0]["ruta_destino"] == destino
        assert events[0]["filas_exportadas"] == 3


# ──────────────────────────────────────────────────────────────
# CA4: Exportación mediante métodos alternativos (audited_open)
# ──────────────────────────────────────────────────────────────

class TestAuditedOpen:
    def test_audited_open_genera_evento_exportacion(self, clean_db, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "manual.csv")

        with audited_open(destino, "w", dataset_nombre="manual.csv") as f:
            f.write("col1,col2\n1,2\n3,4\n")

        events = _get_export_events(mock_conn)
        assert len(events) == 1
        assert events[0]["ruta_destino"] == destino
        assert events[0]["dataset_nombre"] == "manual.csv"

    def test_audited_open_cuenta_lineas_escritas(self, clean_db, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "manual.csv")

        with audited_open(destino, "w") as f:
            f.write("col1,col2\n")
            f.write("1,2\n")
            f.write("3,4\n")

        events = _get_export_events(mock_conn)
        assert events[0]["filas_exportadas"] == 3

    def test_audited_open_detecta_sobrescritura(self, clean_db, tmp_path):
        _, mock_conn = clean_db
        destino = tmp_path / "manual.csv"
        destino.write_text("preexistente\n")

        with audited_open(str(destino), "w") as f:
            f.write("nuevo\n")

        events = _get_export_events(mock_conn)
        assert events[0]["sobrescritura"] == 1

    def test_audited_open_modo_lectura_no_audita(self, clean_db, tmp_path):
        _, mock_conn = clean_db
        origen = tmp_path / "input.csv"
        origen.write_text("col\n1\n")

        with audited_open(str(origen), "r") as f:
            f.read()

        assert len(_get_export_events(mock_conn)) == 0

    def test_audited_open_escribe_contenido_real(self, clean_db, tmp_path):
        _, mock_conn = clean_db
        destino = tmp_path / "manual.csv"

        with audited_open(str(destino), "w") as f:
            f.write("hola\n")

        assert destino.read_text() == "hola\n"


# ──────────────────────────────────────────────────────────────
# Alertas: usuario desconocido y exportación masiva
# ──────────────────────────────────────────────────────────────

class TestAlertas:
    def test_usuario_desconocido_genera_nivel_alerta_critico(self, clean_db, audited, tmp_path, monkeypatch):
        _, mock_conn = clean_db
        monkeypatch.setattr(
            "audit_tracer.export_capture._get_session",
            lambda: ("DESCONOCIDO", "sesion-sin-usuario"),
        )
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["nivel_alerta"] == "CRITICO"
        assert events[0]["motivo_alerta"] is not None

    def test_exportacion_masiva_genera_nivel_alerta_critico(self, clean_db, tmp_path, monkeypatch):
        _, mock_conn = clean_db
        monkeypatch.setattr(
            "audit_tracer.export_capture._get_session",
            lambda: ("u1", "sesion-1"),
        )
        big_df = wrap_for_export(
            pd.DataFrame({"col": range(UMBRAL_EXPORTACION_MASIVA + 1)}),
            "big_dataset.csv",
        )
        destino = str(tmp_path / "big.csv")

        big_df.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["nivel_alerta"] == "CRITICO"
        assert "masiva" in events[0]["motivo_alerta"].lower()

    def test_exportacion_normal_no_genera_alerta_critica_por_volumen(self, clean_db, tmp_path, monkeypatch):
        _, mock_conn = clean_db
        monkeypatch.setattr(
            "audit_tracer.export_capture._get_session",
            lambda: ("u1", "sesion-1"),
        )
        small_df = wrap_for_export(pd.DataFrame({"col": [1, 2, 3]}), "small.csv")
        destino = str(tmp_path / "small.csv")

        small_df.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["nivel_alerta"] == "NORMAL"


# ──────────────────────────────────────────────────────────────
# Integridad y registro completo (CA2)
# ──────────────────────────────────────────────────────────────

class TestRegistroAuditLog:
    def test_evento_tiene_hash_integridad(self, clean_db, audited, tmp_path):
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        events = _get_export_events(mock_conn)
        assert events[0]["hash_integridad"] is not None
        assert len(events[0]["hash_integridad"]) == 64

    def test_evento_disponible_inmediatamente(self, clean_db, audited, tmp_path):
        """CA4 de HU-2.1 aplicado a exportación: persistencia inmediata."""
        _, mock_conn = clean_db
        destino = str(tmp_path / "salida.csv")

        audited.to_csv(destino, index=False)

        conn = mock_conn()
        events = get_events(conn)
        conn.close()
        assert len(events) >= 1

    def test_activate_es_idempotente(self):
        export_capture.activate()
        export_capture.activate()  # no debe lanzar ni duplicar el parcheo
        assert export_capture._export_interceptor_active is True

    def test_deactivate_restaura_metodos_originales(self, clean_db):
        export_capture.deactivate()
        assert export_capture._export_interceptor_active is False
        export_capture.activate()  # dejar reactivado para el resto de tests
