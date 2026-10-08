"""
tests/test_transform_capture.py
================================
Pruebas unitarias — HU-2.2: Registrar eventos de modificación
y transformación de datos

Cubre todos los criterios de aceptación:
  CA1: tipo_transformacion, columnas_afectadas, origen_ejecucion en cada registro
  CA2: orden cronológico garantizado por timestamp
  CA3: solo columnas involucradas, no el dataset completo
  CA4: un registro independiente por transformación
  CA5: usuario_id y sesion_id en cada registro

Subtasks validadas:
  PDGTRAZDSA-58: Catálogo de tipos de transformación definido
  PDGTRAZDSA-59: Interceptación de fillna, dropna, drop, rename, apply, merge
  PDGTRAZDSA-60: Identificación precisa de columnas afectadas
  PDGTRAZDSA-61: Registro en audit_log con todos los campos requeridos
"""

import json
import os
import sqlite3
import pytest
import pandas as pd

from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import get_events
from audit_tracer import transform_capture
from audit_tracer.transform_capture import (
    wrap_for_transforms,
    TIPO_FILTRADO,
    TIPO_IMPUTACION,
    TIPO_ELIMINACION_FILAS,
    TIPO_ELIMINACION_COLS,
    TIPO_RENOMBRE,
    TIPO_APLICACION,
    TIPO_NORMALIZACION,
    TIPO_MERGE,
    TIPOS_VALIDOS,
)


# ──────────────────────────────────────────────────────────────
# FIXTURES
# ──────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_db(monkeypatch, tmp_path):
    """
    BD temporal aislada por test.
    Activa/desactiva el interceptor alrededor de cada test.
    """
    db_file = str(tmp_path / "audit_trail.db")
    schema_dir = "schema"

    def _mock_conn():
        exists = os.path.exists(db_file)
        conn = sqlite3.connect(db_file, check_same_thread=False)
        if not exists:
            for sql in ["usuarios.sql", "audit_log.sql"]:
                path = os.path.join(schema_dir, sql)
                if os.path.exists(path):
                    with open(path, encoding="utf-8") as f:
                        conn.executescript(f.read())
            conn.commit()
        return conn

    monkeypatch.setattr("audit_tracer.transform_capture.get_connection", _mock_conn)
    monkeypatch.setattr("audit_tracer.models.audit_log.get_connection", _mock_conn, raising=False)

    transform_capture.deactivate()
    transform_capture.activate()

    yield db_file, _mock_conn

    transform_capture.deactivate()


@pytest.fixture
def patients_df():
    """DataFrame clínico de prueba (PATIENTS-like)."""
    return pd.DataFrame({
        "subject_id":  [1, 2, 3, 4, 5],
        "age":         [45, None, 60, 30, None],
        "gender":      ["M", "F", "M", None, "F"],
        "diagnosis":   ["sepsis", "pneumonia", "ards", "sepsis", None],
        "los":         [3.0, 7.5, None, 2.0, 5.5],
    })


@pytest.fixture
def audited(patients_df):
    """AuditedTransformDataFrame listo para usar en tests."""
    return wrap_for_transforms(patients_df, "PATIENTS.csv")


def _get_transform_events(mock_conn_fn):
    conn = mock_conn_fn()
    events = get_events(conn, tipo_accion="TRANSFORMACION")
    conn.close()
    return events


def _cols(event) -> list:
    """Parsea columnas_afectadas de un evento."""
    raw = event.get("columnas_afectadas")
    if raw is None:
        return []
    try:
        return json.loads(raw)
    except Exception:
        return [raw]


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-58: Catálogo de tipos de transformación
# ──────────────────────────────────────────────────────────────

class TestCatalogoTipos:
    """Valida que todos los tipos están definidos y son consistentes."""

    def test_tipos_definidos_como_constantes(self):
        assert TIPO_FILTRADO           == "FILTRADO"
        assert TIPO_IMPUTACION         == "IMPUTACION"
        assert TIPO_ELIMINACION_FILAS  == "ELIMINACION_FILAS"
        assert TIPO_ELIMINACION_COLS   == "ELIMINACION_COLS"
        assert TIPO_RENOMBRE           == "RENOMBRE"
        assert TIPO_APLICACION         == "APLICACION"
        assert TIPO_MERGE              == "MERGE"
        assert TIPO_NORMALIZACION      == "NORMALIZACION"

    def test_todos_los_tipos_en_set_validos(self):
        for t in [TIPO_FILTRADO, TIPO_IMPUTACION, TIPO_ELIMINACION_FILAS,
                  TIPO_ELIMINACION_COLS, TIPO_RENOMBRE, TIPO_APLICACION,
                  TIPO_MERGE, TIPO_NORMALIZACION]:
            assert t in TIPOS_VALIDOS

    def test_tipo_accion_siempre_es_transformacion(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.fillna(0)
        audited.dropna()

        events = _get_transform_events(mock_conn)
        assert all(e["tipo_accion"] == "TRANSFORMACION" for e in events)

    def test_tipos_son_strings_sin_espacios(self):
        for t in TIPOS_VALIDOS:
            assert isinstance(t, str)
            assert " " not in t
            assert t == t.upper()


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-59 + CA1: Interceptación de operaciones
# ──────────────────────────────────────────────────────────────

class TestFillna:
    """CA1, CA2, CA3, CA4, CA5 para fillna() → IMPUTACION."""

    def test_fillna_genera_evento(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.fillna(0)
        events = _get_transform_events(mock_conn)
        assert len(events) >= 1

    def test_fillna_tipo_accion_transformacion(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.fillna(0)
        events = _get_transform_events(mock_conn)
        assert events[-1]["tipo_accion"] == "TRANSFORMACION"

    def test_fillna_descripcion_contiene_imputacion(self, clean_db, audited):
        """CA1: tipo_transformacion en descripcion."""
        _, mock_conn = clean_db
        audited.fillna(0)
        events = _get_transform_events(mock_conn)
        assert "IMPUTACION" in events[-1]["motivo_fallo"]

    def test_fillna_dict_registra_solo_columnas_del_dict(self, clean_db, audited):
        """CA3: fillna con dict → solo esas columnas, no todas."""
        _, mock_conn = clean_db
        audited.fillna({"age": 0, "los": -1})

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "age" in cols
        assert "los" in cols
        assert "gender" not in cols     # no fue imputada

    def test_fillna_valor_escalar_registra_columnas_numericas(self, clean_db, audited):
        """fillna escalar afecta todo el DF → registra todas las columnas."""
        _, mock_conn = clean_db
        audited.fillna(0)

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert len(cols) > 0

    def test_fillna_contiene_usuario_id(self, clean_db, audited):
        """CA5."""
        _, mock_conn = clean_db
        audited.fillna(0)
        events = _get_transform_events(mock_conn)
        assert events[-1]["usuario_id"] is not None

    def test_fillna_contiene_sesion_id(self, clean_db, audited):
        """CA5."""
        _, mock_conn = clean_db
        audited.fillna(0)
        events = _get_transform_events(mock_conn)
        assert events[-1]["sesion_id"] is not None

    def test_fillna_contiene_timestamp(self, clean_db, audited):
        """CA2."""
        _, mock_conn = clean_db
        audited.fillna(0)
        events = _get_transform_events(mock_conn)
        assert events[-1]["timestamp"] is not None

    def test_fillna_no_altera_datos(self, clean_db, patients_df):
        """La intercepción no modifica el resultado de fillna."""
        _, _ = clean_db
        audited = wrap_for_transforms(patients_df.copy(), "PATIENTS.csv")
        result = audited.fillna({"age": 0})
        assert result["age"].isna().sum() == 0

    def test_fillna_contiene_dataset_nombre(self, clean_db, audited):
        """CA1."""
        _, mock_conn = clean_db
        audited.fillna(0)
        events = _get_transform_events(mock_conn)
        assert events[-1]["dataset_nombre"] == "PATIENTS.csv"

    def test_fillna_contiene_origen_ejecucion(self, clean_db, audited):
        """CA1: origen_ejecucion en contexto_ejecucion."""
        _, mock_conn = clean_db
        audited.fillna(0)
        events = _get_transform_events(mock_conn)
        ctx = events[-1]["contexto_ejecucion"]
        assert ctx is not None and "Script:" in ctx


class TestDropna:
    """CA1, CA3, CA4, CA5 para dropna() → ELIMINACION_FILAS."""

    def test_dropna_genera_evento(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.dropna()
        events = _get_transform_events(mock_conn)
        assert len(events) >= 1

    def test_dropna_descripcion_contiene_eliminacion_filas(self, clean_db, audited):
        """CA1."""
        _, mock_conn = clean_db
        audited.dropna()
        events = _get_transform_events(mock_conn)
        assert "ELIMINACION_FILAS" in events[-1]["motivo_fallo"]

    def test_dropna_subset_registra_solo_columnas_subset(self, clean_db, audited):
        """CA3: solo las columnas del subset."""
        _, mock_conn = clean_db
        audited.dropna(subset=["age", "diagnosis"])

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "age" in cols
        assert "diagnosis" in cols
        assert "gender" not in cols

    def test_dropna_sin_subset_registra_todas_las_columnas(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.dropna()
        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert len(cols) == 5   # todas las columnas del DF

    def test_dropna_no_altera_datos(self, clean_db, patients_df):
        _, _ = clean_db
        audited = wrap_for_transforms(patients_df.copy(), "PATIENTS.csv")
        result = audited.dropna(subset=["age"])
        assert len(result) == 3   # filas con age no nulo


class TestDrop:
    """CA1, CA3, CA4, CA5 para drop(columns=...) → ELIMINACION_COLS."""

    def test_drop_columns_genera_evento(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.drop(columns=["gender"])
        events = _get_transform_events(mock_conn)
        assert len(events) >= 1

    def test_drop_columns_descripcion_contiene_eliminacion_cols(self, clean_db, audited):
        """CA1."""
        _, mock_conn = clean_db
        audited.drop(columns=["los"])
        events = _get_transform_events(mock_conn)
        assert "ELIMINACION_COLS" in events[-1]["motivo_fallo"]

    def test_drop_columns_registra_columnas_eliminadas(self, clean_db, audited):
        """CA3: solo las columnas eliminadas."""
        _, mock_conn = clean_db
        audited.drop(columns=["gender", "diagnosis"])

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "gender" in cols
        assert "diagnosis" in cols
        assert "age" not in cols        # no fue eliminada

    def test_drop_columns_lista(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.drop(columns=["los", "age"])
        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "los" in cols
        assert "age" in cols

    def test_drop_no_altera_datos(self, clean_db, patients_df):
        _, _ = clean_db
        audited = wrap_for_transforms(patients_df.copy(), "PATIENTS.csv")
        result = audited.drop(columns=["gender"])
        assert "gender" not in result.columns
        assert "age" in result.columns


class TestRename:
    """CA1, CA3, CA4, CA5 para rename() → RENOMBRE."""

    def test_rename_genera_evento(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.rename(columns={"age": "edad", "gender": "sexo"})
        events = _get_transform_events(mock_conn)
        assert len(events) >= 1

    def test_rename_descripcion_contiene_renombre(self, clean_db, audited):
        """CA1."""
        _, mock_conn = clean_db
        audited.rename(columns={"los": "length_of_stay"})
        events = _get_transform_events(mock_conn)
        assert "RENOMBRE" in events[-1]["motivo_fallo"]

    def test_rename_registra_columnas_originales(self, clean_db, audited):
        """CA3: columnas originales (antes del renombrado)."""
        _, mock_conn = clean_db
        audited.rename(columns={"age": "edad", "diagnosis": "dx"})

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "age" in cols
        assert "diagnosis" in cols

    def test_rename_registra_nombres_nuevos(self, clean_db, audited):
        """CA3: también los nombres nuevos (con prefijo →)."""
        _, mock_conn = clean_db
        audited.rename(columns={"age": "edad"})

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert any("edad" in c for c in cols)

    def test_rename_no_altera_datos(self, clean_db, patients_df):
        _, _ = clean_db
        audited = wrap_for_transforms(patients_df.copy(), "PATIENTS.csv")
        result = audited.rename(columns={"age": "edad"})
        assert "edad" in result.columns
        assert "age" not in result.columns


class TestApply:
    """CA1, CA3, CA4, CA5 para apply() → APLICACION / NORMALIZACION."""

    def test_apply_genera_evento(self, clean_db, audited):
        _, mock_conn = clean_db
        audited[["age", "los"]].apply(lambda x: x * 2)
        events = _get_transform_events(mock_conn)
        assert len(events) >= 1

    def test_apply_descripcion_contiene_aplicacion(self, clean_db, audited):
        """CA1."""
        _, mock_conn = clean_db
        audited[["age", "los"]].apply(lambda x: x.fillna(0))
        events = _get_transform_events(mock_conn)
        assert "APLICACION" in events[-1]["motivo_fallo"]

    def test_apply_normalizacion_detectada_por_nombre(self, clean_db, audited):
        """PDGTRAZDSA-58: si func se llama 'normalize' → NORMALIZACION."""
        _, mock_conn = clean_db

        def normalize(col):
            mn, mx = col.min(), col.max()
            return (col - mn) / (mx - mn) if mx != mn else col

        audited[["age", "los"]].apply(normalize)
        events = _get_transform_events(mock_conn)
        assert "NORMALIZACION" in events[-1]["motivo_fallo"]

    def test_apply_no_altera_datos(self, clean_db, patients_df):
        _, _ = clean_db
        df = patients_df[["age"]].fillna(0)
        audited = wrap_for_transforms(df, "test.csv")
        result = audited.apply(lambda x: x * 2)
        assert result["age"].iloc[0] == 90   # 45 * 2


class TestMerge:
    """CA1, CA3, CA4, CA5 para merge() → MERGE."""

    @pytest.fixture
    def admissions_df(self):
        return pd.DataFrame({
            "subject_id":     [1, 2, 3],
            "admission_type": ["EMERGENCY", "ELECTIVE", "EMERGENCY"],
        })

    def test_merge_metodo_genera_evento(self, clean_db, audited, admissions_df):
        _, mock_conn = clean_db
        right = wrap_for_transforms(admissions_df, "ADMISSIONS.csv")
        audited.merge(right, on="subject_id")
        events = _get_transform_events(mock_conn)
        assert len(events) >= 1

    def test_merge_descripcion_contiene_merge(self, clean_db, audited, admissions_df):
        """CA1."""
        _, mock_conn = clean_db
        right = wrap_for_transforms(admissions_df, "ADMISSIONS.csv")
        audited.merge(right, on="subject_id")
        events = _get_transform_events(mock_conn)
        assert "MERGE" in events[-1]["motivo_fallo"]

    def test_merge_registra_columna_clave(self, clean_db, audited, admissions_df):
        """CA3: columna del join."""
        _, mock_conn = clean_db
        right = wrap_for_transforms(admissions_df, "ADMISSIONS.csv")
        audited.merge(right, on="subject_id")
        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "subject_id" in cols

    def test_pd_merge_global_genera_evento(self, clean_db, audited, admissions_df):
        """pd.merge() también debe auditarse."""
        _, mock_conn = clean_db
        right = wrap_for_transforms(admissions_df, "ADMISSIONS.csv")
        pd.merge(audited, right, on="subject_id")
        events = _get_transform_events(mock_conn)
        assert len(events) >= 1

    def test_merge_no_altera_datos(self, clean_db, patients_df, admissions_df):
        _, _ = clean_db
        audited = wrap_for_transforms(patients_df, "PATIENTS.csv")
        right = wrap_for_transforms(admissions_df, "ADMISSIONS.csv")
        result = audited.merge(right, on="subject_id")
        assert "admission_type" in result.columns
        assert "age" in result.columns


# ──────────────────────────────────────────────────────────────
# CA2: Orden cronológico de transformaciones
# ──────────────────────────────────────────────────────────────

class TestOrdenCronologico:
    """CA2: las transformaciones deben almacenarse en orden cronológico."""

    def test_timestamps_en_orden_ascendente(self, clean_db, audited):
        _, mock_conn = clean_db

        audited.fillna(0)
        audited.dropna()
        audited.rename(columns={"age": "edad"})

        events = _get_transform_events(mock_conn)
        timestamps = [e["timestamp"] for e in events]
        assert timestamps == sorted(timestamps), (
            "Los eventos deben estar en orden cronológico ascendente"
        )

    def test_multiples_fillna_generan_registros_separados(self, clean_db, audited):
        """CA4: cada operación = un registro independiente."""
        _, mock_conn = clean_db

        audited.fillna({"age": 0})
        audited.fillna({"los": -1})

        events = _get_transform_events(mock_conn)
        assert len(events) == 2

    def test_secuencia_completa_genera_registros_independientes(self, clean_db, patients_df):
        """CA4: pipeline de 4 transformaciones → 4 registros."""
        _, mock_conn = clean_db

        df = wrap_for_transforms(patients_df.copy(), "PATIENTS.csv")
        df = df.fillna({"age": df["age"].median(), "los": 0})
        df = df.dropna(subset=["gender"])
        df = df.rename(columns={"los": "length_of_stay"})
        df = df.drop(columns=["diagnosis"])

        events = _get_transform_events(mock_conn)
        assert len(events) == 4

        tipos_en_desc = [e["motivo_fallo"] for e in events]
        assert any("IMPUTACION"        in d for d in tipos_en_desc)
        assert any("ELIMINACION_FILAS" in d for d in tipos_en_desc)
        assert any("RENOMBRE"          in d for d in tipos_en_desc)
        assert any("ELIMINACION_COLS"  in d for d in tipos_en_desc)


# ──────────────────────────────────────────────────────────────
# CA3: Solo columnas involucradas
# ──────────────────────────────────────────────────────────────

class TestColumnasAfectadas:
    """CA3: columnas_afectadas debe ser específico, no el dataset completo."""

    def test_fillna_dict_no_incluye_columnas_no_imputadas(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.fillna({"age": 0})   # solo age

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "gender" not in cols
        assert "diagnosis" not in cols
        assert "los" not in cols

    def test_drop_columns_no_incluye_columnas_retenidas(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.drop(columns=["diagnosis"])

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "age" not in cols
        assert "gender" not in cols

    def test_dropna_subset_no_incluye_otras_columnas(self, clean_db, audited):
        _, mock_conn = clean_db
        audited.dropna(subset=["age"])

        events = _get_transform_events(mock_conn)
        cols = _cols(events[-1])
        assert "los" not in cols
        assert "diagnosis" not in cols

    def test_columnas_afectadas_es_lista_json(self, clean_db, audited):
        """columnas_afectadas debe poder parsearse como JSON array."""
        _, mock_conn = clean_db
        audited.fillna({"age": 0, "los": 0})

        events = _get_transform_events(mock_conn)
        raw = events[-1]["columnas_afectadas"]
        parsed = json.loads(raw)
        assert isinstance(parsed, list)


