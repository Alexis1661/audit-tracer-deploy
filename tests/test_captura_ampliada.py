"""
tests/test_captura_ampliada.py
==============================
LIB-R2 y HU-03 (21/11/2026): lo que antes la librería no interceptaba.

  * Lectores adicionales de pandas (read_parquet, read_json, read_table, ...)
    y de NumPy -> CARGA
  * head, tail, sample, describe, groupby, filter, at, iat -> CONSULTA
  * open() en modo lectura sobre un archivo ya cargado como dataset -> CONSULTA
  * to_sql, to_pickle, to_feather, to_clipboard, np.save, ... -> EXPORTACION
  * fit / predict / validación cruzada de scikit-learn -> MODELADO
"""

import json
import os
import sqlite3

import numpy as np
import pandas as pd
import pytest

from audit_tracer import data_capture, export_capture, model_capture, transform_capture
from audit_tracer.db import SCHEMA_DIR
from audit_tracer.models.audit_log import get_events


@pytest.fixture(autouse=True)
def base(monkeypatch, tmp_path):
    db_file = str(tmp_path / "audit_trail.db")

    def conectar():
        existe = os.path.exists(db_file)
        conn = sqlite3.connect(db_file, check_same_thread=False)
        if not existe:
            for sql in ("usuarios.sql", "audit_log.sql"):
                with open(os.path.join(SCHEMA_DIR, sql), encoding="utf-8") as f:
                    conn.executescript(f.read())
            conn.commit()
        return conn

    for modulo in ("audit_tracer.data_capture", "audit_tracer.transform_capture",
                   "audit_tracer.export_capture", "audit_tracer.model_capture", "audit_tracer.failed_access"):
        monkeypatch.setattr(f"{modulo}.get_connection", conectar)
    data_capture._ultimos_loc.clear()
    model_capture._ultimos.clear()
    for modulo in (data_capture, export_capture):
        modulo.deactivate()
        modulo.activate()
    model_capture.activate()
    yield conectar
    data_capture.deactivate()
    export_capture.deactivate()


def _eventos(conectar):
    conn = conectar()
    try:
        return get_events(conn)
    finally:
        conn.close()


def _nuevos(conectar, antes):
    return _eventos(conectar)[antes:]


@pytest.fixture
def archivo_csv(tmp_path):
    ruta = tmp_path / "PACIENTES.csv"
    pd.DataFrame({"edad": [30, 45, 70, 15, 50, 60], "sexo": [0, 1, 0, 1, 1, 0],
                  "y": [0, 1, 1, 0, 1, 0]}).to_csv(ruta, index=False)
    return ruta


class TestLectoresAdicionales:

    def test_read_parquet_y_read_json_son_carga(self, base, tmp_path):
        df = pd.DataFrame({"a": [1, 2], "b": [3, 4]})
        df.to_parquet(tmp_path / "datos.parquet")
        df.to_json(tmp_path / "datos.json")
        antes = len(_eventos(base))
        leido = pd.read_parquet(tmp_path / "datos.parquet")
        pd.read_json(tmp_path / "datos.json")
        cargas = [e for e in _nuevos(base, antes) if e["tipo_accion"] == "CARGA"]
        assert [e["dataset_nombre"] for e in cargas] == ["datos.parquet", "datos.json"]
        assert isinstance(leido, data_capture.AuditedFrame)

    def test_read_table_por_nombre_de_parametro(self, base, tmp_path):
        (tmp_path / "t.tsv").write_text("x\ty\n1\t2\n")
        antes = len(_eventos(base))
        pd.read_table(filepath_or_buffer=tmp_path / "t.tsv")
        (e,) = _nuevos(base, antes)
        assert e["tipo_accion"] == "CARGA" and e["dataset_nombre"] == "t.tsv"

    def test_archivo_inexistente_es_acceso_fallido(self, base, tmp_path):
        antes = len(_eventos(base))
        with pytest.raises(FileNotFoundError):
            pd.read_parquet(tmp_path / "no_existe.parquet")
        assert [e["tipo_accion"] for e in _nuevos(base, antes)] == ["ACCESO_FALLIDO"]

    def test_numpy_load_y_save(self, base, tmp_path):
        antes = len(_eventos(base))
        np.save(tmp_path / "x.npy", np.arange(10))
        np.load(tmp_path / "x.npy")
        tipos = [(e["tipo_accion"], e["dataset_nombre"]) for e in _nuevos(base, antes)]
        assert tipos == [("EXPORTACION", "numpy_array"), ("CARGA", "x.npy")]

    def test_desactivar_restaura_los_lectores(self):
        data_capture.deactivate()
        assert not hasattr(pd.read_parquet, "_audit_tracer_original")
        assert not hasattr(np.load, "_audit_tracer_original")
        import builtins
        assert not hasattr(builtins.open, "_audit_tracer_original")
        data_capture.activate()
        assert hasattr(pd.read_parquet, "_audit_tracer_original")


class TestConsultasAdicionales:

    @pytest.fixture
    def df(self):
        return data_capture.wrap_audited(
            pd.DataFrame({"edad": [30, 45, 70, 15], "sexo": ["F", "M", "F", "M"], "glucosa": [90, 110, 160, 85]}),
            "PACIENTES.csv")

    @pytest.mark.parametrize("operacion,columnas", [
        (lambda d: d.head(2), ["edad", "sexo", "glucosa"]),
        (lambda d: d.tail(2), ["edad", "sexo", "glucosa"]),
        (lambda d: d.groupby("sexo"), ["sexo"]),
        (lambda d: d.filter(["edad"]), ["edad"]),
        (lambda d: d.nlargest(2, "glucosa"), ["edad", "sexo", "glucosa"]),
    ])
    def test_son_consulta_con_sus_columnas(self, base, df, operacion, columnas):
        antes = len(_eventos(base))
        operacion(df)
        consultas = [e for e in _nuevos(base, antes) if e["tipo_accion"] == "CONSULTA"]
        assert consultas and json.loads(consultas[0]["columnas_afectadas"]) == columnas

    def test_at_e_iat_registran_la_columna_una_vez_por_segundo(self, base, df):
        antes = len(_eventos(base))
        for i in range(4):
            df.at[i, "glucosa"]
        df.iat[0, 0]
        nuevos = _nuevos(base, antes)
        assert [json.loads(e["columnas_afectadas"]) for e in nuevos] == [["glucosa"], ["edad"]]

    def test_los_resultados_son_los_de_pandas(self, df):
        crudo = pd.DataFrame(df)
        assert df.head(2).equals(crudo.head(2))
        assert df.groupby("sexo")["edad"].mean().equals(crudo.groupby("sexo")["edad"].mean())
        assert df.at[2, "glucosa"] == 160
        df.at[2, "glucosa"] = 161
        assert df.at[2, "glucosa"] == 161

    def test_no_se_guardan_valores(self, base):
        centinela = 987654321
        df = data_capture.wrap_audited(pd.DataFrame({"glucosa": [centinela, 90]}), "PACIENTES.csv")
        df.describe()
        df.sample(1, random_state=0)
        df.nlargest(1, "glucosa")
        campos = ("dataset_nombre", "columnas_afectadas", "contexto_ejecucion", "motivo_fallo", "motivo_alerta")
        assert all(str(centinela) not in str(e.get(c)) for e in _eventos(base) for c in campos)


class TestLecturaDirectaConOpen:

    def test_leer_con_open_un_dataset_ya_cargado_es_consulta(self, base, archivo_csv):
        pd.read_csv(archivo_csv)
        antes = len(_eventos(base))
        import csv
        with open(archivo_csv, encoding="utf-8") as f:
            list(csv.reader(f))
        (e,) = _nuevos(base, antes)
        assert e["tipo_accion"] == "CONSULTA" and e["dataset_nombre"] == "PACIENTES.csv"
        assert "open()" in e["columnas_afectadas"]

    def test_otros_archivos_no_generan_eventos(self, base, archivo_csv, tmp_path):
        pd.read_csv(archivo_csv)
        otro = tmp_path / "notas.txt"
        otro.write_text("hola")
        antes = len(_eventos(base))
        with open(otro) as f:
            f.read()
        with open(archivo_csv, "a") as f:   # escritura: no es lectura del dataset
            f.write("")
        assert _nuevos(base, antes) == []


class TestExportacionesAdicionales:

    @pytest.fixture
    def df(self):
        return data_capture.wrap_audited(pd.DataFrame({"a": range(5)}), "ORIGEN.csv")

    def test_to_pickle_y_to_feather(self, base, df, tmp_path):
        antes = len(_eventos(base))
        df.to_pickle(tmp_path / "x.pkl")
        df.reset_index(drop=True).to_feather(tmp_path / "x.feather")
        exportaciones = [e for e in _nuevos(base, antes) if e["tipo_accion"] == "EXPORTACION"]
        assert [os.path.basename(e["ruta_destino"]) for e in exportaciones] == ["x.pkl", "x.feather"]
        assert exportaciones[0]["filas_exportadas"] == 5

    def test_to_sql_registra_la_tabla_de_destino(self, base, df, tmp_path):
        conn = sqlite3.connect(tmp_path / "destino.db")
        antes = len(_eventos(base))
        df.to_sql("pacientes_copia", conn, index=False)
        conn.close()
        (e,) = [e for e in _nuevos(base, antes) if e["tipo_accion"] == "EXPORTACION"]
        assert e["ruta_destino"] == "sql:pacientes_copia" and e["filas_exportadas"] == 5

    def test_to_html_sin_archivo_no_es_exportacion(self, base, df, tmp_path):
        antes = len(_eventos(base))
        df.to_html()
        assert _nuevos(base, antes) == []
        df.to_html(tmp_path / "tabla.html")
        assert [e["tipo_accion"] for e in _nuevos(base, antes)] == ["EXPORTACION"]


class TestModelado:

    @pytest.fixture
    def datos(self):
        sklearn = pytest.importorskip("sklearn")  # noqa: F841
        df = data_capture.wrap_audited(pd.DataFrame({
            "edad": [30, 45, 70, 15, 50, 60] * 3, "sexo": [0, 1, 0, 1, 1, 0] * 3, "y": [0, 1, 1, 0, 1, 0] * 3,
        }), "PACIENTES.csv")
        return df[["edad", "sexo"]], df["y"]

    def _modelado(self, base, antes):
        return [e for e in _nuevos(base, antes) if e["tipo_accion"].startswith("MODELADO")]

    def test_fit_y_predict_son_modelado(self, base, datos):
        from sklearn.linear_model import LogisticRegression
        X, y = datos
        antes = len(_eventos(base))
        modelo = LogisticRegression().fit(X, y)
        modelo.predict(X)
        eventos = self._modelado(base, antes)
        assert [e["motivo_fallo"] for e in eventos] == [
            "[ENTRENAMIENTO] LogisticRegression.fit()", "[PREDICCION] LogisticRegression.predict()"]
        assert all(e["dataset_nombre"] == "PACIENTES.csv" for e in eventos)
        assert json.loads(eventos[0]["columnas_afectadas"]) == ["edad", "sexo"]
        assert "Filas: 18" in eventos[0]["contexto_ejecucion"]

    def test_pipeline_y_busqueda_de_hiperparametros_son_un_solo_evento(self, base, datos):
        from sklearn.linear_model import LogisticRegression
        from sklearn.model_selection import GridSearchCV, cross_val_score
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        X, y = datos
        antes = len(_eventos(base))
        make_pipeline(StandardScaler(), LogisticRegression()).fit(X, y)
        GridSearchCV(LogisticRegression(), {"C": [0.1, 1, 10]}, cv=3).fit(X, y)
        cross_val_score(LogisticRegression(), X, y, cv=3)
        assert [e["motivo_fallo"] for e in self._modelado(base, antes)] == [
            "[ENTRENAMIENTO] Pipeline.fit()", "[ENTRENAMIENTO] GridSearchCV.fit()",
            "[VALIDACION] LogisticRegression.cross_val_score()"]

    def test_predicciones_en_bucle_se_registran_una_vez_por_segundo(self, base, datos):
        from sklearn.tree import DecisionTreeClassifier
        X, y = datos
        modelo = DecisionTreeClassifier().fit(X, y)
        antes = len(_eventos(base))
        for _ in range(20):
            modelo.predict(X)
        assert len(self._modelado(base, antes)) == 1

    def test_un_entrenamiento_fallido_es_modelado_fallido_y_la_excepcion_llega(self, base, datos):
        from sklearn.linear_model import LogisticRegression
        X, _ = datos
        antes = len(_eventos(base))
        with pytest.raises(ValueError):
            LogisticRegression().fit(X, [1] * len(X))   # una sola clase
        (e,) = self._modelado(base, antes)
        assert e["tipo_accion"] == "MODELADO_FALLIDO" and "ValueError" in e["motivo_fallo"]

    def test_estimadores_definidos_despues_tambien_se_capturan(self, base, datos):
        from sklearn.base import BaseEstimator, ClassifierMixin
        import numpy as _np

        class Mayoria(ClassifierMixin, BaseEstimator):
            def fit(self, X, y):
                self.clase_ = int(_np.bincount(_np.asarray(y)).argmax())
                return self

            def predict(self, X):
                return _np.full(len(X), self.clase_)

        X, y = datos
        antes = len(_eventos(base))
        Mayoria().fit(X, y).predict(X)
        assert [e["motivo_fallo"] for e in self._modelado(base, antes)] == [
            "[ENTRENAMIENTO] Mayoria.fit()", "[PREDICCION] Mayoria.predict()"]

    def test_desactivar_suspende_la_captura(self, base, datos):
        from sklearn.linear_model import LogisticRegression
        X, y = datos
        model_capture.deactivate()
        try:
            antes = len(_eventos(base))
            LogisticRegression().fit(X, y)
            assert self._modelado(base, antes) == []
            assert any(e["tipo_accion"] == "AUDITORIA_DESACTIVADA" for e in _eventos(base))
        finally:
            model_capture.activate()
