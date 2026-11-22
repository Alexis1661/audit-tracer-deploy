"""
tests/test_captura_consultas.py
===============================
Captura ampliada de consultas (21/11/2026):

  * df.loc[...] y df.iloc[...]            -> CONSULTA
  * df[mascara], df.loc[mascara]           -> TRANSFORMACION [FILTRADO]
  * pd.read_sql / read_sql_query / read_sql_table -> CARGA (solo la tabla, nunca el texto SQL)

Desde la segunda ronda del 21/11/2026 también se interceptan head, tail, filter,
groupby, describe y sample (ver tests/test_captura_ampliada.py).
"""

import os
import sqlite3

import pandas as pd
import pytest

from audit_tracer import data_capture, transform_capture
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

    for modulo in ("audit_tracer.data_capture", "audit_tracer.transform_capture"):
        monkeypatch.setattr(f"{modulo}.get_connection", conectar)
    monkeypatch.setattr("audit_tracer.models.audit_log.get_connection", conectar, raising=False)
    data_capture._ultimos_loc.clear()
    data_capture.deactivate()
    data_capture.activate()
    yield conectar
    data_capture.deactivate()


def _eventos(conectar):
    conn = conectar()
    try:
        return get_events(conn)
    finally:
        conn.close()


@pytest.fixture
def df():
    return data_capture.wrap_audited(
        pd.DataFrame({"edad": [30, 45, 70, 15], "sexo": ["F", "M", "F", "M"], "glucosa": [90, 110, 160, 85]}),
        "PACIENTES.csv")


def _nuevos(conectar, antes):
    return _eventos(conectar)[antes:]


class TestLocIloc:

    def test_loc_con_columna_es_consulta(self, df, base):
        antes = len(_eventos(base))
        r = df.loc[:, "edad"]
        assert list(r) == [30, 45, 70, 15]
        (e,) = _nuevos(base, antes)
        assert e["tipo_accion"] == "CONSULTA" and e["dataset_nombre"] == "PACIENTES.csv"
        assert e["columnas_afectadas"] == '["edad"]'

    def test_loc_con_lista_de_columnas(self, df, base):
        antes = len(_eventos(base))
        df.loc[0:1, ["edad", "sexo"]]
        (e,) = _nuevos(base, antes)
        assert e["tipo_accion"] == "CONSULTA" and e["columnas_afectadas"] == '["edad", "sexo"]'

    def test_iloc_registra_consulta_con_las_columnas_por_posicion(self, df, base):
        antes = len(_eventos(base))
        r = df.iloc[0:2, [0, 2]]
        assert list(r.columns) == ["edad", "glucosa"]
        (e,) = _nuevos(base, antes)
        assert e["tipo_accion"] == "CONSULTA" and e["columnas_afectadas"] == '["edad", "glucosa"]'

    def test_iloc_de_filas_registra_las_columnas_del_resultado(self, df, base):
        antes = len(_eventos(base))
        df.iloc[0:2]
        (e,) = _nuevos(base, antes)
        assert e["tipo_accion"] == "CONSULTA" and e["columnas_afectadas"] == '["edad", "sexo", "glucosa"]'

    def test_el_resultado_y_la_asignacion_son_los_de_pandas(self, df, base):
        sin_auditoria = pd.DataFrame(df.to_dict("list"))
        assert df.loc[1, "edad"] == sin_auditoria.loc[1, "edad"] == 45
        df.loc[1, "edad"] = 99
        assert df.loc[1, "edad"] == 99
        df.iloc[0, 0] = 1
        assert df.iloc[0, 0] == 1

    def test_lecturas_repetidas_por_celda_se_registran_una_vez(self, df, base):
        antes = len(_eventos(base))
        for i in range(200):
            df.loc[i % 4, "edad"]
        assert len(_nuevos(base, antes)) == 1

    def test_los_errores_del_usuario_llegan_intactos(self, df):
        with pytest.raises(KeyError):
            df.loc[:, "no_existe"]
        with pytest.raises(IndexError):
            df.iloc[99]

    def test_loc_con_axis_funciona(self, df):
        assert len(df.loc(axis=0)[[0, 1]]) == 2


class TestFiltrado:

    def test_mascara_booleana_es_transformacion_filtrado(self, df, base):
        antes = len(_eventos(base))
        r = df[df["edad"] >= 18]
        assert len(r) == 3
        filtrado = [e for e in _nuevos(base, antes) if e["tipo_accion"] == "TRANSFORMACION"]
        assert len(filtrado) == 1
        e = filtrado[0]
        assert e["motivo_fallo"] == "[FILTRADO] df[mascara]: 3 de 4 filas"
        assert e["dataset_nombre"] == "PACIENTES.csv"
        assert "Comparacion:v1:4,3:3,3:0,0" in e["contexto_ejecucion"]

    def test_loc_con_mascara_tambien_es_filtrado(self, df, base):
        antes = len(_eventos(base))
        df.loc[df["sexo"] == "F"]
        (e,) = [e for e in _nuevos(base, antes) if e["tipo_accion"] == "TRANSFORMACION"]
        assert e["motivo_fallo"] == "[FILTRADO] df.loc[mascara]: 2 de 4 filas"

    def test_el_resultado_conserva_el_nombre_del_dataset(self, df):
        assert df[df["edad"] > 20]._dataset_nombre == "PACIENTES.csv"

    def test_no_se_guardan_los_valores_de_las_celdas(self, df, base):
        df[df["edad"] == 45]
        texto = str([dict(e) for e in _eventos(base)])
        assert "== 45" not in texto

    def test_seleccion_de_columnas_sigue_siendo_consulta(self, df, base):
        antes = len(_eventos(base))
        df[["edad", "sexo"]]
        (e,) = _nuevos(base, antes)
        assert e["tipo_accion"] == "CONSULTA"

    def test_groupby_describe_sample_y_filter_ahora_son_consulta(self, df, base):
        antes = len(_eventos(base))
        df.groupby("sexo")["glucosa"].mean()
        df.describe()
        df.sample(2)
        df.filter(["edad"])
        tipos = [e["tipo_accion"] for e in _nuevos(base, antes)]
        assert tipos and set(tipos) == {"CONSULTA"}


class TestReadSql:

    @pytest.fixture
    def bd(self, tmp_path):
        ruta = str(tmp_path / "clinica.db")
        conn = sqlite3.connect(ruta)
        conn.execute("CREATE TABLE pacientes (id INTEGER, nombre TEXT, edad INTEGER)")
        conn.executemany("INSERT INTO pacientes VALUES (?, ?, ?)", [(1, "Ana", 30), (2, "Luis", 45), (3, "Eva", 70)])
        conn.commit()
        yield conn
        conn.close()

    def test_read_sql_query_es_carga_y_guarda_solo_la_tabla(self, bd, base):
        antes = len(_eventos(base))
        r = pd.read_sql("SELECT id, edad FROM pacientes WHERE nombre = 'Ana'", bd)
        assert list(r.columns) == ["id", "edad"] and len(r) == 1
        (e,) = _nuevos(base, antes)
        assert e["tipo_accion"] == "CARGA" and e["dataset_nombre"] == "sql:pacientes"
        assert e["columnas_afectadas"] == '["id", "edad"]'
        assert "Ana" not in str([dict(x) for x in _eventos(base)])

    def test_read_sql_query_y_read_sql_table(self, bd, base):
        antes = len(_eventos(base))
        pd.read_sql_query("select * from pacientes", bd)
        pd.read_sql_table  # se parchea aunque necesite SQLAlchemy para ejecutarse
        nuevos = _nuevos(base, antes)
        assert [e["dataset_nombre"] for e in nuevos] == ["sql:pacientes"]

    def test_el_dataframe_leido_queda_auditado(self, bd, base):
        r = pd.read_sql("SELECT * FROM pacientes", bd)
        assert isinstance(r, data_capture.AuditedFrame) and r._dataset_nombre == "sql:pacientes"
        antes = len(_eventos(base))
        r["edad"]
        assert _nuevos(base, antes)[0]["tipo_accion"] == "CONSULTA"

    def test_los_errores_de_sql_llegan_intactos(self, bd):
        with pytest.raises(Exception) as exc:
            pd.read_sql("SELECT * FROM no_existe", bd)
        assert "no_existe" in str(exc.value)

    def test_desactivar_restaura_pandas(self, bd):
        data_capture.deactivate()
        assert not hasattr(pd.read_sql, "_audit_tracer_original")
        data_capture.activate()
        assert hasattr(pd.read_sql, "_audit_tracer_original")
