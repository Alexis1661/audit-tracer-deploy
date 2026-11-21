"""
tests/test_lineage.py
=====================
Pruebas — HU-7.1: Visualización de linaje de datos (grafo)

CA1: El grafo tiene nodos de datasets, transformaciones y modelos, y aristas
     que representan la relación de origen deducida de los eventos.
CA2: El grafo se obtiene seleccionando un dataset o un evento.
CA3: El orden de los pasos se deriva del timestamp, no del orden de inserción
     ni del orden en que la consulta devuelve las filas.
CA4: Cada nodo enlaza al detalle de evento existente de HU-4.3.

Todos los grafos se construyen a partir de eventos insertados en audit_log
(con insert_event() o con los interceptores reales de captura), nunca a
partir de estructuras armadas a mano.
"""

import os

import pandas as pd
from conftest import crear_sesion_web
import pytest

import app as app_module
from audit_tracer import data_capture, export_capture
from audit_tracer.db import get_central_connection, get_connection
from audit_tracer.lineage import build_lineage_graph, list_lineage_datasets
from audit_tracer.models.audit_log import insert_event


# ──────────────────────────────────────────────────────────────
# FIXTURES / HELPERS
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def conn():
    c = get_connection(":memory:")
    yield c
    c.close()


def _ev(conn, **kwargs):
    kwargs.setdefault("usuario_id", "u-cientifico")
    kwargs.setdefault("sesion_id", "s1")
    kwargs.setdefault("nivel_alerta", "NORMAL")
    return insert_event(conn, kwargs)


def _sembrar_flujo_completo(conn, sesion_id="s1", dataset="vitals.csv", dia="2026-08-21"):
    """
    carga → transformación → transformación → modelado → exportación,
    insertado DESORDENADO a propósito (la exportación primero).
    Devuelve los event_id en orden temporal real.
    """
    exp = _ev(conn, sesion_id=sesion_id, tipo_accion="EXPORTACION", dataset_nombre=dataset,
              ruta_destino="outputs/vitals_clean.csv", filas_exportadas=10,
              timestamp=f"{dia}T10:40:00")
    carga = _ev(conn, sesion_id=sesion_id, tipo_accion="CARGA", dataset_nombre=dataset,
                timestamp=f"{dia}T10:00:00")
    modelo = _ev(conn, sesion_id=sesion_id, tipo_accion="MODELADO", dataset_nombre=dataset,
                 timestamp=f"{dia}T10:31:00")
    t1 = _ev(conn, sesion_id=sesion_id, tipo_accion="TRANSFORMACION", dataset_nombre=dataset,
             motivo_fallo="[ELIMINACION_FILAS] dropna()", timestamp=f"{dia}T10:12:00")
    t2 = _ev(conn, sesion_id=sesion_id, tipo_accion="TRANSFORMACION", dataset_nombre=dataset,
             motivo_fallo="[IMPUTACION] fillna(value=0)", timestamp=f"{dia}T10:20:00")
    return [carga, t1, t2, modelo, exp]


def _nodo(grafo, event_id, tipo=None):
    for n in grafo["nodes"]:
        if n.get("event_id") == event_id and (tipo is None or n["tipo"] == tipo):
            return n
    raise AssertionError(f"No hay nodo para el evento {event_id}")


def _aristas(grafo, tipo=None):
    return {(e["source"], e["target"]) for e in grafo["edges"] if tipo is None or e["tipo"] == tipo}


# ──────────────────────────────────────────────────────────────
# CA1 — Construcción del grafo
# ──────────────────────────────────────────────────────────────

class TestConstruccionGrafo:

    def test_nodos_por_tipo_y_aristas_de_origen(self, conn):
        carga, t1, t2, modelo, exp = _sembrar_flujo_completo(conn)
        grafo = build_lineage_graph(conn, dataset_nombre="vitals.csv")

        assert _nodo(grafo, carga)["tipo"] == "dataset"
        assert _nodo(grafo, t1)["tipo"] == "transformacion"
        assert _nodo(grafo, modelo)["tipo"] == "modelo"
        assert _nodo(grafo, exp, "exportacion")["tipo"] == "exportacion"

        esperadas = {
            (f"ev-{carga}", f"ev-{t1}"),
            (f"ev-{t1}", f"ev-{t2}"),
            (f"ev-{t2}", f"ev-{modelo}"),
            (f"ev-{modelo}", f"ev-{exp}"),
        }
        assert _aristas(grafo, "secuencia") == esperadas

    def test_exportacion_genera_nodo_de_archivo_destino(self, conn):
        *_, exp = _sembrar_flujo_completo(conn)
        grafo = build_lineage_graph(conn, dataset_nombre="vitals.csv")

        archivo = _nodo(grafo, exp, "archivo")
        assert archivo["label"] == "vitals_clean.csv"
        assert archivo["ruta_destino"] == "outputs/vitals_clean.csv"
        assert (f"ev-{exp}", archivo["id"]) in _aristas(grafo, "exportado_a")

    def test_consultas_y_eventos_sin_dataset_no_forman_parte_del_linaje(self, conn):
        _sembrar_flujo_completo(conn)
        consulta = _ev(conn, tipo_accion="CONSULTA", dataset_nombre="vitals.csv",
                       timestamp="2026-08-21T10:05:00")
        _ev(conn, tipo_accion="INICIO_SESION", timestamp="2026-08-21T09:59:00")

        grafo = build_lineage_graph(conn, dataset_nombre="vitals.csv")
        assert consulta not in {n.get("event_id") for n in grafo["nodes"]}
        assert {n["tipo_accion"] for n in grafo["nodes"]} <= {
            "CARGA", "TRANSFORMACION", "MODELADO", "EXPORTACION"}

    def test_sesiones_distintas_no_se_enlazan(self, conn):
        a = _sembrar_flujo_completo(conn, sesion_id="s1", dia="2026-08-21")
        b = _sembrar_flujo_completo(conn, sesion_id="s2", dia="2026-08-22")
        grafo = build_lineage_graph(conn, dataset_nombre="vitals.csv")

        assert len(grafo["cadenas"]) == 2
        ids_a = {f"ev-{i}" for i in a}
        ids_b = {f"ev-{i}" for i in b}
        for origen, destino in _aristas(grafo, "secuencia"):
            assert (origen in ids_a) == (destino in ids_a)
            assert (origen in ids_b) == (destino in ids_b)

    def test_datasets_distintos_de_la_misma_sesion_no_se_mezclan(self, conn):
        _sembrar_flujo_completo(conn, dataset="vitals.csv")
        otra = _ev(conn, tipo_accion="CARGA", dataset_nombre="labs.csv",
                   timestamp="2026-08-21T10:15:00")
        grafo = build_lineage_graph(conn, dataset_nombre="vitals.csv")
        assert otra not in {n.get("event_id") for n in grafo["nodes"]}

    def test_dataset_no_identificable_no_se_enlaza(self, conn):
        _ev(conn, tipo_accion="EXPORTACION", dataset_nombre="dataset_desconocido",
            ruta_destino="a.csv", timestamp="2026-08-21T10:00:00")
        _ev(conn, tipo_accion="EXPORTACION", dataset_nombre="dataset_desconocido",
            ruta_destino="b.csv", timestamp="2026-08-21T10:05:00")

        grafo = build_lineage_graph(conn, dataset_nombre="dataset_desconocido")
        assert _aristas(grafo, "secuencia") == set()
        assert any("no identifica un dataset concreto" in a for a in grafo["advertencias"])
        assert list_lineage_datasets(conn) == []

    def test_dataset_sin_eventos_devuelve_grafo_vacio_con_advertencia(self, conn):
        grafo = build_lineage_graph(conn, dataset_nombre="no_existe.csv")
        assert grafo["nodes"] == [] and grafo["edges"] == []
        assert grafo["advertencias"]


# ──────────────────────────────────────────────────────────────
# CA2 — Selección por dataset o por evento
# ──────────────────────────────────────────────────────────────

class TestSeleccion:

    def test_lista_de_datasets_con_linaje(self, conn):
        _sembrar_flujo_completo(conn, sesion_id="s1")
        _sembrar_flujo_completo(conn, sesion_id="s2", dia="2026-08-22")
        _ev(conn, tipo_accion="CONSULTA", dataset_nombre="solo_consultado.csv")

        datasets = {d["dataset_nombre"]: d for d in list_lineage_datasets(conn)}
        assert set(datasets) == {"vitals.csv"}
        assert datasets["vitals.csv"]["sesiones"] == 2
        assert datasets["vitals.csv"]["total_eventos"] == 10

    def test_por_evento_muestra_solo_su_sesion_y_lo_marca(self, conn):
        a = _sembrar_flujo_completo(conn, sesion_id="s1")
        _sembrar_flujo_completo(conn, sesion_id="s2", dia="2026-08-22")

        grafo = build_lineage_graph(conn, event_id=a[1])
        assert grafo["alcance"] == "evento"
        assert grafo["dataset_nombre"] == "vitals.csv"
        assert {n["sesion_id"] for n in grafo["nodes"] if n["tipo"] != "archivo"} == {"s1"}
        seleccionados = [n for n in grafo["nodes"] if n["seleccionado"]]
        assert [n["event_id"] for n in seleccionados] == [a[1]]

    def test_por_evento_de_consulta_muestra_linaje_de_su_dataset(self, conn):
        _sembrar_flujo_completo(conn)
        consulta = _ev(conn, tipo_accion="CONSULTA", dataset_nombre="vitals.csv",
                       timestamp="2026-08-21T10:05:00")
        grafo = build_lineage_graph(conn, event_id=consulta)
        assert len(grafo["cadenas"]) == 1
        assert any("CONSULTA" in a for a in grafo["advertencias"])

    def test_evento_inexistente(self, conn):
        grafo = build_lineage_graph(conn, event_id=9999)
        assert grafo["nodes"] == []
        assert "no existe" in grafo["advertencias"][0]


# ──────────────────────────────────────────────────────────────
# CA3 — Reconstrucción temporal
# ──────────────────────────────────────────────────────────────

class TestOrdenTemporal:

    def test_orden_por_timestamp_y_no_por_insercion(self, conn):
        orden_real = _sembrar_flujo_completo(conn)  # insertados desordenados
        grafo = build_lineage_graph(conn, dataset_nombre="vitals.csv")

        pasos = grafo["cadenas"][0]["pasos"]
        assert [p["event_id"] for p in pasos] == orden_real
        assert [p["paso"] for p in pasos] == [1, 2, 3, 4, 5]
        assert [p["tipo_accion"] for p in pasos] == [
            "CARGA", "TRANSFORMACION", "TRANSFORMACION", "MODELADO", "EXPORTACION"]
        # Como la inserción fue desordenada, el orden por event_id NO coincide.
        assert sorted(orden_real) != orden_real

    def test_posicion_horizontal_refleja_el_orden(self, conn):
        orden_real = _sembrar_flujo_completo(conn)
        grafo = build_lineage_graph(conn, dataset_nombre="vitals.csv")
        xs = [_nodo(grafo, eid)["position"]["x"] for eid in orden_real]
        assert xs == sorted(xs) and len(set(xs)) == len(xs)

    def test_timestamp_identico_desempata_por_event_id(self, conn):
        a = _ev(conn, tipo_accion="CARGA", dataset_nombre="x.csv", timestamp="2026-08-21T10:00:00")
        b = _ev(conn, tipo_accion="TRANSFORMACION", dataset_nombre="x.csv", timestamp="2026-08-21T10:00:00")
        grafo = build_lineage_graph(conn, dataset_nombre="x.csv")
        assert [p["event_id"] for p in grafo["cadenas"][0]["pasos"]] == [a, b]

    def test_modelo_entrenado_identificable_en_la_cadena(self, conn):
        _, _, t2, modelo, _ = _sembrar_flujo_completo(conn)
        grafo = build_lineage_graph(conn, dataset_nombre="vitals.csv")
        assert (f"ev-{t2}", f"ev-{modelo}") in _aristas(grafo, "secuencia")
        assert _nodo(grafo, modelo)["label"] == "Modelo entrenado"


# ──────────────────────────────────────────────────────────────
# DoD — Eventos reales de los interceptores: carga → exportación
# ──────────────────────────────────────────────────────────────

class TestCapturaReal:

    def test_grafo_desde_eventos_capturados_por_los_interceptores(self, tmp_path, monkeypatch):
        db_file = str(tmp_path / "audit_trail.db")
        monkeypatch.setattr(data_capture, "get_connection", lambda: get_connection(db_file))
        monkeypatch.setattr(export_capture, "get_connection", lambda: get_connection(db_file))

        csv_origen = tmp_path / "PATIENTS.csv"
        csv_origen.write_text("subject_id,age\n1,40\n2,\n3,70\n", encoding="utf-8")
        destino = tmp_path / "patients_clean.csv"

        data_capture.activate()
        export_capture.activate()
        try:
            df = pd.read_csv(str(csv_origen))                      # → CARGA
            limpio = export_capture.wrap_for_export(df.dropna(), "PATIENTS.csv")
            limpio.to_csv(str(destino), index=False)               # → EXPORTACION
        finally:
            export_capture.deactivate()
            data_capture.deactivate()

        conn = get_connection(db_file)
        try:
            grafo = build_lineage_graph(conn, dataset_nombre="PATIENTS.csv")
        finally:
            conn.close()

        pasos = grafo["cadenas"][0]["pasos"]
        assert [p["tipo_accion"] for p in pasos] == ["CARGA", "EXPORTACION"]
        archivo = next(n for n in grafo["nodes"] if n["tipo"] == "archivo")
        assert archivo["ruta_destino"] == str(destino)
        assert len(_aristas(grafo, "secuencia")) == 1
        assert len(_aristas(grafo, "exportado_a")) == 1


# ──────────────────────────────────────────────────────────────
# CA2/CA4 — Rutas del dashboard
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def central_db(tmp_path, monkeypatch):
    """Base central aislada: las rutas no tocan audit_central.db real."""
    db_file = str(tmp_path / "audit_central.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_file))
    conn = get_central_connection(db_file)
    ids = _sembrar_flujo_completo(conn)
    conn.close()
    return ids


def _cliente(rol):
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    crear_sesion_web(client, "u-test", rol, "Test", "s-web")
    return client


class TestRutas:

    def test_api_linaje_por_dataset_con_url_de_detalle_hu43(self, central_db):
        resp = _cliente("AUDITOR").get("/api/linaje?dataset=vitals.csv")
        assert resp.status_code == 200
        grafo = resp.get_json()
        for n in grafo["nodes"]:
            assert n["detalle_url"] == f"/eventos/{n['event_id']}"
        assert len(grafo["nodes"]) == 6  # 5 eventos + archivo exportado

    def test_api_linaje_por_evento(self, central_db):
        resp = _cliente("AUDITOR").get(f"/api/linaje?event_id={central_db[2]}")
        grafo = resp.get_json()
        assert grafo["alcance"] == "evento"
        assert any(n["seleccionado"] and n["event_id"] == central_db[2] for n in grafo["nodes"])

    def test_pagina_linaje_renderiza_grafo_y_linea_de_tiempo(self, central_db):
        resp = _cliente("AUDITOR").get("/linaje?dataset=vitals.csv")
        html = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert 'id="lineage-graph"' in html
        assert "Reconstrucción temporal" in html
        for eid in central_db:
            assert f'href="/eventos/{eid}"' in html

    def test_pagina_sin_seleccion_lista_datasets(self, central_db):
        html = _cliente("ANALISTA").get("/linaje").get_data(as_text=True)
        assert 'value="vitals.csv"' in html
        assert 'id="lineage-graph"' not in html

    def test_nodo_enlaza_a_detalle_existente_de_hu43(self, central_db):
        client = _cliente("AUDITOR")
        grafo = client.get("/api/linaje?dataset=vitals.csv").get_json()
        resp = client.get(grafo["nodes"][0]["detalle_url"])
        assert resp.status_code == 200
        assert "Detalle del Evento" in resp.get_data(as_text=True)

    def test_detalle_y_eventos_ofrecen_acceso_al_linaje(self, central_db):
        client = _cliente("AUDITOR")
        detalle = client.get(f"/eventos/{central_db[0]}").get_data(as_text=True)
        assert f"/linaje?event_id={central_db[0]}" in detalle
        listado = client.get("/eventos").get_data(as_text=True)
        assert "/linaje?event_id=" in listado

    def test_rol_sin_permiso_de_reportes_es_rechazado(self, central_db):
        resp = _cliente("CIENTIFICO_DATOS").get("/linaje?dataset=vitals.csv")
        assert resp.status_code == 403
        assert _cliente("CIENTIFICO_DATOS").get("/api/linaje?dataset=vitals.csv").status_code == 403

    def test_requiere_sesion(self):
        client = app_module.app.test_client()
        resp = client.get("/linaje")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]


# ──────────────────────────────────────────────────────────────
# Uniones (merge): la cohorte queda en un solo grafo
# ──────────────────────────────────────────────────────────────

def _sembrar_cohorte(conn, sesion_id="s-cohorte"):
    """ADMISSIONS (carga, fillna, merge) + PATIENTS (carga) → merge(A,P) (drop, exportación)."""
    dia = "2026-11-21"
    ca = _ev(conn, sesion_id=sesion_id, tipo_accion="CARGA", dataset_nombre="ADMISSIONS.csv", timestamp=f"{dia}T10:00:00")
    cp = _ev(conn, sesion_id=sesion_id, tipo_accion="CARGA", dataset_nombre="PATIENTS.csv", timestamp=f"{dia}T10:00:01")
    fa = _ev(conn, sesion_id=sesion_id, tipo_accion="TRANSFORMACION", dataset_nombre="ADMISSIONS.csv",
             motivo_fallo="[IMPUTACION] fillna()", timestamp=f"{dia}T10:01:00")
    mg = _ev(conn, sesion_id=sesion_id, tipo_accion="TRANSFORMACION", dataset_nombre="ADMISSIONS.csv",
             motivo_fallo="[MERGE] merge(ADMISSIONS.csv ⟕ PATIENTS.csv, how='left', on=['subject_id'])",
             timestamp=f"{dia}T10:02:00")
    dr = _ev(conn, sesion_id=sesion_id, tipo_accion="TRANSFORMACION", dataset_nombre="merge(ADMISSIONS.csv,PATIENTS.csv)",
             motivo_fallo="[ELIMINACION_COLS] drop(columns=['row_id'])", timestamp=f"{dia}T10:03:00")
    ex = _ev(conn, sesion_id=sesion_id, tipo_accion="EXPORTACION", dataset_nombre="merge(ADMISSIONS.csv,PATIENTS.csv)",
             ruta_destino="out/reporte.csv", filas_exportadas=129, timestamp=f"{dia}T10:04:00")
    return dict(ca=ca, cp=cp, fa=fa, mg=mg, dr=dr, ex=ex)


class TestUniones:

    def test_entradas_de_union(self):
        from audit_tracer.lineage import entradas_de_union
        assert entradas_de_union("merge(A.csv,B.csv)") == ("A.csv", "B.csv")
        assert entradas_de_union("merge(merge(A.csv,B.csv),C.csv)") == ("merge(A.csv,B.csv)", "C.csv")
        assert entradas_de_union("merge(A.csv,merge(B.csv,C.csv))") == ("A.csv", "merge(B.csv,C.csv)")
        assert entradas_de_union("ADMISSIONS.csv") is None and entradas_de_union(None) is None

    def test_el_resultado_se_conecta_con_sus_dos_entradas_en_un_solo_grafo(self, conn):
        e = _sembrar_cohorte(conn)
        g = build_lineage_graph(conn, dataset_nombre="merge(ADMISSIONS.csv,PATIENTS.csv)")
        # los eventos de las dos entradas y del resultado están en el mismo grafo
        for k in ("ca", "cp", "fa", "mg", "dr", "ex"):
            _nodo(g, e[k])
        union = _aristas(g, "union")
        assert (f"ev-{e['mg']}", f"ev-{e['dr']}") in union     # izquierda: el evento MERGE de ADMISSIONS
        assert (f"ev-{e['cp']}", f"ev-{e['dr']}") in union     # derecha: la carga de PATIENTS
        assert len(union) == 2

    def test_la_cadena_de_la_cohorte_se_recorre_de_la_carga_a_la_exportacion(self, conn):
        e = _sembrar_cohorte(conn)
        g = build_lineage_graph(conn, dataset_nombre="merge(ADMISSIONS.csv,PATIENTS.csv)")
        alcanzables, pendientes = {f"ev-{e['ca']}"}, [f"ev-{e['ca']}"]
        while pendientes:
            actual = pendientes.pop()
            for a in g["edges"]:
                if a["source"] == actual and a["target"] not in alcanzables:
                    alcanzables.add(a["target"])
                    pendientes.append(a["target"])
        assert f"ev-{e['ex']}" in alcanzables
        assert any(n["tipo"] == "archivo" and n["label"] == "reporte.csv" for n in g["nodes"] if n["id"] in alcanzables)

    def test_se_llega_al_mismo_grafo_desde_una_entrada_o_desde_un_evento(self, conn):
        e = _sembrar_cohorte(conn)
        desde_entrada = build_lineage_graph(conn, dataset_nombre="ADMISSIONS.csv")
        desde_evento = build_lineage_graph(conn, event_id=e["ex"])
        for g in (desde_entrada, desde_evento):
            assert {n["event_id"] for n in g["nodes"] if n.get("event_id")} >= set(e.values())
            assert len(_aristas(g, "union")) == 2

    def test_las_posiciones_ubican_el_resultado_despues_de_las_entradas(self, conn):
        e = _sembrar_cohorte(conn)
        g = build_lineage_graph(conn, dataset_nombre="merge(ADMISSIONS.csv,PATIENTS.csv)")
        assert _nodo(g, e["dr"])["position"]["x"] > _nodo(g, e["mg"])["position"]["x"]

    def test_sesiones_distintas_no_se_unen(self, conn):
        e1 = _sembrar_cohorte(conn, "s-1")
        # misma unión pero la entrada PATIENTS solo existe en otra sesión
        e2 = _ev(conn, sesion_id="s-2", tipo_accion="CARGA", dataset_nombre="PATIENTS.csv", timestamp="2026-11-21T11:00:00")
        g = build_lineage_graph(conn, event_id=e1["ex"])
        assert e2 not in {n.get("event_id") for n in g["nodes"]}

    def test_una_union_con_entrada_de_otra_sesion_no_inventa_aristas(self, conn):
        _ev(conn, sesion_id="s-a", tipo_accion="CARGA", dataset_nombre="ADMISSIONS.csv", timestamp="2026-11-21T10:00:00")
        dr = _ev(conn, sesion_id="s-b", tipo_accion="TRANSFORMACION", dataset_nombre="merge(ADMISSIONS.csv,PATIENTS.csv)",
                 motivo_fallo="[ELIMINACION_COLS] drop()", timestamp="2026-11-21T10:03:00")
        g = build_lineage_graph(conn, event_id=dr)
        assert _aristas(g, "union") == set()

    def test_datasets_sin_uniones_no_cambian(self, conn):
        ids = _sembrar_flujo_completo(conn)
        g = build_lineage_graph(conn, dataset_nombre="vitals.csv")
        assert _aristas(g, "union") == set() and len(g["nodes"]) == 6  # 5 eventos + archivo
