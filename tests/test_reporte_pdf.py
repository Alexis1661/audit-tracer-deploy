"""
tests/test_reporte_pdf.py
=========================
Resultado esperado 3 — exportación del reporte de auditoría en PDF.

El PDF debe tener el mismo contenido que el CSV de /reportes/exportar:
mismos filtros, mismas filas, mismas columnas y la misma referencia
normativa por evento (HU-4.5 / HU-7.3); y el mismo control de acceso.
"""

import csv
import io

import pytest
from pypdf import PdfReader

from conftest import crear_sesion_web

import app as app_module
from audit_tracer.db import get_central_connection
from audit_tracer.models.audit_log import NO_RESULTS_MESSAGE, insert_event
from audit_tracer.normative_mapping import SIN_REFERENCIA_NORMATIVA, referencia_normativa
from audit_tracer.reporte_pdf import ENCABEZADOS, TITULO, construir_reporte_pdf


def _evento(conn, tipo_accion, **extra):
    datos = {"usuario_id": "cientifica_pdf", "sesion_id": "s-pdf", "tipo_accion": tipo_accion,
             "dataset_nombre": "ADMISSIONS.csv", "nivel_alerta": "NORMAL"}
    datos.update(extra)
    return insert_event(conn, datos)


@pytest.fixture
def central_db(tmp_path, monkeypatch):
    db_file = str(tmp_path / "audit_central.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_file))
    conn = get_central_connection(db_file)
    _evento(conn, "CARGA", timestamp="2026-11-10T15:00:00", columnas_afectadas='["subject_id", "hadm_id"]')
    _evento(conn, "TRANSFORMACION", timestamp="2026-11-10T15:05:00")
    _evento(conn, "EXPORTACION", timestamp="2026-11-10T15:10:00", filas_exportadas=2174,
            nivel_alerta="CRITICO", ruta_destino="anexo.csv")
    _evento(conn, "MODELADO", timestamp="2026-11-11T15:00:00")
    _evento(conn, "CARGA", usuario_id="otro_usuario", timestamp="2026-11-11T16:00:00")
    conn.close()


def _cliente(rol="AUDITOR"):
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    crear_sesion_web(client, "auditor_pdf", rol, "Auditora PDF", "s-web-pdf")
    return client


def _texto_pdf(datos: bytes) -> str:
    lector = PdfReader(io.BytesIO(datos))
    return "\n".join(p.extract_text() for p in lector.pages)


def _csv(client, query=""):
    resp = client.get(f"/reportes/exportar{query}")
    return list(csv.DictReader(io.StringIO(resp.get_data(as_text=True))))


def _sin_espacios(texto: str) -> str:
    return "".join(texto.split())


class TestDescargaPDF:

    def test_responde_un_pdf_descargable(self, central_db):
        resp = _cliente().get("/reportes/exportar/pdf")
        assert resp.status_code == 200
        assert resp.mimetype == "application/pdf"
        assert "attachment; filename=reporte_auditoria.pdf" in resp.headers["Content-Disposition"]
        assert resp.data.startswith(b"%PDF")
        assert len(PdfReader(io.BytesIO(resp.data)).pages) >= 1

    def test_mismas_filas_y_referencias_que_el_csv(self, central_db):
        client = _cliente()
        filas_csv = _csv(client)
        texto = _sin_espacios(_texto_pdf(client.get("/reportes/exportar/pdf").data))
        assert len(filas_csv) == 5
        assert "Totaldeeventos:5" in texto
        for fila in filas_csv:
            assert _sin_espacios(fila["referencia_normativa"]) in texto
            assert _sin_espacios(fila["usuario_id"]) in texto
            assert _sin_espacios(fila["timestamp"]) in texto  # mismo formato (hora Colombia)
        assert _sin_espacios(SIN_REFERENCIA_NORMATIVA) in texto  # MODELADO, igual que en el CSV

    def test_mismas_columnas_que_el_csv(self, central_db):
        client = _cliente()
        cabecera_csv = list(csv.reader(io.StringIO(client.get("/reportes/exportar").get_data(as_text=True))))[0]
        assert list(ENCABEZADOS) == cabecera_csv
        texto = _sin_espacios(_texto_pdf(client.get("/reportes/exportar/pdf").data))
        for encabezado in ENCABEZADOS.values():
            assert _sin_espacios(encabezado) in texto

    @pytest.mark.parametrize("query,esperados", [
        ("?reporte_tipo_accion=EXPORTACION", 1),
        ("?reporte_usuario_id=otro_usuario", 1),
        ("?reporte_fecha_inicio=2026-11-10&reporte_fecha_fin=2026-11-10", 3),
        ("?reporte_usuario_id=cientifica_pdf&reporte_tipo_accion=CARGA", 1),
    ])
    def test_respeta_los_mismos_filtros_que_el_csv(self, central_db, query, esperados):
        client = _cliente()
        filas_csv = _csv(client, query)
        assert len(filas_csv) == esperados
        texto = _sin_espacios(_texto_pdf(client.get(f"/reportes/exportar/pdf{query}").data))
        assert f"Totaldeeventos:{esperados}" in texto
        for fila in filas_csv:
            assert _sin_espacios(fila["referencia_normativa"]) in texto

    def test_muestra_los_filtros_aplicados(self, central_db):
        query = "?reporte_tipo_accion=EXPORTACION&reporte_fecha_inicio=2026-11-10"
        texto = _texto_pdf(_cliente().get(f"/reportes/exportar/pdf{query}").data)
        assert "Tipo de acción: EXPORTACION" in texto
        assert "Desde: 2026-11-10" in texto
        assert _sin_espacios(referencia_normativa("EXPORTACION")) in _sin_espacios(texto)

    def test_sin_resultados_es_un_pdf_valido_con_el_mensaje(self, central_db):
        resp = _cliente().get("/reportes/exportar/pdf?reporte_usuario_id=nadie")
        assert resp.status_code == 200
        texto = _texto_pdf(resp.data)
        assert "Total de eventos: 0" in texto
        assert NO_RESULTS_MESSAGE in texto

    def test_incluye_titulo_y_quien_lo_genero(self, central_db):
        texto = _texto_pdf(_cliente().get("/reportes/exportar/pdf").data)
        assert TITULO.split(" — ")[0] in texto
        assert "Auditora PDF (AUDITOR)" in texto

    def test_mismo_control_de_acceso_que_el_csv(self, central_db):
        client = _cliente("CIENTIFICO_DATOS")
        csv_resp = client.get("/reportes/exportar")
        pdf_resp = client.get("/reportes/exportar/pdf")
        assert csv_resp.status_code == pdf_resp.status_code == 403

    def test_sin_sesion_redirige_al_login(self, central_db):
        app_module.app.config["TESTING"] = True
        resp = app_module.app.test_client().get("/reportes/exportar/pdf")
        assert resp.status_code == 302
        assert "/login" in resp.headers["Location"]

    def test_boton_en_la_vista_de_reportes_lleva_los_filtros(self, central_db):
        html = _cliente().get("/reportes?reporte_tipo_accion=CARGA").get_data(as_text=True)
        assert "Exportar Reporte (PDF)" in html
        assert "/reportes/exportar/pdf?reporte_tipo_accion=CARGA" in html


class TestConstruccion:

    def test_escapa_el_marcado_de_los_datos(self):
        pdf = construir_reporte_pdf(
            [{"event_id": 1, "usuario_id": "u<b>", "timestamp": "2026-11-10T15:00:00",
              "tipo_accion": "CARGA", "dataset_nombre": "<script>x</script>.csv",
              "columnas_afectadas": None, "nivel_alerta": "NORMAL",
              "referencia_normativa": referencia_normativa("CARGA")}],
            {}, generado_por="Prueba (ADMIN)", generado_en="2026-11-21 10:00:00")
        texto = _texto_pdf(pdf)
        assert "<script>x</script>.csv" in texto
        assert "u<b>" in texto
        assert "Sin filtros" in texto

    def test_muchas_filas_ocupan_varias_paginas(self):
        filas = [{"event_id": i, "usuario_id": "u", "timestamp": "2026-11-10T15:00:00", "tipo_accion": "CARGA",
                  "dataset_nombre": "LABEVENTS.csv", "columnas_afectadas": '["itemid"]', "nivel_alerta": "NORMAL",
                  "referencia_normativa": referencia_normativa("CARGA")} for i in range(300)]
        pdf = construir_reporte_pdf(filas, {}, generado_por="x", generado_en="y")
        assert len(PdfReader(io.BytesIO(pdf)).pages) > 1
