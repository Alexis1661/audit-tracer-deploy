"""Los filtros de usuario del dashboard aceptan el ID o el correo de la cuenta."""
import csv
import io

import pytest

import app as app_module
from audit_tracer.db import get_central_connection
from audit_tracer.models.audit_log import insert_event
from conftest import crear_sesion_web


@pytest.fixture
def cliente(monkeypatch, tmp_path):
    db_path = str(tmp_path / "central.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    conn = get_central_connection(db_path)
    conn.execute("INSERT INTO usuarios (usuario_id, email, password_hash, rol) VALUES "
                 "('11111111-aaaa', 'Ana.Perez@Hospital.org', 'x', 'CIENTIFICO_DATOS')")
    conn.commit()
    insert_event(conn, {"usuario_id": "11111111-aaaa", "sesion_id": "s", "tipo_accion": "CARGA",
                        "dataset_nombre": "de_ana.csv", "nivel_alerta": "CRITICO", "motivo_alerta": "x"})
    insert_event(conn, {"usuario_id": "22222222-bbbb", "sesion_id": "s", "tipo_accion": "CARGA",
                        "dataset_nombre": "de_otro.csv", "nivel_alerta": "CRITICO", "motivo_alerta": "x"})
    conn.close()
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as c:
        crear_sesion_web(c, "auditor-1", "AUDITOR")
        yield c


@pytest.mark.parametrize("valor", ["11111111-aaaa", "Ana.Perez@Hospital.org", "ana.perez@hospital.org"])
def test_eventos_filtra_por_id_o_correo(cliente, valor):
    html = cliente.get(f"/eventos?usuario_id={valor}").get_data(as_text=True)
    assert "11111111..." in html and "22222222..." not in html


def test_eventos_conserva_lo_que_escribio_el_usuario_en_el_campo(cliente):
    html = cliente.get("/eventos?usuario_id=ana.perez@hospital.org").get_data(as_text=True)
    assert 'value="ana.perez@hospital.org"' in html


def test_correo_inexistente_no_devuelve_eventos(cliente):
    html = cliente.get("/eventos?usuario_id=nadie@x.co").get_data(as_text=True)
    assert "11111111..." not in html and "22222222..." not in html


@pytest.mark.parametrize("ruta", ["/reportes/exportar", "/eventos/criticos/exportar"])
def test_exportaciones_csv_aceptan_correo(cliente, ruta):
    clave = "reporte_usuario_id" if ruta == "/reportes/exportar" else "usuario_id"
    texto = cliente.get(f"{ruta}?{clave}=ana.perez@hospital.org").get_data(as_text=True)
    filas = list(csv.DictReader(io.StringIO(texto)))
    assert {f["usuario_id"] for f in filas} == {"11111111-aaaa"}


def test_reporte_en_pantalla_y_pdf_aceptan_correo(cliente):
    html = cliente.get("/reportes?reporte_usuario_id=ana.perez@hospital.org").get_data(as_text=True)
    assert "11111111-aaaa" in html and "22222222-bbbb" not in html
    pdf = cliente.get("/reportes/exportar/pdf?reporte_usuario_id=ana.perez@hospital.org")
    assert pdf.status_code == 200 and pdf.data.startswith(b"%PDF")
    from pypdf import PdfReader
    texto = "".join(p.extract_text() for p in PdfReader(io.BytesIO(pdf.data)).pages)
    assert "Total de eventos: 1" in texto
