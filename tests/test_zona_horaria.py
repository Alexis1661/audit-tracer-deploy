"""
tests/test_zona_horaria.py
===========================
Hora de Colombia en la interfaz. Los timestamps se guardan en UTC; el
dashboard, los CSV, los filtros por día y el horario laboral (HU-4.4)
deben trabajar en hora de Colombia (UTC-5).
"""

from datetime import datetime

import pytest

import app as app_module
from audit_tracer.db import get_central_connection
from audit_tracer.models.audit_log import insert_event
from audit_tracer.utils.horario import es_horario_laboral
from audit_tracer.utils.zona_horaria import (
    fin_dia_utc, formatear_fecha, inicio_dia_utc, lote_a_hora_colombia,
)


class TestConversion:
    @pytest.mark.parametrize("utc, colombia", [
        ("2026-10-26T19:05:09.123456", "2026-10-26 14:05:09"),
        ("2026-10-27T03:00:00", "2026-10-26 22:00:00"),          # cruza la medianoche
        ("2026-10-26T19:05:09+00:00", "2026-10-26 14:05:09"),    # con zona explícita
        ("2026-10-26 19:05:09", "2026-10-26 14:05:09"),          # formato de SQLite
        (datetime(2026, 1, 1, 2, 0), "2025-12-31 21:00:00"),     # cruza el año
    ])
    def test_formatea_en_hora_colombia(self, utc, colombia):
        assert formatear_fecha(utc) == colombia

    def test_valores_vacios_o_ilegibles_no_rompen_la_vista(self):
        assert formatear_fecha(None) == "—"
        assert formatear_fecha("") == "—"
        assert formatear_fecha("no-es-fecha") == "no-es-fecha"

    def test_un_dia_de_colombia_en_limites_utc(self):
        assert inicio_dia_utc("2026-10-26") == "2026-10-26T05:00:00.000000"
        assert fin_dia_utc("2026-10-26") == "2026-10-27T04:59:59.999999"

    def test_lote_de_merkle_en_hora_colombia(self):
        assert lote_a_hora_colombia("2026-10-26T19") == "2026-10-26 14:00–14:59"


class TestHorarioLaboral:
    @pytest.mark.parametrize("utc, laboral", [
        (datetime(2026, 10, 26, 19, 0), True),    # 14:00 en Colombia (antes: "fuera de horario")
        (datetime(2026, 10, 26, 13, 0), True),    # 08:00 en Colombia
        (datetime(2026, 10, 26, 12, 59), False),  # 07:59 en Colombia
        (datetime(2026, 10, 26, 23, 0), False),   # 18:00 en Colombia
        (datetime(2026, 10, 27, 2, 0), False),    # 21:00 en Colombia
    ])
    def test_horario_laboral_se_mide_en_hora_colombia(self, utc, laboral):
        assert es_horario_laboral(utc) is laboral


@pytest.fixture
def admin_client(monkeypatch, tmp_path):
    db_path = str(tmp_path / "central_tz.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    app_module.app.config["TESTING"] = True
    conn = get_central_connection(db_path)
    # 21:00 del 26 en Colombia = 02:00 del 27 en UTC.
    insert_event(conn, {"usuario_id": "u-1", "sesion_id": "s-1", "tipo_accion": "CARGA",
                        "dataset_nombre": "nocturno.csv", "timestamp": "2026-10-27T02:00:00"})
    conn.close()
    with app_module.app.test_client() as client:
        with client.session_transaction() as sess:
            sess.update(usuario_id="admin", rol="ADMIN", nombre="Admin", sesion_id="s")
        yield client


class TestDashboard:
    def test_eventos_muestra_hora_colombia(self, admin_client):
        html = admin_client.get("/eventos").get_data(as_text=True)
        assert "2026-10-26 21:00:00" in html
        assert "2026-10-27 02:00:00" not in html

    def test_filtro_por_dia_usa_el_dia_de_colombia(self, admin_client):
        del_26 = admin_client.get("/eventos?fecha_inicio=2026-10-26&fecha_fin=2026-10-26").get_data(as_text=True)
        del_27 = admin_client.get("/eventos?fecha_inicio=2026-10-27&fecha_fin=2026-10-27").get_data(as_text=True)
        assert "2026-10-26 21:00:00" in del_26
        assert "2026-10-26 21:00:00" not in del_27

    def test_csv_del_reporte_en_hora_colombia(self, admin_client):
        csv = admin_client.get("/reportes/exportar").get_data(as_text=True)
        assert "2026-10-26 21:00:00" in csv
