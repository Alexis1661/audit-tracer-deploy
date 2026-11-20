"""La paginación de /eventos no debe activar el filtro de anomalías por su cuenta."""
import re

import app as app_module
from audit_tracer.db import get_central_connection
from audit_tracer.models.audit_log import insert_event
from conftest import crear_sesion_web


def test_siguiente_pagina_conserva_los_filtros_sin_activar_anomalias(monkeypatch, tmp_path):
    db_path = str(tmp_path / "central.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    conn = get_central_connection(db_path)
    for i in range(15):
        insert_event(conn, {"usuario_id": "u-1", "sesion_id": "s", "tipo_accion": "EXPORTACION",
                            "dataset_nombre": f"d{i}.csv", "timestamp": f"2026-11-20T10:{i:02d}:00",
                            "nivel_alerta": "NORMAL"})
    conn.close()
    app_module.app.config["TESTING"] = True
    with app_module.app.test_client() as client:
        crear_sesion_web(client, "auditor-1", "AUDITOR")
        pagina1 = client.get("/eventos?tipo_accion=EXPORTACION").get_data(as_text=True)
        siguiente = re.search(r'href="(/eventos\?[^"]*page=2[^"]*)"', pagina1).group(1).replace("&amp;", "&")
        assert "solo_anomalias=False" not in siguiente
        pagina2 = client.get(siguiente).get_data(as_text=True)
    assert "No se encontraron registros" not in pagina2
    assert 'id="solo_anomalias" name="solo_anomalias" value="1" checked' not in pagina2
