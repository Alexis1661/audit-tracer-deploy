"""
tests/test_mapeo_normativo.py
=============================
Pruebas para HU-7.3 — Reportes con mapeo normativo explícito.

Criterios de Aceptación:
CA1: Cada tipo de evento tiene asociada una o más referencias normativas
     (p. ej. HIPAA §164.312(b), Ley 1581).
CA2: El reporte exportable (extiende HU-4.5) incluye una columna adicional
     con la referencia normativa de cada evento.
CA3: Si un evento no tiene referencia normativa asociada, el reporte lo
     indica explícitamente en lugar de dejarlo vacío.

DoD: se valida con al menos un caso de cada tipo de evento
     (acceso, transformación, exportación).
"""

import csv
import io
from pathlib import Path

from conftest import crear_sesion_web
import pytest

import app as app_module
from audit_tracer.db import get_central_connection, get_connection
from audit_tracer.models.audit_log import (
    REPORT_CSV_COLUMNS,
    export_report_to_csv,
    generate_report,
    insert_event,
)
from audit_tracer.normative_mapping import (
    MAPEO_NORMATIVO,
    SIN_REFERENCIA_NORMATIVA,
    obtener_mapeo,
    referencia_normativa,
)

RAIZ = Path(__file__).resolve().parent.parent
MATRIZ_CSV = RAIZ / "docs" / "matriz_trazabilidad_normativa.csv"


def _lista(celda):
    return [p.strip() for p in celda.split(";") if p.strip()]


def _mapeo_desde_matriz():
    """Deriva tipo_accion → cláusulas a partir de la matriz de HU-6.6."""
    mapeo = {}
    with open(MATRIZ_CSV, encoding="utf-8", newline="") as f:
        for fila in csv.DictReader(f):
            for evento in _lista(fila["eventos_audit_log"]):
                # "INTENTO_MODIFICACION (tabla audit_intentos_bloqueados)" → "INTENTO_MODIFICACION"
                tipo = evento.split(" (")[0].strip()
                d = mapeo.setdefault(tipo, {"hipaa": set(), "ley_1581": set(), "controles": set()})
                d["hipaa"].update(_lista(fila["hipaa"]))
                d["ley_1581"].update(_lista(fila["ley_1581"]))
                d["controles"].add(fila["id"])
    return mapeo


@pytest.fixture
def db_conn():
    conn = get_connection(":memory:")
    yield conn
    conn.close()


def _evento(conn, tipo_accion, **extra):
    datos = {
        "usuario_id": "auditor_ext",
        "sesion_id": "s-7.3",
        "tipo_accion": tipo_accion,
        "dataset_nombre": "PACIENTES.csv",
        "nivel_alerta": "NORMAL",
    }
    datos.update(extra)
    return insert_event(conn, datos)


# ──────────────────────────────────────────────────────────────
# CA1 — Tabla de mapeo tipo_evento → referencia normativa
# ──────────────────────────────────────────────────────────────

class TestCA1TablaDeMapeo:

    @pytest.mark.parametrize("tipo", sorted(MAPEO_NORMATIVO))
    def test_cada_tipo_tiene_al_menos_una_referencia_hipaa_y_ley_1581(self, tipo):
        mapeo = MAPEO_NORMATIVO[tipo]
        assert mapeo["hipaa"], f"{tipo}: sin cláusula HIPAA"
        assert mapeo["ley_1581"], f"{tipo}: sin artículo de la Ley 1581"
        assert all(c.startswith("§164.") for c in mapeo["hipaa"])
        assert all(c.startswith("Art. ") for c in mapeo["ley_1581"])
        assert mapeo["controles"], f"{tipo}: sin control de la matriz HU-6.6"

    def test_tabla_coincide_exactamente_con_la_matriz_hu_6_6(self):
        """DoR: el mapeo reutiliza la matriz. Si alguien cambia una sin la otra, falla."""
        esperado = _mapeo_desde_matriz()
        assert set(MAPEO_NORMATIVO) == set(esperado)
        for tipo, mapeo in MAPEO_NORMATIVO.items():
            assert set(mapeo["hipaa"]) == esperado[tipo]["hipaa"], tipo
            assert set(mapeo["ley_1581"]) == esperado[tipo]["ley_1581"], tipo
            assert set(mapeo["controles"]) == esperado[tipo]["controles"], tipo

    def test_tabla_sin_cláusulas_repetidas_por_tipo(self):
        for tipo, mapeo in MAPEO_NORMATIVO.items():
            for campo in ("hipaa", "ley_1581", "controles"):
                assert len(mapeo[campo]) == len(set(mapeo[campo])), f"{tipo}.{campo}"

    @pytest.mark.parametrize("tipo", ["CARGA", "CONSULTA", "TRANSFORMACION", "EXPORTACION"])
    def test_eventos_de_datos_clinicos_citan_el_control_de_auditoria_164_312_b(self, tipo):
        """Acceso, transformación y exportación son actividad que §164.312(b) exige registrar."""
        assert "§164.312(b)" in MAPEO_NORMATIVO[tipo]["hipaa"]
        assert "Art. 17 lit. m" in MAPEO_NORMATIVO[tipo]["ley_1581"]

    def test_obtener_mapeo_normaliza_mayusculas_y_espacios(self):
        assert obtener_mapeo(" exportacion ") is MAPEO_NORMATIVO["EXPORTACION"]

    @pytest.mark.parametrize("tipo", [None, "", "MODELADO", "TIPO_INVENTADO"])
    def test_obtener_mapeo_de_tipo_sin_referencia_es_none(self, tipo):
        assert obtener_mapeo(tipo) is None


# ──────────────────────────────────────────────────────────────
# CA2/CA3 — Texto de la columna referencia_normativa
# ──────────────────────────────────────────────────────────────

class TestTextoReferencia:

    def test_formato_incluye_hipaa_ley_1581_y_control_de_la_matriz(self):
        assert referencia_normativa("TRANSFORMACION") == (
            "HIPAA §164.312(b); §164.312(c)(1) | "
            "Ley 1581 Art. 4 lit. d; Art. 17 lit. m | "
            "Matriz CT-13"
        )

    def test_texto_no_rompe_el_separador_de_columnas_del_csv(self):
        """El texto usa ';' y '|' (no ','), igual que la matriz, para leerse limpio en Excel."""
        for tipo in MAPEO_NORMATIVO:
            assert "," not in referencia_normativa(tipo)

    @pytest.mark.parametrize("tipo", [None, "", "MODELADO", "MODELADO_FALLIDO", "TIPO_INVENTADO"])
    def test_ca3_sin_referencia_devuelve_texto_explicito(self, tipo):
        texto = referencia_normativa(tipo)
        assert texto == SIN_REFERENCIA_NORMATIVA
        assert texto.strip()


# ──────────────────────────────────────────────────────────────
# CA2/CA3 + DoD — generación del reporte (extiende HU-4.5)
# ──────────────────────────────────────────────────────────────

class TestGeneracionReporte:

    @pytest.fixture
    def eventos_dod(self, db_conn):
        """Un caso de cada tipo exigido por el DoD + uno sin mapeo (CA3)."""
        _evento(db_conn, "CARGA", timestamp="2026-10-01T08:00:00")           # acceso
        _evento(db_conn, "CONSULTA", timestamp="2026-10-01T09:00:00")        # acceso
        _evento(db_conn, "TRANSFORMACION", timestamp="2026-10-01T10:00:00",
                columnas_afectadas='["diagnostico"]')
        _evento(db_conn, "EXPORTACION", timestamp="2026-10-01T11:00:00",
                ruta_destino="/tmp/salida.csv", filas_exportadas=120)
        _evento(db_conn, "MODELADO", timestamp="2026-10-01T12:00:00")        # sin mapeo
        return db_conn

    def test_ca2_columna_referencia_normativa_es_parte_del_reporte(self):
        assert REPORT_CSV_COLUMNS[-1] == "referencia_normativa"
        assert REPORT_CSV_COLUMNS[:7] == [
            "event_id", "usuario_id", "timestamp", "tipo_accion",
            "dataset_nombre", "columnas_afectadas", "nivel_alerta",
        ]

    @pytest.mark.parametrize("tipo, clausula_hipaa, articulo_ley", [
        ("CARGA", "§164.312(b)", "Art. 17 lit. m"),
        ("CONSULTA", "§164.312(b)", "Art. 17 lit. m"),
        ("TRANSFORMACION", "§164.312(c)(1)", "Art. 4 lit. d"),
        ("EXPORTACION", "§164.308(a)(1)(ii)(D)", "Art. 4 lit. f"),
    ])
    def test_dod_cada_tipo_de_evento_trae_su_clausula(self, eventos_dod, tipo, clausula_hipaa, articulo_ley):
        (fila,) = generate_report(eventos_dod, tipo_accion=tipo)
        ref = fila["referencia_normativa"]
        assert ref == referencia_normativa(tipo)
        assert "HIPAA" in ref and clausula_hipaa in ref
        assert "Ley 1581" in ref and articulo_ley in ref

    def test_ca3_evento_sin_mapeo_se_marca_explicitamente(self, eventos_dod):
        (fila,) = generate_report(eventos_dod, tipo_accion="MODELADO")
        assert fila["referencia_normativa"] == SIN_REFERENCIA_NORMATIVA

    def test_ninguna_fila_del_reporte_queda_sin_referencia(self, eventos_dod):
        reporte = generate_report(eventos_dod)
        assert len(reporte) == 5
        assert all(f["referencia_normativa"] for f in reporte)

    def test_mapeo_no_altera_filtros_ni_orden_de_hu_4_5(self, eventos_dod):
        reporte = generate_report(eventos_dod, fecha_inicio="2026-10-01T09:30:00")
        assert [f["tipo_accion"] for f in reporte] == ["TRANSFORMACION", "EXPORTACION", "MODELADO"]

    def test_referencia_no_se_guarda_en_audit_log_ni_cambia_el_hash(self, eventos_dod):
        """La columna se calcula al reportar: audit_log y su hash_integridad quedan intactos."""
        columnas = {r[1] for r in eventos_dod.execute("PRAGMA table_info(audit_log)")}
        assert "referencia_normativa" not in columnas


# ──────────────────────────────────────────────────────────────
# CA2/CA3 — exportación CSV
# ──────────────────────────────────────────────────────────────

class TestExportacionCsv:

    @pytest.fixture
    def eventos(self, db_conn):
        _evento(db_conn, "CONSULTA", timestamp="2026-10-02T08:00:00")
        _evento(db_conn, "TRANSFORMACION", timestamp="2026-10-02T09:00:00")
        _evento(db_conn, "EXPORTACION", timestamp="2026-10-02T10:00:00")
        _evento(db_conn, "MODELADO_FALLIDO", timestamp="2026-10-02T11:00:00")
        return db_conn

    def test_ca2_csv_incluye_columna_y_valor_por_evento(self, eventos, tmp_path):
        dest = tmp_path / "reporte_normativo.csv"
        assert export_report_to_csv(eventos, str(dest)) == 4

        with open(dest, encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames == REPORT_CSV_COLUMNS
            filas = list(reader)

        por_tipo = {f["tipo_accion"]: f["referencia_normativa"] for f in filas}
        assert por_tipo["CONSULTA"] == referencia_normativa("CONSULTA")
        assert por_tipo["TRANSFORMACION"] == referencia_normativa("TRANSFORMACION")
        assert por_tipo["EXPORTACION"] == referencia_normativa("EXPORTACION")
        assert "§164.528 (apoyo)" in por_tipo["EXPORTACION"]

    def test_ca3_csv_no_deja_la_celda_vacia(self, eventos):
        buffer = io.StringIO()
        export_report_to_csv(eventos, buffer)
        buffer.seek(0)
        filas = list(csv.DictReader(buffer))
        assert all(f["referencia_normativa"].strip() for f in filas)
        (sin_mapeo,) = [f for f in filas if f["tipo_accion"] == "MODELADO_FALLIDO"]
        assert sin_mapeo["referencia_normativa"] == SIN_REFERENCIA_NORMATIVA

    def test_caracter_seccion_sobrevive_el_round_trip_utf8(self, eventos, tmp_path):
        dest = tmp_path / "reporte_utf8.csv"
        export_report_to_csv(eventos, str(dest), tipo_accion="CONSULTA")
        texto = dest.read_text(encoding="utf-8")
        assert "HIPAA §164.312(b)" in texto


# ──────────────────────────────────────────────────────────────
# Integración — rutas del dashboard (vista y descarga)
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def central_db(tmp_path, monkeypatch):
    """Base central aislada: las rutas no tocan audit_central.db real."""
    db_file = str(tmp_path / "audit_central.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_file))
    conn = get_central_connection(db_file)
    _evento(conn, "CONSULTA", timestamp="2026-10-03T08:00:00")
    _evento(conn, "TRANSFORMACION", timestamp="2026-10-03T09:00:00")
    _evento(conn, "EXPORTACION", timestamp="2026-10-03T10:00:00")
    _evento(conn, "MODELADO", timestamp="2026-10-03T11:00:00")
    conn.close()


def _cliente(rol="AUDITOR"):
    app_module.app.config["TESTING"] = True
    client = app_module.app.test_client()
    crear_sesion_web(client, "auditor_ext", rol, "Auditor Externo", "s-web-7.3")
    return client


class TestRutasDashboard:

    def test_descarga_csv_incluye_referencia_normativa(self, central_db):
        resp = _cliente().get("/reportes/exportar")
        assert resp.status_code == 200
        assert resp.mimetype == "text/csv"

        filas = list(csv.DictReader(io.StringIO(resp.get_data(as_text=True))))
        assert len(filas) == 4
        por_tipo = {f["tipo_accion"]: f["referencia_normativa"] for f in filas}
        for tipo in ("CONSULTA", "TRANSFORMACION", "EXPORTACION"):
            assert por_tipo[tipo] == referencia_normativa(tipo)
        assert por_tipo["MODELADO"] == SIN_REFERENCIA_NORMATIVA

    def test_descarga_csv_respeta_filtros(self, central_db):
        resp = _cliente().get("/reportes/exportar?reporte_tipo_accion=EXPORTACION")
        filas = list(csv.DictReader(io.StringIO(resp.get_data(as_text=True))))
        assert [f["tipo_accion"] for f in filas] == ["EXPORTACION"]
        assert filas[0]["referencia_normativa"] == referencia_normativa("EXPORTACION")

    def test_vista_reportes_muestra_la_columna(self, central_db):
        resp = _cliente().get("/reportes")
        html = resp.get_data(as_text=True)
        assert resp.status_code == 200
        assert "Referencia Normativa" in html
        assert "HIPAA §164.312(b); §164.312(c)(1)" in html  # TRANSFORMACION
        assert "referencia-normativa--ausente" in html       # MODELADO (CA3)
        assert SIN_REFERENCIA_NORMATIVA in html

    def test_vista_sin_resultados_ocupa_las_ocho_columnas(self, central_db):
        resp = _cliente().get("/reportes?reporte_usuario_id=nadie")
        assert 'colspan="8"' in resp.get_data(as_text=True)
