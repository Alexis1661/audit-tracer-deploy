"""
tests/test_detalle_evento.py
==============================
Pruebas unitarias e integración para:
  - HU-4.3: Visualización de detalle de evento.
  - HU-7.4: Mejoras explicativas del detalle del evento (contexto de usuario,
            narrativa en lenguaje natural, diagnóstico de severidad,
            recomendaciones accionables y resumen forense copiable).
"""

import pytest
from audit_tracer.db import get_connection, get_central_connection
from audit_tracer.models.audit_log import insert_event, get_event_by_id
from audit_tracer.models.usuarios import create_user
from audit_tracer.event_explainer import (
    resolve_user_info,
    generate_event_explanation,
    generate_alert_diagnosis,
    generate_recommendations,
    generate_copyable_summary,
    enrich_event_detail,
)
from app import app


@pytest.fixture
def db_conn():
    """Conexión SQLite en memoria aislada para pruebas."""
    conn = get_connection(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def flask_client():
    """Cliente de pruebas HTTP para Flask."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['usuario_id'] = 'analista_002'
            sess['rol'] = 'ANALISTA'
            sess['nombre'] = 'Analista Test'
            sess['sesion_id'] = 's_test_403'
        yield client


# ============================================================================
# HU-4.3 — Pruebas Base de Consulta de Evento
# ============================================================================

class TestVisualizacionDetalleEvento:
    """Pruebas unitarias para los criterios de aceptación CA1 a CA4 de HU-4.3."""

    def test_get_event_by_id_retorna_evento_correcto(self, db_conn):
        """CA1, CA3: Verifica que get_event_by_id consulte el evento exacto por su event_id."""
        event_id_1 = insert_event(db_conn, {
            'usuario_id': 'u1',
            'sesion_id': 's1',
            'tipo_accion': 'CARGA',
            'dataset_nombre': 'PATIENTS.csv',
            'nivel_alerta': 'NORMAL'
        })
        event_id_2 = insert_event(db_conn, {
            'usuario_id': 'u2',
            'sesion_id': 's2',
            'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'admissions.xlsx',
            'nivel_alerta': 'CRITICO'
        })

        evento = get_event_by_id(db_conn, event_id_2)

        assert evento is not None
        assert evento['event_id'] == event_id_2
        assert evento['usuario_id'] == 'u2'
        assert evento['tipo_accion'] == 'EXPORTACION'
        assert evento['dataset_nombre'] == 'admissions.xlsx'
        assert evento['nivel_alerta'] == 'CRITICO'

    def test_get_event_by_id_inexistente_retorna_none(self, db_conn):
        """Verifica que se retorne None cuando el event_id no existe en la base de datos."""
        evento = get_event_by_id(db_conn, 99999)
        assert evento is None

    def test_get_event_by_id_incluye_todos_los_campos_requeridos(self, db_conn):
        """CA2: Verifica que el evento retornado contenga la totalidad de los campos del esquema."""
        event_id = insert_event(db_conn, {
            'usuario_id': 'u_analista',
            'sesion_id': 'sesion_full_001',
            'timestamp': '2026-08-24T12:00:00',
            'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'LABS.csv',
            'columnas_afectadas': '["subject_id", "valuenum"]',
            'ruta_destino': 'outputs/labs.csv',
            'filas_exportadas': 500,
            'sobrescritura': 1,
            'contexto_ejecucion': 'Script: export.py | Env: dev',
            'motivo_fallo': None,
            'nivel_alerta': 'ADVERTENCIA',
            'motivo_alerta': 'Sobrescritura de archivo'
        })

        evento = get_event_by_id(db_conn, event_id)

        campos_esperados = [
            'event_id', 'usuario_id', 'sesion_id', 'timestamp', 'tipo_accion',
            'dataset_nombre', 'columnas_afectadas', 'ruta_destino', 'filas_exportadas',
            'sobrescritura', 'contexto_ejecucion', 'motivo_fallo', 'nivel_alerta',
            'motivo_alerta', 'hash_integridad'
        ]

        for campo in campos_esperados:
            assert campo in evento, f"El campo {campo} debe estar presente en el detalle del evento"

        assert evento['usuario_id'] == 'u_analista'
        assert evento['sesion_id'] == 'sesion_full_001'
        assert evento['tipo_accion'] == 'EXPORTACION'
        assert evento['dataset_nombre'] == 'LABS.csv'
        assert evento['filas_exportadas'] == 500
        assert evento['hash_integridad'] is not None
        assert len(evento['hash_integridad']) == 64

    def test_get_event_by_id_soporta_campos_opcionales_nulos(self, db_conn):
        """CA4: Verifica que se pueda recuperar y consultar un evento con campos opcionales nulos/vacíos."""
        event_id = insert_event(db_conn, {
            'usuario_id': 'u_minimo',
            'sesion_id': 's_minimo',
            'tipo_accion': 'INICIO_SESION',
            'nivel_alerta': 'NORMAL'
        })

        evento = get_event_by_id(db_conn, event_id)

        assert evento is not None
        assert evento['event_id'] == event_id
        assert evento['dataset_nombre'] is None
        assert evento['columnas_afectadas'] is None
        assert evento['ruta_destino'] is None
        assert evento['motivo_fallo'] is None
        assert evento['motivo_alerta'] is None


# ============================================================================
# HU-7.4 — Pruebas de Enriquecimiento Explicativo y Contextual
# ============================================================================

class TestResolucionUsuarioInfo:
    """HU-7.4 CA1: Pruebas de resolución de identidad y perfil de usuario."""

    def test_resuelve_usuario_registrado_por_uuid(self, db_conn):
        user_id = create_user(db_conn, "analista.garcia@audit.com", "Secret123*", "ANALISTA")
        info = resolve_user_info(db_conn, user_id)

        assert info["es_desconocido"] is False
        assert info["email"] == "analista.garcia@audit.com"
        assert info["rol"] == "ANALISTA"
        assert "Analista" in info["nombre"]
        assert info["activo"] is True

    def test_resuelve_usuario_por_email_directo(self, db_conn):
        user_id = create_user(db_conn, "auditor.perez@audit.com", "Secret123*", "AUDITOR")
        info = resolve_user_info(db_conn, "auditor.perez@audit.com")

        assert info["es_desconocido"] is False
        assert info["email"] == "auditor.perez@audit.com"
        assert info["rol"] == "AUDITOR"

    def test_resuelve_usuario_desconocido_o_anonimo(self, db_conn):
        info_desconocido = resolve_user_info(db_conn, "DESCONOCIDO")
        assert info_desconocido["es_desconocido"] is True
        assert info_desconocido["nombre"] == "Usuario No Identificado"
        assert info_desconocido["rol"] == "DESCONOCIDO"

        info_none = resolve_user_info(db_conn, None)
        assert info_none["es_desconocido"] is True

    def test_resuelve_usuario_sistema(self, db_conn):
        info_sys = resolve_user_info(db_conn, "SISTEMA")
        assert info_sys["es_sistema"] is True
        assert info_sys["rol"] == "SISTEMA"


class TestGeneracionExplicaciones:
    """HU-7.4 CA2: Pruebas de generación de narrativa en lenguaje claro."""

    def test_explicacion_carga_datos(self):
        evento = {
            "tipo_accion": "CARGA",
            "dataset_nombre": "PATIENTS.csv",
            "columnas_afectadas": '["id", "nombre", "diagnostico"]',
            "contexto_ejecucion": "Script: load.py | Env: Jupyter"
        }
        user_info = {"nombre": "Analista García", "rol": "ANALISTA"}
        exp = generate_event_explanation(evento, user_info)

        assert "Carga inicial" in exp["titulo"]
        assert "Analista García" in exp["descripcion"]
        assert "PATIENTS.csv" in exp["descripcion"]
        assert "Jupyter" in exp["entorno_desc"]

    def test_explicacion_exportacion_con_filas_y_ruta(self):
        evento = {
            "tipo_accion": "EXPORTACION",
            "dataset_nombre": "admissions.xlsx",
            "filas_exportadas": 4500,
            "ruta_destino": "outputs/admissions_full.xlsx",
            "sobrescritura": 1,
        }
        user_info = {"nombre": "Científico López", "rol": "CIENTIFICO_DATOS"}
        exp = generate_event_explanation(evento, user_info)

        assert "Exportación de datos" in exp["titulo"]
        assert "4500 registros" in exp["descripcion"]
        assert "outputs/admissions_full.xlsx" in exp["descripcion"]
        assert "sobrescritura" in exp["descripcion"]

    def test_explicacion_acceso_fallido(self):
        evento = {
            "tipo_accion": "ACCESO_FALLIDO",
            "dataset_nombre": "archivo_inexistente_3.csv",
            "motivo_fallo": "archivo no existe",
        }
        user_info = {"nombre": "Analista García", "rol": "ANALISTA"}
        exp = generate_event_explanation(evento, user_info)

        assert "Intento fallido de acceso" in exp["titulo"]
        assert "archivo_inexistente_3.csv" in exp["descripcion"]
        assert "archivo no existe" in exp["descripcion"]


class TestDiagnosticoYRecomendaciones:
    """HU-7.4 CA3 y CA4: Pruebas de diagnóstico de severidad y recomendaciones."""

    def test_diagnostico_evento_critico_exportacion_masiva(self):
        evento = {
            "tipo_accion": "EXPORTACION",
            "nivel_alerta": "CRITICO",
            "motivo_alerta": "Exportación masiva: 4500 filas (> 1000)",
            "filas_exportadas": 4500,
            "ruta_destino": "outputs/export.csv"
        }
        user_info = {"nombre": "Analista García", "email": "analista.garcia@audit.com"}
        diag = generate_alert_diagnosis(evento)
        recs = generate_recommendations(evento, user_info, diag)

        assert diag["es_critico"] is True
        assert diag["es_alerta"] is True
        assert "exfiltración masiva" in diag["impacto"]
        assert len(recs) >= 2
        assert any(r["tipo"] == "urgente" for r in recs)
        assert any("autorización" in r["titulo"].lower() for r in recs)

    def test_diagnostico_evento_critico_accesos_fallidos(self):
        evento = {
            "tipo_accion": "ACCESO_FALLIDO",
            "nivel_alerta": "CRITICO",
            "motivo_alerta": "5 intentos fallidos en menos de 5 minutos",
            "dataset_nombre": "pacientes_oncologia.csv"
        }
        user_info = {"nombre": "Usuario Externo", "email": "externo@audit.com"}
        diag = generate_alert_diagnosis(evento)
        recs = generate_recommendations(evento, user_info, diag)

        assert diag["es_critico"] is True
        assert "fuerza bruta" in diag["impacto"].lower() or "escaneo" in diag["impacto"].lower()
        assert len(recs) >= 2
        assert any("intrusión" in r["titulo"].lower() for r in recs)

    def test_diagnostico_evento_normal(self):
        evento = {
            "tipo_accion": "CONSULTA",
            "nivel_alerta": "NORMAL",
            "dataset_nombre": "labs.csv"
        }
        user_info = {"nombre": "Auditor Pérez", "email": "auditor@audit.com"}
        diag = generate_alert_diagnosis(evento)
        recs = generate_recommendations(evento, user_info, diag)

        assert diag["es_critico"] is False
        assert diag["es_alerta"] is False
        assert len(recs) >= 1
        assert any(r["tipo"] in ("info", "mejora") for r in recs)

    def test_resumen_copiable_formato(self):
        evento = {
            "event_id": 42,
            "timestamp": "2026-10-01T20:00:00",
            "tipo_accion": "CARGA",
            "dataset_nombre": "PATIENTS.csv",
            "hash_integridad": "a1b2c3d4" * 8
        }
        user_info = {"nombre": "Analista Test", "email": "test@audit.com", "rol": "ANALISTA"}
        explicacion = {"descripcion": "Carga de prueba"}
        diagnostico = {"nivel": "NORMAL", "impacto": "Operación estándar"}

        resumen = generate_copyable_summary(evento, user_info, explicacion, diagnostico)
        assert "REPORTE DE AUDITORÍA CLÍNICA — EVENTO #42" in resumen
        assert "Analista Test" in resumen
        assert "PATIENTS.csv" in resumen
        assert "Hash SHA-256" in resumen


# ============================================================================
# Pruebas de Integración con Flask UI
# ============================================================================

class TestVistaFrontendDetalleEvento:
    """Pruebas de integración de la interfaz web para /eventos/<event_id>."""

    def test_endpoint_detalle_evento_existente_status_200(self, flask_client):
        """Verifica que al consultar /eventos/<event_id> responda 200 OK con el contenido enriquecido."""
        conn = get_central_connection()
        user_id = create_user(conn, f"doctor_{insert_event(conn, {'tipo_accion':'INICIO_SESION', 'usuario_id':'s'})}@audit.com", "Secret123*", "ANALISTA")
        event_id = insert_event(conn, {
            'usuario_id': user_id,
            'sesion_id': 's_web_test_enriched',
            'tipo_accion': 'CARGA',
            'dataset_nombre': 'WEB_TEST_ENRICHED.csv',
            'nivel_alerta': 'NORMAL',
            'contexto_ejecucion': 'Script: notebook.py | Env: Jupyter'
        })
        conn.close()

        response = flask_client.get(f'/eventos/{event_id}')
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        # Verificaciones HU-4.3
        assert f'Detalle del Evento #{event_id}' in html
        assert 'WEB_TEST_ENRICHED.csv' in html
        assert 'Trazabilidad Criptográfica' in html

        # Verificaciones HU-7.4 (Enriquecimiento explicativo)
        assert 'Recomendaciones y Guía de Mitigación' in html
        assert 'Carga inicial de datos clínicos' in html
        assert 'Cuaderno interactivo (Jupyter / Colab Notebook)' in html
        assert 'Copiar Resumen Forense' in html
        assert 'Ver eventos de este usuario' in html
        assert 'Ver historial de este dataset' in html

    def test_endpoint_detalle_evento_inexistente_redirecciona(self, flask_client):
        """Verifica que al intentar ver un event_id inexistente redireccione a /eventos con mensaje flash."""
        response = flask_client.get('/eventos/999999', follow_redirects=True)
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        assert 'Evento #999999 no encontrado' in html
