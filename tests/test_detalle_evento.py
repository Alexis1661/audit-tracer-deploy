"""
tests/test_detalle_evento.py
==============================
Pruebas unitarias para HU-4.3 — Visualización de detalle de evento.

Criterios de Aceptación:
CA1: El sistema permite seleccionar un event_id para consultar su detalle.
CA2: El sistema muestra toda la información asociada al evento, incluyendo usuario_id,
     sesion_id, timestamp, tipo_accion y campos adicionales.
CA3: La información del evento es consistente con lo almacenado en audit_log.
CA4: El sistema muestra el evento aunque tenga campos opcionales vacíos.
"""

import pytest
from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import insert_event, get_event_by_id
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


class TestVisualizacionDetalleEvento:
    """Pruebas unitarias para los criterios de aceptación CA1 a CA4 de HU-4.3."""

    # ── CA1 y CA3: Consulta por event_id y consistencia de datos ──
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

    # ── CA2: El sistema muestra toda la información asociada al evento ──
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

    # ── CA4: Muestra el evento aunque tenga campos opcionales vacíos ──
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


class TestVistaFrontendDetalleEvento:
    """Pruebas de integración de la interfaz web para /eventos/<event_id>."""

    def test_endpoint_detalle_evento_existente_status_200(self, flask_client):
        """Verifica que al consultar /eventos/<event_id> responda 200 OK con el contenido."""
        conn = get_connection()
        event_id = insert_event(conn, {
            'usuario_id': 'u_web_test',
            'sesion_id': 's_web_test',
            'tipo_accion': 'CARGA',
            'dataset_nombre': 'WEB_TEST.csv',
            'nivel_alerta': 'NORMAL'
        })
        conn.close()

        response = flask_client.get(f'/eventos/{event_id}')
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        assert f'Detalle del Evento #{event_id}' in html
        assert 'u_web_test' in html
        assert 'WEB_TEST.csv' in html
        assert 'Trazabilidad e Integridad Criptográfica' in html

    def test_endpoint_detalle_evento_inexistente_redirecciona(self, flask_client):
        """Verifica que al intentar ver un event_id inexistente redireccione a /eventos con mensaje flash."""
        response = flask_client.get('/eventos/999999', follow_redirects=True)
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        assert 'Evento #999999 no encontrado' in html
