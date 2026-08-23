"""
tests/test_consulta_eventos.py
===============================
Pruebas unitarias para HU-4.1 — Consulta de eventos de auditoría.

Criterios de Aceptación:
CA1: El sistema muestra una lista de eventos almacenados en audit_log.
CA2: Cada evento visible incluye como mínimo: event_id, usuario_id, timestamp y tipo_accion.
CA3: La lista se presenta en orden cronológico descendente (más recientes primero).
CA4: El sistema permite visualizar múltiples eventos en una sola consulta.
"""

import pytest
from datetime import datetime
from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import insert_event, get_events
from app import app


@pytest.fixture
def db_conn():
    """Conexión SQLite en memoria para aislamiento de pruebas."""
    conn = get_connection(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def flask_client():
    """Cliente de pruebas de Flask."""
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess['usuario_id'] = 'analista_001'
            sess['rol'] = 'ANALISTA'
            sess['nombre'] = 'Analista Test'
            sess['sesion_id'] = 'sesion_test_401'
        yield client


class TestConsultaEventosAuditoria:
    """Pruebas unitarias para los criterios de aceptación CA1 a CA4 de la HU-4.1."""

    # ── CA1: El sistema muestra una lista de eventos almacenados en audit_log ──
    def test_ca1_obtiene_lista_eventos_almacenados(self, db_conn):
        """Verifica que la consulta retorne los eventos almacenados en audit_log."""
        insert_event(db_conn, {
            'usuario_id': 'user_1',
            'sesion_id': 's1',
            'tipo_accion': 'CARGA',
            'dataset_nombre': 'PACIENTES.csv',
            'nivel_alerta': 'NORMAL'
        })
        insert_event(db_conn, {
            'usuario_id': 'user_2',
            'sesion_id': 's2',
            'tipo_accion': 'CONSULTA',
            'dataset_nombre': 'LABS.csv',
            'nivel_alerta': 'NORMAL'
        })

        eventos = get_events(db_conn)
        assert isinstance(eventos, list)
        assert len(eventos) == 2

    # ── CA2: Cada evento visible incluye como mínimo: event_id, usuario_id, timestamp y tipo_accion ──
    def test_ca2_eventos_incluyen_campos_minimos_requeridos(self, db_conn):
        """Verifica que cada evento devuelto contenga event_id, usuario_id, timestamp y tipo_accion."""
        insert_event(db_conn, {
            'usuario_id': 'user_audit_1',
            'sesion_id': 's_test',
            'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'DIAGNOSTICOS.xlsx',
            'nivel_alerta': 'ADVERTENCIA'
        })

        eventos = get_events(db_conn)
        assert len(eventos) > 0
        evento = eventos[0]

        # Verificar presencia de campos mínimos del CA2
        assert 'event_id' in evento and evento['event_id'] is not None
        assert 'usuario_id' in evento and evento['usuario_id'] == 'user_audit_1'
        assert 'timestamp' in evento and evento['timestamp'] is not None
        assert 'tipo_accion' in evento and evento['tipo_accion'] == 'EXPORTACION'

    # ── CA3: La lista se presenta en orden cronológico descendente (más recientes primero) ──
    def test_ca3_orden_cronologico_descendente(self, db_conn):
        """Verifica que al consultar con orden_desc=True los eventos se ordenen del más reciente al más antiguo."""
        insert_event(db_conn, {
            'usuario_id': 'user_1',
            'sesion_id': 's1',
            'timestamp': '2026-01-01T10:00:00',
            'tipo_accion': 'INICIO_SESION',
            'nivel_alerta': 'NORMAL'
        })
        insert_event(db_conn, {
            'usuario_id': 'user_1',
            'sesion_id': 's1',
            'timestamp': '2026-01-01T12:00:00',
            'tipo_accion': 'CARGA',
            'nivel_alerta': 'NORMAL'
        })
        insert_event(db_conn, {
            'usuario_id': 'user_1',
            'sesion_id': 's1',
            'timestamp': '2026-01-01T14:00:00',
            'tipo_accion': 'EXPORTACION',
            'nivel_alerta': 'CRITICO'
        })

        eventos = get_events(db_conn, orden_desc=True)

        assert len(eventos) == 3
        # El más reciente (14:00:00) debe estar primero
        assert eventos[0]['tipo_accion'] == 'EXPORTACION'
        assert eventos[1]['tipo_accion'] == 'CARGA'
        # El más antiguo (10:00:00) debe estar al final
        assert eventos[2]['tipo_accion'] == 'INICIO_SESION'

        # Validar estrictamente la secuencia de timestamps descendente
        timestamps = [e['timestamp'] for e in eventos]
        assert timestamps == sorted(timestamps, reverse=True)

    # ── CA4: El sistema permite visualizar múltiples eventos en una sola consulta ──
    def test_ca4_permite_visualizar_multiples_eventos(self, db_conn):
        """Verifica la capacidad de consultar y recuperar múltiples eventos en un solo llamado."""
        for i in range(15):
            insert_event(db_conn, {
                'usuario_id': f'user_{i}',
                'sesion_id': f'sesion_{i}',
                'tipo_accion': 'CONSULTA' if i % 2 == 0 else 'CARGA',
                'dataset_nombre': 'CONSULTAS.csv',
                'nivel_alerta': 'NORMAL'
            })

        eventos = get_events(db_conn)
        assert len(eventos) == 15


class TestVistaFrontendConsultaEventos:
    """Pruebas de integración para la ruta Flask /eventos (HU-4.1 en interfaz web)."""

    def test_endpoint_eventos_retorna_200_y_muestra_campos_minimos(self, flask_client):
        """Verifica que la página /eventos cargue correctamente y contenga los encabezados mínimos."""
        response = flask_client.get('/eventos')
        assert response.status_code == 200
        html = response.get_data(as_text=True)

        # Verificar encabezados de columna en la tabla HTML (CA2)
        assert 'ID' in html
        assert 'Fecha y Hora' in html
        assert 'Usuario' in html
        assert 'Acción Realizada' in html
