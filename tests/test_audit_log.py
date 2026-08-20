import pytest
import os
import sqlite3
from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import insert_event, get_events, verify_integrity
from audit_tracer.utils.hashing import hash_event

@pytest.fixture
def db_conn():
    conn = get_connection(":memory:")
    yield conn
    conn.close()

def test_insert_event(db_conn):
    """insert_event() inserta y retorna event_id válido."""
    event = {
        'usuario_id': 'test_user',
        'sesion_id': 'test_session',
        'tipo_accion': 'CARGA',
        'dataset_nombre': 'test.csv',
        'nivel_alerta': 'NORMAL'
    }
    event_id = insert_event(db_conn, event)
    assert event_id > 0
    
    # Check that it was actually inserted
    events = get_events(db_conn, usuario_id='test_user')
    assert len(events) == 1
    assert events[0]['event_id'] == event_id
    assert events[0]['hash_integridad'] is not None
    assert len(events[0]['hash_integridad']) == 64  # SHA-256 hex length

def test_get_events_filters(db_conn):
    """get_events() funciona con distintas combinaciones de filtros."""
    insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'nivel_alerta': 'NORMAL'})
    insert_event(db_conn, {'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'CONSULTA', 'nivel_alerta': 'ADVERTENCIA'})

    assert len(get_events(db_conn, usuario_id='u1')) == 1
    assert len(get_events(db_conn, tipo_accion='CONSULTA')) == 1
    assert len(get_events(db_conn, nivel_alerta='NORMAL')) == 1
    assert len(get_events(db_conn, usuario_id='u3')) == 0


# ──────────────────────────────────────────────────────────────
# HU-4.2 — Filtrado de eventos de auditoría
# ──────────────────────────────────────────────────────────────

class TestFiltradoEventos:
    """
    CA1: filtrar por usuario_id.
    CA2: filtrar por rango de fechas (timestamp).
    CA3: filtrar por tipo_accion.
    CA4: filtrar por dataset_nombre.
    CA5: los filtros se pueden combinar.
    CA6: el resultado refleja únicamente los eventos que cumplen los criterios.
    """

    @pytest.fixture
    def eventos_variados(self, db_conn):
        """Set de eventos con distintas combinaciones de usuario/fecha/acción/dataset."""
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
            'dataset_nombre': 'PATIENTS.csv', 'timestamp': '2026-01-05T10:00:00',
            'nivel_alerta': 'NORMAL',
        })
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'PATIENTS.csv', 'timestamp': '2026-01-10T10:00:00',
            'nivel_alerta': 'NORMAL',
        })
        insert_event(db_conn, {
            'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'admissions.xlsx', 'timestamp': '2026-01-10T11:00:00',
            'nivel_alerta': 'CRITICO',
        })
        insert_event(db_conn, {
            'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'CONSULTA',
            'dataset_nombre': 'admissions.xlsx', 'timestamp': '2026-02-01T09:00:00',
            'nivel_alerta': 'NORMAL',
        })
        return db_conn

    # ── CA1 ──────────────────────────────────────────────────
    def test_filtra_por_usuario_id(self, eventos_variados):
        eventos = get_events(eventos_variados, usuario_id='u1')
        assert len(eventos) == 2
        assert all(e['usuario_id'] == 'u1' for e in eventos)

    # ── CA2 ──────────────────────────────────────────────────
    def test_filtra_por_rango_de_fechas(self, eventos_variados):
        eventos = get_events(
            eventos_variados,
            fecha_inicio='2026-01-06T00:00:00',
            fecha_fin='2026-01-31T23:59:59',
        )
        assert len(eventos) == 2
        assert all('2026-01-1' in e['timestamp'] for e in eventos)

    def test_filtra_por_fecha_solo_inicio(self, eventos_variados):
        eventos = get_events(eventos_variados, fecha_inicio='2026-02-01T00:00:00')
        assert len(eventos) == 1
        assert eventos[0]['tipo_accion'] == 'CONSULTA'

    # ── CA3 ──────────────────────────────────────────────────
    def test_filtra_por_tipo_accion(self, eventos_variados):
        eventos = get_events(eventos_variados, tipo_accion='EXPORTACION')
        assert len(eventos) == 2
        assert all(e['tipo_accion'] == 'EXPORTACION' for e in eventos)

    # ── CA4 ──────────────────────────────────────────────────
    def test_filtra_por_dataset_nombre(self, eventos_variados):
        eventos = get_events(eventos_variados, dataset_nombre='admissions.xlsx')
        assert len(eventos) == 2
        assert all(e['dataset_nombre'] == 'admissions.xlsx' for e in eventos)

    # ── CA5: combinación de filtros ────────────────────────────
    def test_combina_usuario_y_tipo_accion(self, eventos_variados):
        eventos = get_events(eventos_variados, usuario_id='u1', tipo_accion='EXPORTACION')
        assert len(eventos) == 1
        assert eventos[0]['dataset_nombre'] == 'PATIENTS.csv'

    def test_combina_usuario_fecha_y_tipo_accion(self, eventos_variados):
        eventos = get_events(
            eventos_variados,
            usuario_id='u2',
            tipo_accion='EXPORTACION',
            fecha_inicio='2026-01-01T00:00:00',
            fecha_fin='2026-01-31T23:59:59',
        )
        assert len(eventos) == 1
        assert eventos[0]['dataset_nombre'] == 'admissions.xlsx'

    def test_combina_dataset_y_tipo_accion(self, eventos_variados):
        eventos = get_events(eventos_variados, dataset_nombre='admissions.xlsx', tipo_accion='CONSULTA')
        assert len(eventos) == 1
        assert eventos[0]['usuario_id'] == 'u2'

    # ── CA6: el resultado refleja solo lo que cumple todos los criterios ──
    def test_combinacion_sin_coincidencias_devuelve_vacio(self, eventos_variados):
        eventos = get_events(eventos_variados, usuario_id='u1', tipo_accion='CONSULTA')
        assert eventos == []

    def test_filtros_no_alteran_datos_subyacentes(self, eventos_variados):
        """Aplicar filtros es de solo lectura: no modifica los registros."""
        total_antes = len(get_events(eventos_variados))
        get_events(eventos_variados, usuario_id='u1', tipo_accion='EXPORTACION')
        total_despues = len(get_events(eventos_variados))
        assert total_antes == total_despues == 4

def test_verify_integrity(db_conn):
    """verify_integrity() detecta si un registro fue alterado manualmente."""
    # Insert a valid event
    event = {
        'usuario_id': 'u1', 
        'tipo_accion': 'CARGA', 
        'nivel_alerta': 'NORMAL',
        'sesion_id': 's1'
    }
    insert_event(db_conn, event)
    
    # Check that it starts clean
    corrupted = verify_integrity(db_conn)
    assert len(corrupted) == 0
    
    # Manually alter a record in the database
    cursor = db_conn.cursor()
    cursor.execute("UPDATE audit_log SET tipo_accion = 'BORRADO' WHERE usuario_id = 'u1'")
    db_conn.commit()
    
    # Verify integrity should now detect it
    corrupted = verify_integrity(db_conn)
    assert len(corrupted) == 1
    assert corrupted[0]['tipo_accion'] == 'BORRADO'
    assert corrupted[0]['stored_hash'] != corrupted[0]['calculated_hash']
