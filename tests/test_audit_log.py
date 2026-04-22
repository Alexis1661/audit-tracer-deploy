import pytest
import os
import sqlite3
from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import insert_event, get_events
from audit_tracer.utils.hashing import verify_integrity, hash_event

@pytest.fixture
def db_conn():
    if os.path.exists("audit_trail.db"):
        os.remove("audit_trail.db")
    conn = get_connection()
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

def test_verify_integrity(db_conn):
    """verify_integrity() retorna lista vacía si no hay alteraciones y detecta alteraciones."""
    insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'nivel_alerta': 'NORMAL'})
    
    # Should be empty
    assert len(verify_integrity(db_conn)) == 0
    
    # Manual alteration
    cursor = db_conn.cursor()
    cursor.execute("UPDATE audit_log SET tipo_accion = 'ALTERADO' WHERE usuario_id = 'u1'")
    db_conn.commit()
    
    # Should detect the alteration
    altered = verify_integrity(db_conn)
    assert len(altered) == 1
