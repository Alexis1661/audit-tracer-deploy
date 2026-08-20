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
