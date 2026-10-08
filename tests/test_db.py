import os
import sqlite3
import pytest
from audit_tracer.db import get_connection

DB_NAME = "test_creation.db"

def test_get_connection_creates_db():
    """Verifica que la BD se crea automáticamente si no existe."""
    if os.path.exists(DB_NAME):
        try:
            os.remove(DB_NAME)
        except PermissionError:
            pass
    
    conn = get_connection(DB_NAME)
    assert os.path.exists(DB_NAME)
    assert isinstance(conn, sqlite3.Connection)
    conn.close()

def test_tables_exist():
    """Verifica que las tablas audit_log y usuarios existen después de get_connection()."""
    conn = get_connection(DB_NAME)
    cursor = conn.cursor()
    
    # Check usuarios table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usuarios'")
    assert cursor.fetchone() is not None
    
    # Check audit_log table
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'")
    assert cursor.fetchone() is not None
    
    conn.close()
