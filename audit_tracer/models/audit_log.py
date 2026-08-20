import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
from ..utils.hashing import hash_event

def insert_event(conn: sqlite3.Connection, event: Dict) -> int:
    """
    Inserts an event into the audit_log table.
    Calculates the integrity hash before insertion.
    Never allows updates or deletes.

    Args:
        conn (sqlite3.Connection): Database connection.
        event (Dict): Event data dictionary.

    Returns:
        int: The newly created event_id.
    """
    # Ensure timestamp is set if not provided
    if 'timestamp' not in event:
        event['timestamp'] = datetime.utcnow().isoformat()
    
    columns = [
        'usuario_id', 'sesion_id', 'timestamp', 'tipo_accion',
        'dataset_nombre', 'columnas_afectadas', 'ruta_destino',
        'filas_exportadas', 'sobrescritura',
        'contexto_ejecucion', 'motivo_fallo', 'nivel_alerta',
        'motivo_alerta'
    ]

    # Create a full dictionary with all columns to ensure consistency for hashing
    full_event = {col: event.get(col) for col in columns}
    
    # Calculate integrity hash using the full dictionary
    event['hash_integridad'] = hash_event(full_event)
    
    placeholders = ', '.join(['?'] * (len(columns) + 1))
    query = f"INSERT INTO audit_log ({', '.join(columns)}, hash_integridad) VALUES ({placeholders})"
    
    values = [full_event.get(col) for col in columns] + [event['hash_integridad']]
    
    cursor = conn.cursor()
    cursor.execute(query, values)
    conn.commit()
    
    return cursor.lastrowid

def get_events(
    conn: sqlite3.Connection, 
    usuario_id: str = None, 
    fecha_inicio: str = None, 
    fecha_fin: str = None, 
    tipo_accion: str = None, 
    dataset_nombre: str = None, 
    nivel_alerta: str = None
) -> List[Dict]:
    """
    Retrieves events from the audit_log table with filters.
    Results are sorted chronologically.

    Args:
        conn (sqlite3.Connection): Database connection.
        usuario_id (str, optional): Filter by user ID.
        fecha_inicio (str, optional): Start date filter (ISO 8601).
        fecha_fin (str, optional): End date filter (ISO 8601).
        tipo_accion (str, optional): Filter by action type.
        dataset_nombre (str, optional): Filter by dataset name.
        nivel_alerta (str, optional): Filter by alert level.

    Returns:
        List[Dict]: List of event dictionaries.
    """
    query = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    
    if usuario_id:
        query += " AND usuario_id = ?"
        params.append(usuario_id)
    if fecha_inicio:
        query += " AND timestamp >= ?"
        params.append(fecha_inicio)
    if fecha_fin:
        query += " AND timestamp <= ?"
        params.append(fecha_fin)
    if tipo_accion:
        query += " AND tipo_accion = ?"
        params.append(tipo_accion)
    if dataset_nombre:
        query += " AND dataset_nombre = ?"
        params.append(dataset_nombre)
    if nivel_alerta:
        query += " AND nivel_alerta = ?"
        params.append(nivel_alerta)
        
    query += " ORDER BY timestamp ASC"
    
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    return [dict(row) for row in rows]

def verify_integrity(conn: sqlite3.Connection) -> List[Dict]:
    """
    Verifies the integrity of all records in the audit_log table.
    Recalculates the hash for each record and compares it with the stored hash.

    Returns:
        List[Dict]: A list of records that failed the integrity check.
    """
    query = "SELECT * FROM audit_log ORDER BY timestamp ASC"
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    
    corrupted_records = []
    
    columns_to_hash = [
        'usuario_id', 'sesion_id', 'timestamp', 'tipo_accion',
        'dataset_nombre', 'columnas_afectadas', 'ruta_destino',
        'filas_exportadas', 'sobrescritura',
        'contexto_ejecucion', 'motivo_fallo', 'nivel_alerta',
        'motivo_alerta'
    ]
    
    for row in rows:
        stored_hash = row['hash_integridad']
        # Create dictionary for hashing (same logic as insert_event)
        event_data = {col: row[col] for col in columns_to_hash}
        
        calculated_hash = hash_event(event_data)
        
        if calculated_hash != stored_hash:
            corrupted_records.append({
                'event_id': row['event_id'],
                'timestamp': row['timestamp'],
                'tipo_accion': row['tipo_accion'],
                'stored_hash': stored_hash,
                'calculated_hash': calculated_hash
            })
            
    return corrupted_records
