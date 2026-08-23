import csv
import os
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from ..utils.hashing import hash_event

def insert_event(conn: sqlite3.Connection, event: Dict) -> int:
    """
    Inserts an event into the audit_log table.
    Calculates the integrity hash before insertion.
    Never allows updates or deletes.

    HU-2.5 CA1/CA2/CA3: normaliza usuario_id/sesion_id para que el evento
    nunca se pierda por falta de identificación, y clasifica como CRITICO
    todo evento cuyo usuario_id sea DESCONOCIDO.

    Args:
        conn (sqlite3.Connection): Database connection.
        event (Dict): Event data dictionary.

    Returns:
        int: The newly created event_id.
    """
    # Ensure timestamp is set if not provided
    if 'timestamp' not in event:
        event['timestamp'] = datetime.utcnow().isoformat()

    # HU-2.5 CA2/CA3: garantizar usuario_id y sesion_id siempre presentes,
    # para que ningún evento se pierda por violar el NOT NULL del schema.
    event['usuario_id'] = event.get('usuario_id') or 'DESCONOCIDO'
    event['sesion_id'] = event.get('sesion_id') or 'SIN_SESION'

    # HU-2.5 CA2: usuario no identificado siempre se marca como CRITICO.
    if event['usuario_id'] == 'DESCONOCIDO':
        event['nivel_alerta'] = 'CRITICO'
        if not event.get('motivo_alerta'):
            event['motivo_alerta'] = 'Operación ejecutada por usuario no identificado'

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


# ──────────────────────────────────────────────────────────────
# HU-4.4 — Identificación de eventos críticos
# ──────────────────────────────────────────────────────────────

def get_critical_events(
    conn: sqlite3.Connection,
    usuario_id: str = None,
    fecha_inicio: str = None,
    fecha_fin: str = None,
    tipo_accion: str = None,
    dataset_nombre: str = None,
) -> List[Dict]:
    """
    CA2 — Función equivalente a get_events(conn, ..., nivel_alerta='CRITICO').
    Permite consultar únicamente los eventos clasificados como críticos,
    opcionalmente combinados con los mismos filtros que get_events() (CA4).

    Returns:
        List[Dict]: Eventos con nivel_alerta = 'CRITICO' que cumplen los filtros.
    """
    return get_events(
        conn,
        usuario_id=usuario_id,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        tipo_accion=tipo_accion,
        dataset_nombre=dataset_nombre,
        nivel_alerta='CRITICO',
    )


def contar_intentos_fallidos_recientes(
    conn: sqlite3.Connection,
    usuario_id: str,
    ahora: datetime,
    ventana_minutos: int = 5,
) -> int:
    """
    CA1-a — Cuenta eventos ACCESO_FALLIDO ya registrados para `usuario_id`
    dentro de los últimos `ventana_minutos` minutos contados hacia atrás
    desde `ahora`. No incluye el intento que se está evaluando: ese debe
    sumarse aparte antes de insertarlo, ya que todavía no existe en la BD.

    Returns:
        int: Número de intentos fallidos recientes ya persistidos.
    """
    desde = (ahora - timedelta(minutes=ventana_minutos)).isoformat()
    query = (
        "SELECT COUNT(*) FROM audit_log "
        "WHERE usuario_id = ? AND tipo_accion = 'ACCESO_FALLIDO' "
        "AND timestamp >= ? AND timestamp <= ?"
    )
    cursor = conn.cursor()
    cursor.execute(query, (usuario_id, desde, ahora.isoformat()))
    return cursor.fetchone()[0]


# Columnas incluidas en la exportación CSV de eventos críticos (CA5).
# Cubre el detalle completo del registro, incluyendo el hash de integridad
# para que el reporte sea verificable frente a audit_log.
CRITICAL_EVENTS_CSV_COLUMNS = [
    'event_id', 'usuario_id', 'sesion_id', 'timestamp', 'tipo_accion',
    'dataset_nombre', 'columnas_afectadas', 'ruta_destino', 'filas_exportadas',
    'sobrescritura', 'contexto_ejecucion', 'motivo_fallo', 'nivel_alerta',
    'motivo_alerta', 'hash_integridad',
]


def export_critical_events_to_csv(
    conn: sqlite3.Connection,
    dest,
    usuario_id: str = None,
    fecha_inicio: str = None,
    fecha_fin: str = None,
    tipo_accion: str = None,
    dataset_nombre: str = None,
) -> int:
    """
    CA5 — Exporta a CSV los eventos críticos (nivel_alerta = CRITICO) que
    cumplan los filtros dados, combinables igual que get_critical_events().

    Args:
        dest: ruta de archivo (str/os.PathLike) o un objeto file-like ya
              abierto en modo texto (p. ej. io.StringIO para descargas HTTP).

    Returns:
        int: Número de eventos exportados.
    """
    eventos = get_critical_events(
        conn,
        usuario_id=usuario_id,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        tipo_accion=tipo_accion,
        dataset_nombre=dataset_nombre,
    )

    def _write(f):
        writer = csv.DictWriter(f, fieldnames=CRITICAL_EVENTS_CSV_COLUMNS)
        writer.writeheader()
        for evento in eventos:
            writer.writerow({col: evento.get(col) for col in CRITICAL_EVENTS_CSV_COLUMNS})

    if isinstance(dest, (str, os.PathLike)):
        with open(dest, "w", newline="", encoding="utf-8") as f:
            _write(f)
    else:
        _write(dest)

    return len(eventos)


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
