import csv
import os
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from ..utils.hashing import hash_event

# Los 13 campos funcionales sobre los que se calcula hash_integridad.
# event_id, evento_uuid y hash_integridad quedan fuera a propósito:
# son metadata de almacenamiento/transporte, no el evento auditado en sí.
# Debe ser idéntica en la base local y en la central (HU-5.4 CA1) para que
# un mismo evento produzca el mismo hash sin importar dónde se calculó.
_HASHED_COLUMNS = [
    'usuario_id', 'sesion_id', 'timestamp', 'tipo_accion',
    'dataset_nombre', 'columnas_afectadas', 'ruta_destino',
    'filas_exportadas', 'sobrescritura',
    'contexto_ejecucion', 'motivo_fallo', 'nivel_alerta',
    'motivo_alerta'
]


def _prepare_event(event: Dict) -> Dict:
    """
    Normaliza un evento y calcula, en Python, todo lo necesario para
    insertarlo en CUALQUIER conexión que comparta el esquema de audit_log
    (local o central) — sin volver a tocar SQL específico de motor.

    HU-2.5 CA1/CA2/CA3: normaliza usuario_id/sesion_id para que el evento
    nunca se pierda por falta de identificación, y clasifica como CRITICO
    todo evento cuyo usuario_id sea DESCONOCIDO.

    HU-5.4 CA1: genera evento_uuid si el evento no trae uno ya asignado
    (insert_event_dual() genera uno solo y lo reutiliza en ambas bases,
    para que el mismo evento tenga el mismo evento_uuid en local y central).

    Returns:
        Dict: copia del evento con timestamp, usuario_id, sesion_id,
        evento_uuid y hash_integridad ya resueltos.
    """
    event = dict(event)  # no mutar el dict del caller

    if not event.get('timestamp'):
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

    if not event.get('evento_uuid'):
        event['evento_uuid'] = str(uuid.uuid4())

    # El hash se calcula una sola vez, aquí, sobre los campos funcionales
    # únicamente — evento_uuid queda fuera para que el mismo evento hashee
    # igual sin importar en qué base terminó insertado.
    full_event = {col: event.get(col) for col in _HASHED_COLUMNS}
    event['hash_integridad'] = hash_event(full_event)

    return event


def _execute_insert(conn: sqlite3.Connection, prepared_event: Dict) -> int:
    """Ejecuta el INSERT de un evento ya preparado por _prepare_event() en `conn`."""
    columns = _HASHED_COLUMNS + ['evento_uuid', 'hash_integridad']
    placeholders = ', '.join(['?'] * len(columns))
    query = f"INSERT INTO audit_log ({', '.join(columns)}) VALUES ({placeholders})"
    values = [prepared_event.get(col) for col in columns]

    cursor = conn.cursor()
    cursor.execute(query, values)
    conn.commit()

    return cursor.lastrowid


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
    prepared = _prepare_event(event)
    event_id = _execute_insert(conn, prepared)

    # Preservar el comportamiento histórico: el dict que pasó el caller
    # queda con hash_integridad poblado tras el insert.
    event['hash_integridad'] = prepared['hash_integridad']
    event.setdefault('evento_uuid', prepared['evento_uuid'])

    return event_id


def insert_event_dual(
    local_conn: Optional[sqlite3.Connection],
    central_conn: Optional[sqlite3.Connection],
    event: Dict,
) -> Dict:
    """
    HU-5.4 — Escribe el mismo evento en la base local (caché/respaldo
    inmediato) y en la base central consolidada, calculando el hash y el
    evento_uuid UNA sola vez (no se duplica lógica de hashing entre las
    dos escrituras).

    Si la escritura central falla (ej. servidor no disponible), el evento
    igual queda persistido localmente — no se pierde. Ese es exactamente
    el modelo híbrido que sustenta HU-5.6/HU-5.8: local siempre se escribe
    primero y no depende de que la central esté disponible.

    Args:
        local_conn: conexión local, o None para omitir esa escritura.
        central_conn: conexión central, o None para omitir esa escritura.
        event: datos del evento (mismo formato que insert_event()).

    Returns:
        Dict con 'evento_uuid', 'hash_integridad', 'local_event_id' y
        'central_event_id' (None si no se escribió o si la escritura
        central falló).
    """
    prepared = _prepare_event(event)

    local_event_id = _execute_insert(local_conn, prepared) if local_conn is not None else None

    central_event_id = None
    if central_conn is not None:
        try:
            central_event_id = _execute_insert(central_conn, prepared)
        except Exception as exc:
            # TODO(HU-5.8): encolar para reintento de sincronización.
            print(f"[AuditTracer] Advertencia: no se pudo escribir en la base central — {exc}")

    return {
        'evento_uuid': prepared['evento_uuid'],
        'hash_integridad': prepared['hash_integridad'],
        'local_event_id': local_event_id,
        'central_event_id': central_event_id,
    }

def get_events(
    conn: sqlite3.Connection, 
    usuario_id: str = None, 
    fecha_inicio: str = None, 
    fecha_fin: str = None, 
    tipo_accion: str = None, 
    dataset_nombre: str = None, 
    nivel_alerta: str = None,
    orden_desc: bool = False
) -> List[Dict]:
    """
    Retrieves events from the audit_log table with filters.
    HU-4.1 — Consulta de eventos de auditoría (CA1-CA4).

    Args:
        conn (sqlite3.Connection): Database connection.
        usuario_id (str, optional): Filter by user ID.
        fecha_inicio (str, optional): Start date filter (ISO 8601).
        fecha_fin (str, optional): End date filter (ISO 8601).
        tipo_accion (str, optional): Filter by action type.
        dataset_nombre (str, optional): Filter by dataset name.
        nivel_alerta (str, optional): Filter by alert level.
        orden_desc (bool, optional): If True, orders by timestamp DESC (HU-4.1 CA3).

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
        
    if orden_desc:
        query += " ORDER BY timestamp DESC, event_id DESC"
    else:
        query += " ORDER BY timestamp ASC, event_id ASC"
    
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    return [dict(row) for row in rows]


def get_event_by_id(conn: sqlite3.Connection, event_id: int) -> Optional[Dict]:
    """
    HU-4.3 — Retrieves details for a specific event by its event_id (CA1-CA4).

    Args:
        conn (sqlite3.Connection): Database connection.
        event_id (int): Unique identifier of the event.

    Returns:
        Optional[Dict]: Event dictionary containing all fields, or None if not found.
    """
    query = "SELECT * FROM audit_log WHERE event_id = ?"
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, (event_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def get_event_by_uuid(conn: sqlite3.Connection, evento_uuid: str) -> Optional[Dict]:
    """
    HU-5.8 — Busca un evento por su evento_uuid (clave de idempotencia de
    la sincronización). Funciona igual sobre la base local o la central.

    Returns:
        Optional[Dict]: El evento si existe, o None.
    """
    query = "SELECT * FROM audit_log WHERE evento_uuid = ?"
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, (evento_uuid,))
    row = cursor.fetchone()
    return dict(row) if row else None


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

    HU-5.4 — Genérica sobre `conn`: funciona igual contra la base local o
    la central, porque ambas comparten el mismo esquema y la misma lista
    de columnas hasheadas (_HASHED_COLUMNS).

    Returns:
        List[Dict]: A list of records that failed the integrity check.
    """
    query = "SELECT * FROM audit_log ORDER BY timestamp ASC"
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()

    corrupted_records = []

    for row in rows:
        stored_hash = row['hash_integridad']
        # Create dictionary for hashing (same logic as insert_event)
        event_data = {col: row[col] for col in _HASHED_COLUMNS}

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


# ──────────────────────────────────────────────────────────────
# HU-4.5 — Reportes de auditoría por fechas y usuario, exportación CSV
# ──────────────────────────────────────────────────────────────

# CA2/CA3 — Columnas exactas del reporte de auditoría (display y CSV).
REPORT_CSV_COLUMNS = [
    'event_id', 'usuario_id', 'timestamp', 'tipo_accion',
    'dataset_nombre', 'columnas_afectadas', 'nivel_alerta',
]

# CA4 — Mensaje exacto cuando los filtros no producen eventos. Única fuente
# de verdad: la vista lo reutiliza en lugar de duplicar el texto literal.
NO_RESULTS_MESSAGE = "No se encontraron eventos para los filtros seleccionados."


def generate_report(
    conn: sqlite3.Connection,
    usuario_id: str = None,
    fecha_inicio: str = None,
    fecha_fin: str = None,
    tipo_accion: str = None,
    dataset_nombre: str = None,
) -> List[Dict]:
    """
    CA1 — Genera el reporte de auditoría filtrando por usuario_id, rango de
    fechas, tipo_accion y dataset_nombre, de forma individual o combinada
    (delega en get_events(), que ya soporta estos filtros combinados con AND).

    CA2 — Cada evento se reduce a las columnas REPORT_CSV_COLUMNS, en orden
    cronológico ascendente (get_events() ya ordena por timestamp ASC).

    Returns:
        List[Dict]: Eventos del reporte, o [] si ningún evento cumple los
        filtros (CA4: no se lanza excepción, la lista vacía es el resultado).
    """
    eventos = get_events(
        conn,
        usuario_id=usuario_id,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        tipo_accion=tipo_accion,
        dataset_nombre=dataset_nombre,
    )
    return [{col: evento.get(col) for col in REPORT_CSV_COLUMNS} for evento in eventos]


def export_report_to_csv(
    conn: sqlite3.Connection,
    dest,
    usuario_id: str = None,
    fecha_inicio: str = None,
    fecha_fin: str = None,
    tipo_accion: str = None,
    dataset_nombre: str = None,
) -> int:
    """
    CA3 — Exporta a CSV el reporte de generate_report(), con la cabecera
    estandarizada REPORT_CSV_COLUMNS. Si no hay eventos, escribe igualmente
    un CSV válido con solo la cabecera (CA4: nunca un CSV corrupto).

    Args:
        dest: ruta de archivo (str/os.PathLike) o un objeto file-like ya
              abierto en modo texto (p. ej. io.StringIO para descargas HTTP).

    Returns:
        int: Número de eventos exportados.
    """
    eventos = generate_report(
        conn,
        usuario_id=usuario_id,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        tipo_accion=tipo_accion,
        dataset_nombre=dataset_nombre,
    )

    def _write(f):
        writer = csv.DictWriter(f, fieldnames=REPORT_CSV_COLUMNS)
        writer.writeheader()
        for evento in eventos:
            writer.writerow(evento)

    if isinstance(dest, (str, os.PathLike)):
        with open(dest, "w", newline="", encoding="utf-8") as f:
            _write(f)
    else:
        _write(dest)

    return len(eventos)


# ──────────────────────────────────────────────────────────────
# HU-5.8 — Sincronización de eventos hacia el servidor central
# ──────────────────────────────────────────────────────────────
#
# Dos mitades:
#   (a) Cola local (audit_sync_queue, solo en la base LOCAL): registra
#       qué eventos capturados por la librería (Colab u otro entorno)
#       todavía no fueron confirmados por el servidor central.
#   (b) Inserción idempotente (usada por el endpoint receptor sobre la
#       base CENTRAL): garantiza que reintentar el envío de un mismo
#       evento_uuid nunca produzca una segunda fila.

# CA1/CA3 — Sub-tarea 2: encolar SIEMPRE junto con la inserción local.
def insert_event_and_enqueue_sync(conn: sqlite3.Connection, event: Dict) -> Dict:
    """
    CA1 — Inserta `event` en la base LOCAL (audit_log) y, en la misma
    operación, lo encola en audit_sync_queue con estado 'PENDIENTE'.

    Este es el único punto que usan los interceptores de captura
    (data_capture.py, export_capture.py, failed_access.py,
    session_tracker.py): garantiza que ningún evento capturado quede sin
    persistir localmente antes de que se intente cualquier envío HTTP —
    la llamada de red, si ocurre, siempre sucede DESPUÉS de que esta
    función retorna.

    Args:
        conn:  Conexión a la base LOCAL (no la central: la central no
               tiene tabla audit_sync_queue).
        event: Mismo formato que insert_event().

    Returns:
        Dict: {'event_id', 'evento_uuid', 'hash_integridad'} del evento
        ya persistido y encolado.
    """
    event_id = insert_event(conn, event)
    conn.execute(
        "INSERT INTO audit_sync_queue (event_id, evento_uuid, estado) VALUES (?, ?, 'PENDIENTE')",
        (event_id, event["evento_uuid"]),
    )
    conn.commit()
    return {
        "event_id": event_id,
        "evento_uuid": event["evento_uuid"],
        "hash_integridad": event["hash_integridad"],
    }


def get_pending_sync_events(conn: sqlite3.Connection) -> List[Dict]:
    """
    CA2/CA3 — Eventos locales todavía no confirmados por el servidor
    central (estado 'PENDIENTE' o 'FALLIDO'), en orden de captura, con
    todos los campos de audit_log necesarios para reconstruir el payload
    de sincronización.
    """
    query = """
        SELECT a.*, q.estado, q.intentos, q.ultimo_intento, q.ultimo_error
        FROM audit_sync_queue q
        JOIN audit_log a ON a.event_id = q.event_id
        WHERE q.estado IN ('PENDIENTE', 'FALLIDO')
        ORDER BY a.event_id ASC
    """
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query)
    return [dict(row) for row in cursor.fetchall()]


def mark_event_synced(conn: sqlite3.Connection, event_id: int, cuando: str) -> None:
    """CA3 — Confirmación positiva del servidor central: marca la fila de la cola como SINCRONIZADO."""
    conn.execute(
        """
        UPDATE audit_sync_queue
        SET estado = 'SINCRONIZADO', ultimo_intento = ?, ultimo_error = NULL,
            intentos = intentos + 1, sincronizado_en = ?
        WHERE event_id = ?
        """,
        (cuando, cuando, event_id),
    )
    conn.commit()


def mark_event_sync_failed(conn: sqlite3.Connection, event_id: int, error_mensaje: str, cuando: str) -> None:
    """
    CA2/CA3 — Registra un intento de envío fallido sin eliminar la fila:
    el evento permanece en la cola para reintentarse. `error_mensaje`
    nunca debe incluir el valor del token (CA4).
    """
    conn.execute(
        """
        UPDATE audit_sync_queue
        SET estado = 'FALLIDO', ultimo_intento = ?, ultimo_error = ?,
            intentos = intentos + 1
        WHERE event_id = ?
        """,
        (cuando, error_mensaje, event_id),
    )
    conn.commit()


def get_sync_queue_summary(conn: sqlite3.Connection) -> Dict:
    """
    Sub-tarea 5/6 — Resumen de la cola local para el indicador de
    notebook y el panel de diagnóstico del dashboard.
    """
    filas = conn.execute("SELECT estado, COUNT(*) FROM audit_sync_queue GROUP BY estado").fetchall()
    conteos = {estado: total for estado, total in filas}

    ultimo = conn.execute(
        """
        SELECT ultimo_intento, ultimo_error FROM audit_sync_queue
        WHERE ultimo_intento IS NOT NULL
        ORDER BY ultimo_intento DESC LIMIT 1
        """
    ).fetchone()

    return {
        "pendientes": conteos.get("PENDIENTE", 0),
        "fallidos": conteos.get("FALLIDO", 0),
        "sincronizados": conteos.get("SINCRONIZADO", 0),
        "ultimo_intento": ultimo[0] if ultimo else None,
        "ultimo_error": ultimo[1] if ultimo else None,
    }


# CA5 — Sub-tarea 4: inserción idempotente usada por el endpoint receptor.
def insert_event_if_new(conn: sqlite3.Connection, event: Dict) -> Tuple[Dict, bool]:
    """
    CA5 — Inserta `event` en `conn` (la base CENTRAL) solo si su
    evento_uuid no existe todavía. Es la operación que usa el endpoint
    receptor (POST /api/eventos/sincronizar) para que reintentar el envío
    de un mismo evento nunca produzca una segunda fila.

    La garantía real de no-duplicados es la restricción `evento_uuid TEXT
    UNIQUE NOT NULL` del esquema (schema/audit_log_central.sql, HU-5.4):
    el SELECT inicial es solo una optimización para el camino feliz (evita
    pagar el costo de un INSERT fallido en el caso común). Si dos
    solicitudes concurrentes llegan a la vez para el mismo evento_uuid, la
    que pierde la carrera choca con esa restricción UNIQUE y se recupera
    capturando el IntegrityError — la base de datos es quien realmente
    impide el duplicado, no esta función.

    Returns:
        Tuple[Dict, bool]: (evento almacenado, True si se insertó ahora;
        False si ya existía — en ambos casos el caller puede responder
        de forma idempotente).

    Raises:
        ValueError: Si el evento no trae evento_uuid.
    """
    evento_uuid = event.get("evento_uuid")
    if not evento_uuid:
        raise ValueError("evento_uuid es obligatorio para insertar de forma idempotente")

    existente = get_event_by_uuid(conn, evento_uuid)
    if existente:
        return existente, False

    try:
        event_id = insert_event(conn, dict(event))
    except sqlite3.IntegrityError:
        existente = get_event_by_uuid(conn, evento_uuid)
        if existente:
            return existente, False
        raise  # IntegrityError no relacionado con un evento_uuid duplicado

    return get_event_by_id(conn, event_id), True
