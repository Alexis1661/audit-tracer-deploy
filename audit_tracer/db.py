import sqlite3
import os
import uuid

# Columnas incorporadas a audit_log después de la versión inicial del schema.
# Se agregan con ALTER TABLE a bases de datos preexistentes que fueron creadas
# antes de que existieran, para que insert_event() no falle en silencio
# (HU-2.3 añadió filas_exportadas y sobrescritura; HU-5.4 añadió evento_uuid).
_AUDIT_LOG_MIGRATIONS = [
    ("filas_exportadas", "ALTER TABLE audit_log ADD COLUMN filas_exportadas INTEGER"),
    ("sobrescritura", "ALTER TABLE audit_log ADD COLUMN sobrescritura INTEGER"),
    ("evento_uuid", "ALTER TABLE audit_log ADD COLUMN evento_uuid TEXT"),
]

# HU-5.4 CA3 — Infraestructura de inmutabilidad: bloquea UPDATE/DELETE sobre
# audit_log y deja constancia del intento. Idéntica en la base local y en la
# central (ver schema/audit_log.sql y schema/audit_log_central.sql, que la
# incluyen directamente para bases nuevas). Este bloque se aplica aquí para
# bases *preexistentes* que se crearon antes de que existiera (cierra un
# faltante de HU-3.3, que la implementó en una rama que nunca se mergeó a
# main). CREATE ... IF NOT EXISTS es idempotente: se puede reejecutar en
# cada conexión sin efecto tras la primera vez.
_IMMUTABILITY_DDL = """
CREATE TABLE IF NOT EXISTS audit_intentos_bloqueados (
    intento_id        INTEGER  PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT     NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    tipo_intento      TEXT     NOT NULL,
    event_id_objetivo INTEGER  NOT NULL,
    usuario_id        TEXT,
    sesion_id         TEXT,
    nivel_alerta      TEXT     NOT NULL DEFAULT 'CRITICO',
    motivo_alerta     TEXT
);

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    INSERT INTO audit_intentos_bloqueados (
        tipo_intento, event_id_objetivo, usuario_id, sesion_id, motivo_alerta
    )
    VALUES (
        'INTENTO_MODIFICACION',
        OLD.event_id,
        COALESCE(OLD.usuario_id, 'DESCONOCIDO'),
        COALESCE(OLD.sesion_id, 'SISTEMA'),
        'Intento de UPDATE sobre event_id=' || OLD.event_id || ' bloqueado por trigger de inmutabilidad.'
    );
    SELECT RAISE(FAIL, 'INMUTABILIDAD: No se permite modificar registros de auditoría.');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    INSERT INTO audit_intentos_bloqueados (
        tipo_intento, event_id_objetivo, usuario_id, sesion_id, motivo_alerta
    )
    VALUES (
        'INTENTO_ELIMINACION',
        OLD.event_id,
        COALESCE(OLD.usuario_id, 'DESCONOCIDO'),
        COALESCE(OLD.sesion_id, 'SISTEMA'),
        'Intento de DELETE sobre event_id=' || OLD.event_id || ' bloqueado por trigger de inmutabilidad.'
    );
    SELECT RAISE(FAIL, 'INMUTABILIDAD: No se permite eliminar registros de auditoría.');
END;
"""


def _migrate_audit_log(conn: sqlite3.Connection) -> None:
    """
    Aplica migraciones aditivas pendientes sobre una tabla audit_log
    existente: columnas nuevas, backfill de evento_uuid y la
    infraestructura de inmutabilidad de HU-5.4. Vale tanto para la base
    local como para la central — ambas comparten este mismo esquema base.
    """
    existing_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
    if not existing_columns:
        return  # La tabla no existe todavía; la crea el script de schema.

    for column, alter_sql in _AUDIT_LOG_MIGRATIONS:
        if column not in existing_columns:
            conn.execute(alter_sql)

    # Backfill de evento_uuid ANTES de crear los triggers de abajo: una vez
    # que existen, ni siquiera este UPDATE podría ejecutarse sobre filas
    # preexistentes (bloquean cualquier UPDATE, sin excepción).
    filas_sin_uuid = conn.execute(
        "SELECT event_id FROM audit_log WHERE evento_uuid IS NULL"
    ).fetchall()
    for (event_id,) in filas_sin_uuid:
        conn.execute(
            "UPDATE audit_log SET evento_uuid = ? WHERE event_id = ?",
            (str(uuid.uuid4()), event_id),
        )

    conn.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_evento_uuid ON audit_log(evento_uuid)"
    )

    conn.executescript(_IMMUTABILITY_DDL)

    conn.commit()


def _init_from_schema(conn: sqlite3.Connection, schema_files: list) -> None:
    """Ejecuta los archivos de schema indicados (relativos a schema/) sobre `conn`."""
    schema_dir = "schema"
    for schema_file in schema_files:
        file_path = os.path.join(schema_dir, schema_file)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                conn.executescript(f.read())
        else:
            raise FileNotFoundError(f"Schema file not found: {file_path}")
    conn.commit()


def get_connection(db_path: str = "audit_trail.db") -> sqlite3.Connection:
    """
    Returns an SQLite connection to the specified database file.
    If the database doesn't exist, it creates it and initializes tables from SQL files.
    If it already exists, applies any pending additive migrations.

    Returns:
        sqlite3.Connection: Database connection object.
    """
    db_exists = os.path.exists(db_path)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA busy_timeout = 5000")

    if not db_exists:
        _init_from_schema(conn, ["usuarios.sql", "audit_log.sql"])
    else:
        _migrate_audit_log(conn)

    return conn


def get_central_connection(db_path: str = "audit_central.db") -> sqlite3.Connection:
    """
    HU-5.4 — Devuelve una conexión a la base de datos CENTRAL consolidada.

    Motor: SQLite en modo WAL (ver README.md — Base de datos central, para
    la justificación de esta elección frente a PostgreSQL). WAL permite que
    lectores y el escritor activo avancen sin bloquearse entre sí; el
    PRAGMA busy_timeout hace que escritores concurrentes esperen su turno
    en vez de fallar inmediatamente con "database is locked" (CA2).

    Incluye también la tabla `usuarios` (mismo schema/usuarios.sql que la
    base local, sin cambios): el dashboard Flask consulta y escribe TODO
    a través de esta conexión (autenticación, roles y eventos por igual)
    porque el dashboard es, en este diseño, parte de la infraestructura
    central — no un cliente intermitente como una notebook de Colab, que
    es lo que sí necesita el modelo de caché local + sincronización de
    HU-5.6/5.8.

    Si la base no existe, la crea a partir de usuarios.sql y
    audit_log_central.sql. Si ya existe, aplica las mismas migraciones
    aditivas que la base local (comparten el mismo esquema base de
    audit_log).

    Returns:
        sqlite3.Connection: Conexión a la base central.
    """
    db_exists = os.path.exists(db_path)

    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA busy_timeout = 5000")

    if not db_exists:
        _init_from_schema(conn, ["usuarios.sql", "audit_log_central.sql"])
    else:
        _migrate_audit_log(conn)

    return conn
