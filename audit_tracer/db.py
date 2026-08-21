import sqlite3
import os

# Columnas incorporadas a audit_log después de la versión inicial del schema.
# Se agregan con ALTER TABLE a bases de datos preexistentes que fueron creadas
# antes de que existieran, para que insert_event() no falle en silencio
# (HU-2.3 añadió filas_exportadas y sobrescritura para eventos EXPORTACION).
_AUDIT_LOG_MIGRATIONS = [
    ("filas_exportadas", "ALTER TABLE audit_log ADD COLUMN filas_exportadas INTEGER"),
    ("sobrescritura", "ALTER TABLE audit_log ADD COLUMN sobrescritura INTEGER"),
]


def _migrate_audit_log(conn: sqlite3.Connection) -> None:
    """Aplica migraciones aditivas pendientes sobre una tabla audit_log existente."""
    existing_columns = {row[1] for row in conn.execute("PRAGMA table_info(audit_log)")}
    if not existing_columns:
        return  # La tabla no existe todavía; la crea el script de schema.

    for column, alter_sql in _AUDIT_LOG_MIGRATIONS:
        if column not in existing_columns:
            conn.execute(alter_sql)
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

    if not db_exists:
        # Initialize database from schema files
        schema_dir = "schema"
        # Table order is important if there were FKs, but here they are independent
        schema_files = ["usuarios.sql", "audit_log.sql"]

        for schema_file in schema_files:
            file_path = os.path.join(schema_dir, schema_file)
            if os.path.exists(file_path):
                with open(file_path, "r", encoding="utf-8") as f:
                    sql_script = f.read()
                    conn.executescript(sql_script)
            else:
                raise FileNotFoundError(f"Schema file not found: {file_path}")

        conn.commit()
    else:
        _migrate_audit_log(conn)

    return conn
