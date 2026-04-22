import sqlite3
import os

def get_connection() -> sqlite3.Connection:
    """
    Returns an SQLite connection to 'audit_trail.db' in the root directory.
    If the database doesn't exist, it creates it and initializes tables from SQL files.

    Returns:
        sqlite3.Connection: Database connection object.
    """
    db_path = "audit_trail.db"
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
        
    return conn
