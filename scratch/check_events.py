import sqlite3
import os

db_path = "audit_trail.db"
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT timestamp, usuario_id, tipo_accion, contexto_ejecucion FROM audit_log ORDER BY timestamp DESC LIMIT 5")
        events = cursor.fetchall()
        print("Últimos 5 eventos:")
        for e in events:
            print(f"[{e[0]}] User: {e[1]} | Action: {e[2]} | Context: {e[3]}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
else:
    print("La base de datos no existe.")
