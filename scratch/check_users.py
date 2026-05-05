import sqlite3
import os

db_path = "audit_trail.db"
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT email, rol FROM usuarios")
        users = cursor.fetchall()
        if users:
            print("Usuarios encontrados:")
            for user in users:
                print(f"Email: {user[0]}, Rol: {user[1]}")
        else:
            print("No hay usuarios en la base de datos.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        conn.close()
else:
    print("La base de datos no existe.")
