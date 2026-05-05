import sqlite3
import os
import sys

# Añadir el directorio raíz al path para poder importar audit_tracer
sys.path.append(os.getcwd())

from audit_tracer.db import get_connection
from audit_tracer.auth.registro import register_user

def seed_admin():
    email = "admin@audit.com"
    password = "Admin123*"
    rol = "ADMIN"
    
    conn = get_connection()
    try:
        print(f"Intentando crear usuario admin: {email}...")
        user_id = register_user(conn, email, password, rol, admin_id="SISTEMA")
        print(f"¡Éxito! Usuario admin creado con ID: {user_id}")
        print(f"Credenciales:\n  Email: {email}\n  Password: {password}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    seed_admin()
