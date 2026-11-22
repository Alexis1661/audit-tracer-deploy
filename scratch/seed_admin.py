"""
Crea el primer administrador en la base central (audit_central.db).

B5 / B10 (21/11/2026): la contraseña ya no está escrita aquí. Se toma de
AUDIT_ADMIN_PASSWORD; si no está, se pide por teclado (sin eco); y si no hay
teclado (p. ej. un despliegue), se genera una aleatoria y se muestra una vez.
Debe cumplir la política de contraseñas (audit_tracer/auth/politica_contrasenas.py).

    python scratch/seed_admin.py
"""
import getpass
import os
import secrets
import sys

# Añadir el directorio raíz al path para poder importar audit_tracer
sys.path.append(os.getcwd())

from audit_tracer.db import get_central_connection
from audit_tracer.auth.registro import register_user


def _contrasena() -> tuple:
    valor = os.environ.get("AUDIT_ADMIN_PASSWORD", "").strip()
    if valor:
        return valor, False
    if sys.stdin.isatty():
        return getpass.getpass("Contraseña para admin@audit.com (mín. 8 caracteres, 3 tipos): "), False
    return f"Admin-{secrets.token_urlsafe(9)}-7", True


def seed_admin():
    email = os.environ.get("AUDIT_ADMIN_EMAIL", "admin@audit.com")
    rol = "ADMIN"
    password, generada = _contrasena()

    # HU-5.4: el dashboard (app.py::get_db()) lee y escribe contra la base
    # central, no la local — hay que sembrar el admin ahí para poder
    # iniciar sesión en la app web.
    conn = get_central_connection()
    try:
        print(f"Intentando crear usuario admin: {email}...")
        user_id = register_user(conn, email, password, rol, admin_id="SISTEMA")
        print(f"¡Éxito! Usuario admin creado con ID: {user_id}")
        if generada:
            print(f"Contraseña generada (guárdala ahora, no se vuelve a mostrar): {password}")
    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Error inesperado: {e}")
    finally:
        conn.close()


if __name__ == "__main__":
    seed_admin()
