"""
wsgi.py — Punto de entrada para servidores WSGI (Gunicorn).

SRV-I2 / SRV-D2 (21/11/2026): en producción el dashboard se sirve con
Gunicorn, no con el servidor de desarrollo de Flask:

    gunicorn wsgi:app --workers 1 --threads 8 --timeout 60 --bind 0.0.0.0:$PORT

Un solo proceso con varios hilos: la base central es SQLite (un escritor a la
vez) y el publicador horario de raíces de Merkle debe correr una sola vez.
Las tareas de arranque (cuentas sembradas, limpieza de códigos vencidos y
publicador de Merkle) son las mismas que con `python app.py`.
"""

from app import app, inicializar_servidor

inicializar_servidor()

__all__ = ["app"]
