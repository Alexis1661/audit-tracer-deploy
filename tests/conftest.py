"""
Aislamiento global de la suite (HU-5.1).

La librería guarda sus datos locales en ~/.audit_tracer (base local, llaves,
log de errores, token cacheado). Antes de que cualquier test importe
audit_tracer, el home se redirige a una carpeta temporal: la suite nunca
lee el token real del desarrollador (que la identificaría y abriría
conexiones al servidor central) ni escribe en su base local.
"""

import os
import tempfile

_HOME_TEMPORAL = tempfile.mkdtemp(prefix="audit_tracer_tests_home_")
os.environ["HOME"] = _HOME_TEMPORAL
os.environ["USERPROFILE"] = _HOME_TEMPORAL
os.environ.pop("AUDIT_TRACER_API_URL", None)

# HU-7.2 — app.py arranca un despachador de alertas enganchado a la base
# central real (audit_central.db). En la suite se apaga: las pruebas de
# alertas crean sus propios despachadores contra bases temporales y con un
# servicio de correo en memoria, así ningún test manda correos reales.
os.environ["AUDIT_ALERTAS_DESACTIVADAS"] = "1"
for _var in ("AUDIT_SMTP_HOST", "AUDIT_ALERTAS_OUTBOX", "AUDIT_DASHBOARD_URL"):
    os.environ.pop(_var, None)

def crear_sesion_web(client, usuario_id, rol, nombre=None, sesion_id="sesion-web-test"):
    """Prepara una cookie respaldada por un token de prueba sin agregar eventos."""
    import secrets
    from contextlib import closing
    from datetime import datetime, timezone

    import app
    from audit_tracer.models.tokens import insert_token

    with closing(app.get_db()) as conn:
        email = nombre if nombre and "@" in nombre else f"{usuario_id}@example.test"
        conn.execute(
            "INSERT OR IGNORE INTO usuarios (usuario_id, email, password_hash, rol) VALUES (?, ?, ?, ?)",
            (usuario_id, email, "unused", rol),
        )
        token_id = insert_token(conn, {
            "usuario_id": usuario_id,
            "token": secrets.token_urlsafe(32),
            "fecha_expiracion": (datetime.now(timezone.utc) + app.app.permanent_session_lifetime).isoformat(),
        })
    with client.session_transaction() as session:
        session.update(usuario_id=usuario_id, rol=rol, nombre=nombre or email, sesion_id=sesion_id, token_id=token_id)


def clonar_bd_web(conn, tmp_path, monkeypatch):
    """Entrega conexiones independientes a Flask a partir de una BD en memoria."""
    import sqlite3
    from contextlib import closing

    from audit_tracer.db import _init_from_schema, get_central_connection

    path = str(tmp_path / "central_web.db")
    with closing(sqlite3.connect(path)) as destination:
        conn.backup(destination)
        _init_from_schema(destination, ["usuarios.sql", "tokens.sql"])
    monkeypatch.setattr("app.get_db", lambda: get_central_connection(path))
