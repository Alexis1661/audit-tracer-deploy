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
for _var in ("AUDIT_SMTP_HOST", "AUDIT_ALERTAS_OUTBOX", "AUDIT_DASHBOARD_URL",
             "AUDIT_TRACER_KEY_PASSPHRASE", "AUDIT_EXIGIR_FIRMA", "AUDIT_TSA_URL"):
    os.environ.pop(_var, None)

# LIB-I2 — la suite nunca escribe en el llavero real del sistema operativo
# (Administrador de credenciales de Windows, Llavero de macOS): las pruebas del
# cifrado de la llave usan un llavero en memoria.
os.environ["AUDIT_TRACER_KEYRING"] = "0"

import secrets as _secrets  # noqa: E402

import pytest  # noqa: E402
from flask.testing import FlaskClient  # noqa: E402

_METODOS_SEGUROS = ("GET", "HEAD", "OPTIONS", "TRACE")


class ClienteConCsrf(FlaskClient):
    """
    DSH-T1 — Simula el navegador: todo POST lleva el token CSRF de su sesión,
    como lo hacen los formularios del dashboard. Una prueba que quiera
    simular un formulario de otro sitio pasa csrf=False.
    """

    def open(self, *args, **kwargs):
        csrf = kwargs.pop("csrf", True)
        metodo = str(kwargs.get("method") or "GET").upper()
        if csrf and metodo not in _METODOS_SEGUROS and not (args and not isinstance(args[0], str)):
            token = None
            try:
                with self.session_transaction() as sesion:
                    token = sesion.get("_csrf")
                    if not token:
                        token = _secrets.token_urlsafe(32)
                        sesion["_csrf"] = token
            except (TypeError, RuntimeError):
                token = None
            if token:
                cabeceras = dict(kwargs.get("headers") or {})
                cabeceras.setdefault("X-CSRF-Token", token)
                kwargs["headers"] = cabeceras
        return super().open(*args, **kwargs)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "horario_real: usa el horario laboral real en la clasificación del servidor (SRV-T3)")
    import app as _app
    _app.app.test_client_class = ClienteConCsrf


@pytest.fixture(autouse=True)
def _servidor_en_estado_limpio(request, monkeypatch):
    """
    Cada prueba empieza con los contadores de límite de peticiones y de
    consultas a la bitácora en cero, y con la clasificación del servidor
    (SRV-T3) en horario laboral, para que el resultado no dependa de la hora
    a la que se corre la suite (salvo en las pruebas marcadas horario_real).
    """
    import sys
    modulo_app = sys.modules.get("app")
    if modulo_app is not None:
        modulo_app.limitador.reiniciar()
        modulo_app._ultimas_consultas.clear()
    if request.node.get_closest_marker("horario_real") is None:
        monkeypatch.setattr("audit_tracer.clasificacion_servidor.es_horario_laboral", lambda dt: True)
    yield

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
