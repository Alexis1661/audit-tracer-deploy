"""
tests/test_seed_usuarios.py
===========================
Siembra de cuentas desde la variable de entorno SEED_USUARIOS, para despliegues
con disco efímero donde cada reinicio recrea la base vacía.
"""

import json

import pytest

import app as app_module
from audit_tracer.db import get_central_connection
from audit_tracer.models.audit_log import get_events
from audit_tracer.models.usuarios import get_user_by_email
from audit_tracer.utils.hashing import verify_password

CUENTAS = [
    {"email": "cientifico.p1@validacion.test", "password": "Clave-uno-123*", "rol": "CIENTIFICO_DATOS"},
    {"email": "auditor.p1@validacion.test", "password": "Clave-dos-456*", "rol": "AUDITOR"},
]


@pytest.fixture
def base(monkeypatch, tmp_path):
    ruta = str(tmp_path / "central_seed.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(ruta))
    monkeypatch.delenv("SEED_USUARIOS", raising=False)
    return ruta


def _usuario(ruta, email):
    conn = get_central_connection(ruta)
    try:
        return get_user_by_email(conn, email)
    finally:
        conn.close()


def test_sin_variable_no_crea_nada(base):
    app_module._seed_usuarios_desde_entorno()
    assert _usuario(base, CUENTAS[0]["email"]) is None


def test_crea_las_cuentas_con_su_rol_y_contrasena(base, monkeypatch):
    monkeypatch.setenv("SEED_USUARIOS", json.dumps(CUENTAS))
    app_module._seed_usuarios_desde_entorno()
    for cuenta in CUENTAS:
        usuario = _usuario(base, cuenta["email"])
        assert usuario["rol"] == cuenta["rol"]
        assert verify_password(cuenta["password"], usuario["password_hash"])


def test_es_idempotente_y_no_cambia_contrasenas(base, monkeypatch):
    monkeypatch.setenv("SEED_USUARIOS", json.dumps(CUENTAS))
    app_module._seed_usuarios_desde_entorno()
    cambiada = [{**CUENTAS[0], "password": "Otra-clave-789*"}, CUENTAS[1]]
    monkeypatch.setenv("SEED_USUARIOS", json.dumps(cambiada))
    app_module._seed_usuarios_desde_entorno()
    usuario = _usuario(base, CUENTAS[0]["email"])
    assert verify_password(CUENTAS[0]["password"], usuario["password_hash"])
    conn = get_central_connection(base)
    try:
        assert len(get_events(conn, tipo_accion="CREACION_USUARIO")) == len(CUENTAS)
    finally:
        conn.close()


def test_json_invalido_no_rompe_el_arranque(base, monkeypatch, capsys):
    monkeypatch.setenv("SEED_USUARIOS", "esto no es json")
    app_module._seed_usuarios_desde_entorno()
    assert "JSON inválido" in capsys.readouterr().out


def test_una_cuenta_mala_no_impide_crear_las_demas(base, monkeypatch, capsys):
    mezcla = [{"email": "x@validacion.test", "password": "Clave-123*", "rol": "HACKER"}, {"falta": "campos"}, CUENTAS[0]]
    monkeypatch.setenv("SEED_USUARIOS", json.dumps(mezcla))
    app_module._seed_usuarios_desde_entorno()
    assert _usuario(base, "x@validacion.test") is None
    assert _usuario(base, CUENTAS[0]["email"]) is not None
    assert "2 omitidas" in capsys.readouterr().out


def test_nunca_imprime_contrasenas(base, monkeypatch, capsys):
    monkeypatch.setenv("SEED_USUARIOS", json.dumps(CUENTAS + [{"email": "y@validacion.test", "password": "Secreta-999*", "rol": "HACKER"}]))
    app_module._seed_usuarios_desde_entorno()
    salida = capsys.readouterr().out
    assert not any(c["password"] in salida for c in CUENTAS)
    assert "Secreta-999*" not in salida
