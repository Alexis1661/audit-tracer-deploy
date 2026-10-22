"""
tests/test_ataques_simulados.py
================================
HU-6.5 — Casos de prueba de ataque simulado.

Cada prueba actúa como un atacante, no como un usuario legítimo: escribe
directo en el archivo SQLite, se salta la interfaz, forja cookies, reutiliza
tokens dados de baja o manda eventos con la firma alterada. Cada caso verifica
que el sistema DETECTA o BLOQUEA el intento y que el bloqueo queda en audit_log.

  CA1 — Modificación directa del SQLite local (sin pasar por la aplicación).
  CA2 — Acceso a un módulo sin el rol correspondiente.
  CA3 — Reutilización de un token revocado o expirado.
  CA4 — Evento con firma inválida o manipulada.

Resultados documentados en docs/validacion_resultados.md (CA5).
"""

import sqlite3
import uuid
from datetime import datetime, timedelta

import pytest
from flask import Flask
from flask.sessions import SecureCookieSessionInterface

import app as app_module
from audit_tracer.auth.tokens import generar_token, revocar_token
from audit_tracer.db import get_central_connection, get_connection
from audit_tracer.digital_signatures import (
    generate_keypair, public_key_to_pem, sign_event, verify_signature,
)
from audit_tracer.models.audit_log import get_events, insert_event, verify_integrity
from audit_tracer.models.usuarios import create_user, get_user_by_email, set_user_public_key
from audit_tracer.utils.hashing import hash_event

CLAVE_SESION_ANTIGUA = "audit_tracer_dev_key_2026"   # estuvo fija en app.py y es pública


# ──────────────────────────────────────────────────────────────
# FIXTURES Y HELPERS
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def servidor(monkeypatch, tmp_path):
    """Dashboard Flask real contra una base central temporal."""
    db_path = str(tmp_path / "central_ataques.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    app_module.app.config["TESTING"] = True

    def conectar():
        conn = get_central_connection(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    with app_module.app.test_client() as client:
        yield client, conectar


def _crear_usuario(conectar, email: str, rol: str, password: str = "Password123!") -> str:
    conn = conectar()
    try:
        return create_user(conn, email, password, rol)
    finally:
        conn.close()


def _login(client, email: str, password: str = "Password123!") -> None:
    resp = client.post("/login", data={"email": email, "password": password})
    assert resp.status_code == 302, "El login legítimo debe funcionar antes del ataque"


def _eventos(conectar, **filtros) -> list:
    conn = conectar()
    try:
        return get_events(conn, **filtros)
    finally:
        conn.close()


def _evento(usuario_id: str, **extra) -> dict:
    evento = {
        "evento_uuid": str(uuid.uuid4()),
        "usuario_id": usuario_id,
        "sesion_id": "sesion-colab-1",
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": "EXPORTACION",
        "dataset_nombre": "PATIENTS.csv",
        "ruta_destino": "/content/salida.csv",
        "filas_exportadas": 10,
        "nivel_alerta": "NORMAL",
    }
    evento.update(extra)
    return evento


def _sincronizar(client, token: str, evento: dict):
    return client.post(
        "/api/eventos/sincronizar", json=evento,
        headers={"Authorization": f"Bearer {token}"},
    )


def _evento_guardado(conectar, evento_uuid: str) -> bool:
    conn = conectar()
    try:
        return conn.execute(
            "SELECT 1 FROM audit_log WHERE evento_uuid = ?", (evento_uuid,)
        ).fetchone() is not None
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════
# CA1 — Modificación directa del SQLite local
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def base_local(tmp_path):
    """Base local con eventos legítimos; el atacante tiene acceso al archivo."""
    ruta = str(tmp_path / "audit_trail.db")
    conn = get_connection(ruta)
    ids = [
        insert_event(conn, _evento("u-ana", tipo_accion="CARGA", filas_exportadas=None)),
        insert_event(conn, _evento("u-ana", filas_exportadas=5000, nivel_alerta="CRITICO",
                                   motivo_alerta="Exportación masiva: 5000 filas (> 1000)")),
        insert_event(conn, _evento("u-ana", tipo_accion="CONSULTA", filas_exportadas=None)),
    ]
    conn.close()
    return ruta, ids


def _atacante(ruta: str) -> sqlite3.Connection:
    """Conexión cruda al archivo, sin pasar por audit_tracer."""
    return sqlite3.connect(ruta)


def _quitar_triggers(atacante: sqlite3.Connection) -> None:
    atacante.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_update")
    atacante.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_delete")


def _verificar(ruta: str) -> list:
    conn = sqlite3.connect(ruta)   # lectura cruda: get_connection volvería a crear los triggers
    try:
        return verify_integrity(conn)
    finally:
        conn.close()


class TestCA1ManipulacionDirectaSQLite:
    def test_update_directo_es_bloqueado_y_queda_registrado(self, base_local):
        ruta, ids = base_local
        atacante = _atacante(ruta)

        with pytest.raises(sqlite3.DatabaseError, match="INMUTABILIDAD"):
            atacante.execute("UPDATE audit_log SET nivel_alerta = 'NORMAL' WHERE event_id = ?", (ids[1],))
        atacante.commit()

        nivel = atacante.execute("SELECT nivel_alerta FROM audit_log WHERE event_id = ?", (ids[1],)).fetchone()[0]
        intento = atacante.execute(
            "SELECT tipo_intento, event_id_objetivo FROM audit_intentos_bloqueados"
        ).fetchall()
        atacante.close()

        assert nivel == "CRITICO"
        assert intento == [("INTENTO_MODIFICACION", ids[1])]

    def test_delete_directo_es_bloqueado_y_queda_registrado(self, base_local):
        ruta, ids = base_local
        atacante = _atacante(ruta)

        with pytest.raises(sqlite3.DatabaseError, match="INMUTABILIDAD"):
            atacante.execute("DELETE FROM audit_log WHERE event_id = ?", (ids[1],))
        atacante.commit()

        total = atacante.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        intento = atacante.execute("SELECT tipo_intento FROM audit_intentos_bloqueados").fetchall()
        atacante.close()

        assert total == 3
        assert intento == [("INTENTO_ELIMINACION",)]

    @pytest.mark.parametrize("campo, valor", [
        ("usuario_id", "u-otro"),                  # atribuir el evento a otra persona
        ("nivel_alerta", "NORMAL"),                # esconder una alerta CRITICO
        ("filas_exportadas", 10),                  # ocultar una exportación masiva
        ("timestamp", "2020-01-01T00:00:00"),      # mover el evento en el tiempo
        ("tipo_accion", "CONSULTA"),               # disfrazar la operación
        ("ruta_destino", "/tmp/otro.csv"),         # cambiar a dónde se fueron los datos
    ])
    def test_alteracion_saltandose_los_triggers_la_detecta_verify_integrity(self, base_local, campo, valor):
        ruta, ids = base_local
        assert _verificar(ruta) == []   # punto de partida: base íntegra

        atacante = _atacante(ruta)
        _quitar_triggers(atacante)
        atacante.execute(f"UPDATE audit_log SET {campo} = ? WHERE event_id = ?", (valor, ids[1]))
        atacante.commit()
        atacante.close()

        alterados = _verificar(ruta)
        assert [r["event_id"] for r in alterados] == [ids[1]]
        assert alterados[0]["stored_hash"] != alterados[0]["calculated_hash"]

    def test_hash_recalculado_lo_detecta_la_firma_digital(self, tmp_path):
        """
        Atacante que conoce el algoritmo: altera el campo Y recalcula el
        SHA-256 (es público). verify_integrity() ya no lo ve — límite
        documentado —, pero la firma Ed25519 sí, porque el atacante no tiene
        la llave privada del usuario.
        """
        ruta = str(tmp_path / "audit_trail.db")
        privada, publica = generate_keypair()
        evento = _evento("u-ana", filas_exportadas=5000, nivel_alerta="CRITICO")
        evento["firma_digital"] = sign_event(evento, privada)
        conn = get_connection(ruta)
        event_id = insert_event(conn, evento)
        conn.close()

        atacante = _atacante(ruta)
        atacante.row_factory = sqlite3.Row
        _quitar_triggers(atacante)
        fila = dict(atacante.execute("SELECT * FROM audit_log WHERE event_id = ?", (event_id,)).fetchone())
        fila.update(filas_exportadas=10, nivel_alerta="NORMAL")
        from audit_tracer.models.audit_log import _HASHED_COLUMNS
        nuevo_hash = hash_event({c: fila[c] for c in _HASHED_COLUMNS})
        atacante.execute(
            "UPDATE audit_log SET filas_exportadas = 10, nivel_alerta = 'NORMAL', hash_integridad = ? "
            "WHERE event_id = ?", (nuevo_hash, event_id),
        )
        atacante.commit()
        atacante.close()

        assert _verificar(ruta) == []   # límite: el hash solo no basta contra este atacante
        conn = sqlite3.connect(ruta)
        resultado = verify_signature(conn, event_id, public_key_to_pem(publica))
        conn.close()
        assert resultado["firma_presente"] is True
        assert resultado["firma_valida"] is False


# ══════════════════════════════════════════════════════════════
# CA2 — Acceso a un módulo sin el rol correspondiente
# ══════════════════════════════════════════════════════════════

class TestCA2AccesoSinRol:
    def test_cientifico_de_datos_no_puede_consultar_eventos(self, servidor):
        client, conectar = servidor
        uid = _crear_usuario(conectar, "cientifico@test.com", "CIENTIFICO_DATOS")
        _login(client, "cientifico@test.com")

        resp = client.get("/eventos")

        assert resp.status_code == 403
        denegados = _eventos(conectar, tipo_accion="ACCESO_DENEGADO", usuario_id=uid)
        assert len(denegados) == 1
        assert "consulta_reportes" in denegados[0]["motivo_fallo"]

    def test_analista_no_puede_crearse_un_usuario_admin(self, servidor):
        """Escalada de privilegios: POST directo al formulario de administración."""
        client, conectar = servidor
        uid = _crear_usuario(conectar, "analista@test.com", "ANALISTA")
        _login(client, "analista@test.com")

        resp = client.post("/admin/usuarios/nuevo", data={
            "email": "intruso@test.com", "password": "Intruso123!",
            "confirmar_password": "Intruso123!", "rol": "ADMIN",
        })

        assert resp.status_code == 302 and "/dashboard" in resp.headers["Location"]
        conn = conectar()
        assert get_user_by_email(conn, "intruso@test.com") is None
        conn.close()
        denegados = _eventos(conectar, tipo_accion="ACCESO_DENEGADO", usuario_id=uid)
        assert len(denegados) == 1
        assert "administracion" in denegados[0]["motivo_fallo"]
        assert "Método: POST" in denegados[0]["contexto_ejecucion"]

    def test_analista_no_puede_generar_tokens_para_otro_usuario(self, servidor):
        client, conectar = servidor
        victima = _crear_usuario(conectar, "victima@test.com", "ANALISTA")
        uid = _crear_usuario(conectar, "analista@test.com", "ANALISTA")
        _login(client, "analista@test.com")

        client.post("/admin/tokens/nuevo", data={"usuario_id": victima, "dias_expiracion": "30"})

        conn = conectar()
        tokens_victima = conn.execute(
            "SELECT COUNT(*) FROM tokens_acceso WHERE usuario_id = ?", (victima,)
        ).fetchone()[0]
        conn.close()
        assert tokens_victima == 0
        assert len(_eventos(conectar, tipo_accion="ACCESO_DENEGADO", usuario_id=uid)) == 1

    def test_sin_sesion_no_se_llega_a_la_administracion(self, servidor):
        client, _ = servidor
        resp = client.get("/admin/usuarios")
        assert resp.status_code == 302 and "/login" in resp.headers["Location"]

    def test_cookie_de_sesion_forjada_con_la_clave_antigua_no_da_acceso(self, servidor):
        """
        La clave de sesión estuvo fija en el código (repositorio público): un
        atacante podía firmar su propia cookie con rol=ADMIN.
        """
        client, _ = servidor
        assert app_module.app.secret_key != CLAVE_SESION_ANTIGUA

        falsa = Flask("atacante")
        falsa.secret_key = CLAVE_SESION_ANTIGUA
        cookie = SecureCookieSessionInterface().get_signing_serializer(falsa).dumps({
            "usuario_id": "admin-falso", "rol": "ADMIN", "nombre": "atacante", "sesion_id": "x",
        })
        client.set_cookie("session", cookie)

        resp = client.get("/admin/usuarios")
        assert resp.status_code == 302 and "/login" in resp.headers["Location"]


# ══════════════════════════════════════════════════════════════
# CA3 — Reutilización de un token revocado o expirado
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def usuario_con_token(servidor):
    client, conectar = servidor
    uid = _crear_usuario(conectar, "colab@test.com", "CIENTIFICO_DATOS")
    conn = conectar()
    token = generar_token(conn, uid)
    conn.close()
    return client, conectar, uid, token


def _rechazos(conectar) -> list:
    return _eventos(conectar, tipo_accion="SINCRONIZACION_RECHAZADA")


class TestCA3TokenRevocadoOExpirado:
    def test_token_revocado_deja_de_funcionar_de_inmediato(self, usuario_con_token):
        client, conectar, uid, token = usuario_con_token
        legitimo = _evento(uid)
        assert _sincronizar(client, token["token"], legitimo).status_code == 201

        conn = conectar()
        revocar_token(conn, token["token_id"], admin_id="admin")
        conn.close()

        robado = _evento(uid)
        resp = _sincronizar(client, token["token"], robado)

        assert resp.status_code == 401
        assert resp.get_json()["mensaje"] == "Token revocado"
        assert not _evento_guardado(conectar, robado["evento_uuid"])
        assert [r["motivo_fallo"] for r in _rechazos(conectar)] == ["Token revocado"]

    def test_token_expirado_es_rechazado(self, servidor):
        client, conectar = servidor
        uid = _crear_usuario(conectar, "colab@test.com", "CIENTIFICO_DATOS")
        conn = conectar()
        vencido = generar_token(conn, uid, fecha_expiracion_custom=(datetime.utcnow() - timedelta(days=1)).isoformat())
        conn.close()

        evento = _evento(uid)
        resp = _sincronizar(client, vencido["token"], evento)

        assert resp.status_code == 401
        assert resp.get_json()["mensaje"] == "Token expirado"
        assert not _evento_guardado(conectar, evento["evento_uuid"])
        conn = conectar()
        estado = conn.execute("SELECT estado FROM tokens_acceso WHERE token_id = ?", (vencido["token_id"],)).fetchone()[0]
        conn.close()
        assert estado == "EXPIRADO"

    @pytest.mark.parametrize("alterar", [
        lambda t: t[:-1] + ("A" if t[-1] != "A" else "B"),   # token adivinado / alterado
        lambda t: "tk_" + "x" * 43,                           # token inventado
        lambda t: "",                                         # sin token
    ])
    def test_token_falso_o_ausente_es_rechazado(self, usuario_con_token, alterar):
        client, conectar, uid, token = usuario_con_token
        evento = _evento(uid)
        resp = _sincronizar(client, alterar(token["token"]), evento)
        assert resp.status_code == 401
        assert not _evento_guardado(conectar, evento["evento_uuid"])
        assert len(_rechazos(conectar)) == 1

    def test_validar_token_revocado_por_la_api_responde_invalido(self, usuario_con_token):
        client, conectar, _, token = usuario_con_token
        conn = conectar()
        revocar_token(conn, token["token_id"], admin_id="admin")
        conn.close()

        resp = client.post("/api/tokens/validar", json={"token": token["token"]})
        assert resp.status_code == 401
        assert resp.get_json()["valido"] is False


# ══════════════════════════════════════════════════════════════
# CA4 — Evento con firma inválida o manipulada
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def usuario_con_llave(usuario_con_token):
    client, conectar, uid, token = usuario_con_token
    privada, publica = generate_keypair()
    conn = conectar()
    set_user_public_key(conn, uid, public_key_to_pem(publica))
    conn.close()
    return client, conectar, uid, token["token"], privada


def _firmado(evento: dict, privada) -> dict:
    evento = dict(evento)
    evento["firma_digital"] = sign_event(evento, privada)
    return evento


def _firmas_invalidas(conectar) -> list:
    return _eventos(conectar, tipo_accion="FIRMA_INVALIDA")


class TestCA4FirmaInvalida:
    def test_evento_firmado_correctamente_se_acepta(self, usuario_con_llave):
        client, conectar, uid, token, privada = usuario_con_llave
        evento = _firmado(_evento(uid), privada)
        assert _sincronizar(client, token, evento).status_code == 201
        assert _evento_guardado(conectar, evento["evento_uuid"])

    @pytest.mark.parametrize("campo, valor", [
        ("filas_exportadas", 50000),        # inflar/ocultar el volumen exportado
        ("nivel_alerta", "CRITICO"),
        ("dataset_nombre", "OTRO.csv"),
        ("timestamp", "2020-01-01T00:00:00"),
        ("ruta_destino", "/tmp/fuga.csv"),
    ])
    def test_evento_manipulado_despues_de_firmar_es_rechazado(self, usuario_con_llave, campo, valor):
        client, conectar, uid, token, privada = usuario_con_llave
        evento = _firmado(_evento(uid), privada)
        evento[campo] = valor

        resp = _sincronizar(client, token, evento)

        assert resp.status_code == 422
        assert not _evento_guardado(conectar, evento["evento_uuid"])
        registros = _firmas_invalidas(conectar)
        assert len(registros) == 1 and registros[0]["nivel_alerta"] == "CRITICO"

    def test_evento_firmado_con_otra_llave_es_rechazado(self, usuario_con_llave):
        client, conectar, uid, token, _ = usuario_con_llave
        llave_del_atacante, _ = generate_keypair()
        evento = _firmado(_evento(uid), llave_del_atacante)

        assert _sincronizar(client, token, evento).status_code == 422
        assert not _evento_guardado(conectar, evento["evento_uuid"])
        assert len(_firmas_invalidas(conectar)) == 1

    @pytest.mark.parametrize("firma", ["AAAA", "no-es-base64-%%%", "A" * 86])
    def test_firma_basura_es_rechazada(self, usuario_con_llave, firma):
        client, conectar, uid, token, _ = usuario_con_llave
        evento = _evento(uid, firma_digital=firma)
        assert _sincronizar(client, token, evento).status_code == 422
        assert not _evento_guardado(conectar, evento["evento_uuid"])

    def test_quitar_la_firma_no_salta_la_verificacion(self, usuario_con_llave):
        """Ataque de degradación: mandar el evento manipulado sin firma."""
        client, conectar, uid, token, privada = usuario_con_llave
        evento = _firmado(_evento(uid), privada)
        evento["filas_exportadas"] = 1
        del evento["firma_digital"]

        resp = _sincronizar(client, token, evento)

        assert resp.status_code == 422
        assert not _evento_guardado(conectar, evento["evento_uuid"])
        assert "sin firma" in _firmas_invalidas(conectar)[0]["motivo_fallo"]

    def test_reenviar_un_evento_valido_no_lo_duplica(self, usuario_con_llave):
        """Repetición (replay) de un evento legítimo capturado en tránsito."""
        client, conectar, uid, token, privada = usuario_con_llave
        evento = _firmado(_evento(uid), privada)

        assert _sincronizar(client, token, evento).status_code == 201
        segunda = _sincronizar(client, token, evento)

        assert segunda.status_code == 200 and segunda.get_json()["status"] == "duplicado"
        conn = conectar()
        copias = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE evento_uuid = ?", (evento["evento_uuid"],)
        ).fetchone()[0]
        conn.close()
        assert copias == 1
