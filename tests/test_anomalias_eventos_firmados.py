"""
tests/test_anomalias_eventos_firmados.py
========================================
HU-6.3 — El detector de anomalías evalúa TODOS los eventos que recibe el
servidor, firmados o no y clasificados o no como CRITICO por la librería.

  * El historial de referencia es el anterior al evento y excluye su sesión.
  * Evento firmado: se guarda tal como llegó (su firma y su hash siguen siendo
    válidos) y el servidor agrega un evento ANOMALIA_DETECTADA que nombra las
    reglas activadas.
  * Evento sin firma: se reclasifica en el sitio; si ya era CRITICO conserva
    CRITICO y su motivo suma el nombre de cada regla.
  * La regla de exportación masiva de la librería no cambia.
"""

import sqlite3
import uuid
from datetime import datetime, timedelta

import pytest

import app as app_module
from audit_tracer.alerts.catalogo import clasificar_evento
from audit_tracer.anomaly_detector import (
    TIPO_EVENTO_ANOMALIA, nombres_reglas, obtener_horario_habitual,
)
from audit_tracer.auth.tokens import generar_token
from audit_tracer.db import get_central_connection
from audit_tracer.digital_signatures import (
    add_signature_to_event, generate_keypair, public_key_to_pem, verify_event_signature,
)
from audit_tracer.models.audit_log import _HASHED_COLUMNS, get_anomaly_events, insert_event
from audit_tracer.models.usuarios import create_user, set_user_public_key
from audit_tracer.utils.hashing import hash_event

HOY = datetime.utcnow().date()
MADRUGADA = datetime(HOY.year, HOY.month, HOY.day, 3, 10)  # 03:10 UTC, fuera de 07-19


@pytest.fixture
def servidor(monkeypatch, tmp_path):
    db_path = str(tmp_path / "central_anomalias.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    app_module.app.config["TESTING"] = True

    def conectar():
        conn = get_central_connection(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    conn = conectar()

    def crear(email, con_llave):
        usuario = create_user(conn, email, "Password123!", "CIENTIFICO_DATOS")
        privada = None
        if con_llave:  # con llave registrada, el servidor exige que todo evento venga firmado (HU-6.5)
            privada, publica = generate_keypair()
            set_user_public_key(conn, usuario, public_key_to_pem(publica))
        token = generar_token(conn, usuario)["token"]
        # Línea base: cinco días anteriores, 14:00-15:00 UTC, exportaciones de 100 a 180 filas.
        for dias, filas in zip(range(5, 0, -1), (100, 120, 140, 160, 180)):
            base = datetime(HOY.year, HOY.month, HOY.day, 14, 0) - timedelta(days=dias)
            for i, tipo in enumerate(("INICIO_SESION", "CARGA", "EXPORTACION", "CIERRE_SESION")):
                insert_event(conn, {
                    "usuario_id": usuario, "sesion_id": f"base-{dias}", "tipo_accion": tipo,
                    "timestamp": (base + timedelta(minutes=20 * i)).isoformat(),
                    "dataset_nombre": "LABEVENTS.csv" if tipo != "INICIO_SESION" else None,
                    "filas_exportadas": filas if tipo == "EXPORTACION" else None,
                    "nivel_alerta": "NORMAL"})
        return usuario, token, privada

    usuario, token, privada = crear("cientifica@x.co", True)
    sin_llave = crear("sin.llave@x.co", False)
    conn.close()
    with app_module.app.test_client() as client:
        yield client, conectar, usuario, token, privada, sin_llave


def _evento(usuario, sesion="sesion-noche", tipo="EXPORTACION", filas=76074, momento=MADRUGADA,
            nivel="CRITICO", motivo="Exportación masiva: 76074 filas (> 1000)", **extra):
    ev = {"evento_uuid": str(uuid.uuid4()), "usuario_id": usuario, "sesion_id": sesion,
          "timestamp": momento.isoformat(), "tipo_accion": tipo, "dataset_nombre": "LABEVENTS.csv",
          "filas_exportadas": filas if tipo == "EXPORTACION" else None, "nivel_alerta": nivel,
          "motivo_alerta": motivo if nivel == "CRITICO" else None}
    ev.update(extra)
    return ev


def _enviar(client, token, evento, privada=None):
    if privada is not None:
        evento = add_signature_to_event(evento, privada)
    resp = client.post("/api/eventos/sincronizar", json=evento, headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 201, resp.get_data(as_text=True)
    return evento


def _fila(conectar, evento_uuid):
    conn = conectar()
    try:
        return conn.execute("SELECT * FROM audit_log WHERE evento_uuid = ?", (evento_uuid,)).fetchone()
    finally:
        conn.close()


def _anomalias(conectar):
    conn = conectar()
    try:
        return [dict(f) for f in conn.execute(
            "SELECT * FROM audit_log WHERE tipo_accion = ? ORDER BY event_id", (TIPO_EVENTO_ANOMALIA,))]
    finally:
        conn.close()


class TestHistorialDeReferencia:

    def test_el_horario_habitual_excluye_la_sesion_en_curso(self, servidor):
        _, conectar, usuario, *_ = servidor
        conn = conectar()
        try:
            for minutos in (0, 5, 10, 15, 20, 25):  # una sesión entera de madrugada
                insert_event(conn, {"usuario_id": usuario, "sesion_id": "sesion-noche",
                                    "tipo_accion": "CARGA",
                                    "timestamp": (MADRUGADA + timedelta(minutes=minutos)).isoformat()})
            con_sesion = obtener_horario_habitual(conn, usuario)
            sin_sesion = obtener_horario_habitual(conn, usuario, excluir_sesion="sesion-noche")
        finally:
            conn.close()
        assert con_sesion[0] <= 2          # la madrugada ensancha el horario "habitual"
        assert sin_sesion[0] == 13         # línea base desde las 14:00, menos 1 h de margen

    def test_el_horario_habitual_solo_cuenta_eventos_anteriores(self, servidor):
        _, conectar, usuario, *_ = servidor
        conn = conectar()
        try:
            antes = (MADRUGADA - timedelta(days=30)).isoformat()
            assert obtener_horario_habitual(conn, usuario, antes_de=antes) == (7, 19)  # sin historial → defecto
        finally:
            conn.close()


class TestEventoFirmado:

    def test_exportacion_masiva_fuera_de_horario_activa_las_dos_reglas(self, servidor):
        client, conectar, usuario, token, privada, _ = servidor
        enviado = _enviar(client, token, _evento(usuario), privada)
        anomalias = _anomalias(conectar)
        assert len(anomalias) == 1
        a = anomalias[0]
        assert a["nivel_alerta"] == "ANOMALIA"
        assert a["usuario_id"] == usuario and a["sesion_id"] == "sesion-noche"
        assert a["motivo_alerta"].startswith("Anomalía (reglas: volumen anómalo, horario inusual)")
        assert "Volumen anómalo" in a["motivo_alerta"] and "Horario inusual" in a["motivo_alerta"]
        original = _fila(conectar, enviado["evento_uuid"])
        assert f"#{original['event_id']}" in a["contexto_ejecucion"]
        assert enviado["evento_uuid"] in a["contexto_ejecucion"]

    def test_el_evento_firmado_no_se_altera_y_conserva_la_regla_de_la_libreria(self, servidor):
        client, conectar, usuario, token, privada, _ = servidor
        enviado = _enviar(client, token, _evento(usuario), privada)
        fila = dict(_fila(conectar, enviado["evento_uuid"]))
        assert fila["nivel_alerta"] == "CRITICO"
        assert fila["motivo_alerta"] == "Exportación masiva: 76074 filas (> 1000)"
        conn = conectar()
        try:
            pem = conn.execute("SELECT llave_publica FROM usuarios WHERE usuario_id = ?", (usuario,)).fetchone()[0]
        finally:
            conn.close()
        assert verify_event_signature(fila, pem)                       # la firma sigue válida
        assert fila["hash_integridad"] == hash_event({c: enviado.get(c) for c in _HASHED_COLUMNS})

    def test_la_anomalia_aparece_en_la_consulta_de_anomalias(self, servidor):
        client, conectar, usuario, token, privada, _ = servidor
        _enviar(client, token, _evento(usuario), privada)
        conn = conectar()
        try:
            assert [e["tipo_accion"] for e in get_anomaly_events(conn)] == [TIPO_EVENTO_ANOMALIA]
        finally:
            conn.close()

    def test_la_anomalia_se_clasifica_como_critica_para_notificar(self, servidor):
        client, conectar, usuario, token, privada, _ = servidor
        _enviar(client, token, _evento(usuario), privada)
        conn = conectar()
        try:
            c = clasificar_evento(conn, dict(_anomalias(conectar)[0]))
        finally:
            conn.close()
        assert c is not None and "ANOMALIA_DETECTADA" in c.tipos

    def test_no_repite_la_anomalia_de_una_misma_sesion_y_mismas_reglas(self, servidor):
        client, conectar, usuario, token, privada, _ = servidor
        _enviar(client, token, _evento(usuario), privada)
        _enviar(client, token, _evento(usuario, momento=MADRUGADA + timedelta(minutes=2)), privada)
        assert len(_anomalias(conectar)) == 1

    def test_solo_horario_nombra_unicamente_esa_regla(self, servidor):
        client, conectar, usuario, token, privada, _ = servidor
        _enviar(client, token, _evento(usuario, tipo="CARGA", nivel="NORMAL"), privada)
        (a,) = _anomalias(conectar)
        assert a["motivo_alerta"].startswith("Anomalía (reglas: horario inusual)")
        assert nombres_reglas(["Horario inusual: x"]) == ["horario inusual"]

    def test_un_evento_normal_en_horario_no_genera_anomalia(self, servidor):
        client, conectar, usuario, token, privada, _ = servidor
        ahora = datetime(HOY.year, HOY.month, HOY.day, 14, 30)
        _enviar(client, token, _evento(usuario, filas=150, momento=ahora, nivel="NORMAL"), privada)
        assert _anomalias(conectar) == []

    def test_los_eventos_de_sesion_no_se_evaluan(self, servidor):
        client, conectar, usuario, token, privada, _ = servidor
        _enviar(client, token, _evento(usuario, tipo="INICIO_SESION", nivel="NORMAL"), privada)
        assert _anomalias(conectar) == []


class TestEventoSinFirma:

    def test_un_evento_critico_sin_firma_tambien_se_evalua_y_conserva_critico(self, servidor):
        client, conectar, _u, _t, _p, (usuario, token, _) = servidor
        enviado = _enviar(client, token, _evento(usuario))
        fila = _fila(conectar, enviado["evento_uuid"])
        assert fila["nivel_alerta"] == "CRITICO"
        assert fila["motivo_alerta"].startswith("Exportación masiva: 76074 filas (> 1000) | ")
        assert "Volumen anómalo" in fila["motivo_alerta"] and "Horario inusual" in fila["motivo_alerta"]
        assert _anomalias(conectar) == []   # sin firma se reclasifica en el sitio

    def test_un_evento_normal_sin_firma_pasa_a_anomalia(self, servidor):
        client, conectar, _u, _t, _p, (usuario, token, _) = servidor
        enviado = _enviar(client, token, _evento(usuario, tipo="CARGA", nivel="NORMAL"))
        fila = _fila(conectar, enviado["evento_uuid"])
        assert fila["nivel_alerta"] == "ANOMALIA" and "Horario inusual" in fila["motivo_alerta"]
