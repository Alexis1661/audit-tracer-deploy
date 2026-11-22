"""
tests/test_robustez.py
======================
Pruebas de los arreglos de robustez del 21/11/2026 que no son del modelo
STRIDE propiamente (ese está en test_modelo_amenazas.py):

  * B3 / SRV-I1  tokens y códigos de dispositivo guardados como SHA-256
  * B5           política de contraseñas en register_user()
  * B6 / DSH-D1  bloqueo temporal, desbloqueo automático y por ADMIN
  * SRV-D1       límite de peticiones (login y sincronización)
  * SRV-I2       mensajes de error genéricos y depuración apagada por defecto
  * SRV-R3, DSH-D2  rechazos registrados; verificación completa solo ADMIN/AUDITOR
  * CAN-I2, CAN-S2  polling por POST; origen del código en la confirmación
  * B8           gestión de roles (assign_role)
  * B7           retención y archivo verificable
  * SRV-T2       sello de tiempo RFC 3161 (con una TSA de prueba local)
  * LIB-I2       llave privada cifrada (frase o llavero)
  * LIB-D2       sesiones de la librería sin cierre
  * Envío real por SMTP contra un servidor SMTP local
"""

import json
import os
import secrets
import socketserver
import sqlite3
import threading
from datetime import datetime, timedelta, timezone

import pytest

import app as app_module
from audit_tracer.auth.autenticacion import login as auth_login
from audit_tracer.auth.gestion_roles import assign_role
from audit_tracer.auth.registro import register_user
from audit_tracer.auth.tokens import generar_token, validar_token
from audit_tracer.db import get_central_connection, get_connection
from audit_tracer.models.audit_log import get_events, insert_event
from audit_tracer.models.tokens import hash_token, insert_token
from audit_tracer.models.usuarios import create_user, get_user_by_id

CLAVE = "Clave-Robusta-2026"


@pytest.fixture
def central(monkeypatch, tmp_path):
    ruta = str(tmp_path / "central_robustez.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(ruta))
    app_module.app.config["TESTING"] = True

    def conectar():
        conn = get_central_connection(ruta)
        conn.row_factory = sqlite3.Row
        return conn

    with app_module.app.test_client() as client:
        yield client, conectar


def _usuario(conectar, email, rol="ANALISTA"):
    conn = conectar()
    try:
        return create_user(conn, email, CLAVE, rol)
    finally:
        conn.close()


def _sesion(client, conectar, usuario_id, rol):
    conn = conectar()
    try:
        conn.execute("INSERT OR IGNORE INTO usuarios (usuario_id, email, password_hash, rol) VALUES (?, ?, ?, ?)",
                     (usuario_id, f"{usuario_id}@x.test", "no-usado", rol))
        conn.commit()
        token_id = insert_token(conn, {
            "usuario_id": usuario_id, "token": secrets.token_urlsafe(32),
            "fecha_expiracion": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()})
    finally:
        conn.close()
    with client.session_transaction() as sess:
        sess.update(usuario_id=usuario_id, rol=rol, nombre="t", sesion_id="s-robustez", token_id=token_id)


# ── B3 / SRV-I1 ────────────────────────────────────────────────────────────

class TestTokensComoHash:

    def test_un_token_en_claro_de_una_version_anterior_se_migra(self, tmp_path):
        from audit_tracer.models import tokens as modelo
        ruta = str(tmp_path / "vieja.db")
        conn = get_central_connection(ruta)
        uid = create_user(conn, "a@x.co", CLAVE, "ANALISTA")
        # Fila tal como la dejaba la versión anterior: el token en claro.
        conn.execute("INSERT INTO tokens_acceso (token_id, usuario_id, token, fecha_creacion, fecha_expiracion) "
                     "VALUES ('t1', ?, 'tk_valor_en_claro', ?, ?)",
                     (uid, datetime.utcnow().isoformat(), (datetime.utcnow() + timedelta(days=1)).isoformat()))
        conn.commit()
        conn.close()
        modelo._tablas_migradas.clear()
        conn = get_central_connection(ruta)   # la migración corre al abrir la base
        try:
            guardado = conn.execute("SELECT token, token_sufijo FROM tokens_acceso WHERE token_id = 't1'").fetchone()
            assert tuple(guardado) == (hash_token("tk_valor_en_claro"), "laro")
            assert validar_token(conn, "tk_valor_en_claro")[0] is True
        finally:
            conn.close()

    def test_presentar_el_hash_leido_de_la_base_no_autentica(self, central):
        _, conectar = central
        uid = _usuario(conectar, "a@x.co")
        conn = conectar()
        try:
            token = generar_token(conn, uid)["token"]
            guardado = conn.execute("SELECT token FROM tokens_acceso WHERE usuario_id = ?", (uid,)).fetchone()[0]
            assert token not in guardado
            assert validar_token(conn, guardado)[0] is False
            assert validar_token(conn, token)[0] is True
        finally:
            conn.close()

    def test_el_admin_ve_el_token_una_sola_vez(self, central):
        client, conectar = central
        uid = _usuario(conectar, "cientifico@x.co", "CIENTIFICO_DATOS")
        _sesion(client, conectar, "admin-1", "ADMIN")
        html = client.post("/admin/tokens/nuevo", data={"usuario_id": uid, "dias_expiracion": "30"}).get_data(as_text=True)
        assert "no se volverá a mostrar" in html
        conn = conectar()
        try:
            sufijo = conn.execute("SELECT token_sufijo FROM tokens_acceso WHERE usuario_id = ?", (uid,)).fetchone()[0]
        finally:
            conn.close()
        lista = client.get("/admin/tokens").get_data(as_text=True)
        assert f"tk_…{sufijo}" in lista and "no se volverá a mostrar" not in lista


# ── B5 ─────────────────────────────────────────────────────────────────────

class TestPoliticaDeContrasenas:

    @pytest.mark.parametrize("debil", ["corta1!", "solominusculas", "Password123!", "12345678", "ana.perez-2026A"])
    def test_register_user_rechaza_contrasenas_debiles(self, debil):
        conn = get_connection(":memory:")
        try:
            with pytest.raises(ValueError, match="Contraseña no válida"):
                register_user(conn, "ana.perez@x.co", debil, "ANALISTA", "admin")
        finally:
            conn.close()

    def test_register_user_acepta_una_contrasena_robusta(self):
        conn = get_connection(":memory:")
        try:
            assert register_user(conn, "ana@x.co", CLAVE, "ANALISTA", "admin")
        finally:
            conn.close()

    def test_el_formulario_muestra_los_incumplimientos(self, central):
        client, conectar = central
        _sesion(client, conectar, "admin-1", "ADMIN")
        html = client.post("/admin/usuarios/nuevo", data={
            "email": "n@x.co", "password": "abcdefgh", "confirmar_password": "abcdefgh", "rol": "ANALISTA",
        }).get_data(as_text=True)
        assert "tres de" in html


# ── B6 / DSH-D1 ────────────────────────────────────────────────────────────

class TestBloqueoTemporal:

    def _fallar(self, conn, email, veces=5):
        for _ in range(veces):
            resultado = auth_login(conn, email, "incorrecta", "s")
        return resultado

    def test_el_bloqueo_es_temporal_y_se_levanta_solo(self):
        conn = get_connection(":memory:")
        try:
            uid = register_user(conn, "a@x.co", CLAVE, "ANALISTA", "admin")
            assert "bloqueada" in self._fallar(conn, "a@x.co")["message"]
            usuario = get_user_by_id(conn, uid)
            assert usuario["activo"] == 0 and usuario["bloqueado_hasta"]
            assert auth_login(conn, "a@x.co", CLAVE, "s")["success"] is False   # todavía bloqueada
            conn.execute("UPDATE usuarios SET bloqueado_hasta = ? WHERE usuario_id = ?",
                         ((datetime.utcnow() - timedelta(minutes=1)).isoformat(), uid))
            conn.commit()
            assert auth_login(conn, "a@x.co", CLAVE, "s")["success"] is True
            assert get_events(conn, tipo_accion="DESBLOQUEO_CUENTA")
        finally:
            conn.close()

    def test_el_admin_desbloquea_y_queda_registrado(self, central):
        client, conectar = central
        uid = _usuario(conectar, "bloqueado@x.co")
        conn = conectar()
        try:
            self._fallar(conn, "bloqueado@x.co")
        finally:
            conn.close()
        _sesion(client, conectar, "admin-1", "ADMIN")
        resp = client.post(f"/admin/usuarios/{uid}/desbloquear")
        assert resp.status_code == 302
        conn = conectar()
        try:
            assert get_user_by_id(conn, uid)["activo"] == 1
            (evento,) = get_events(conn, usuario_id="admin-1", tipo_accion="DESBLOQUEO_CUENTA")
            assert uid in evento["contexto_ejecucion"]
        finally:
            conn.close()

    def test_un_analista_no_puede_desbloquear(self, central):
        client, conectar = central
        uid = _usuario(conectar, "bloqueado@x.co")
        _sesion(client, conectar, "analista-1", "ANALISTA")
        client.post(f"/admin/usuarios/{uid}/desbloquear")
        conn = conectar()
        try:
            assert not get_events(conn, tipo_accion="DESBLOQUEO_CUENTA")
        finally:
            conn.close()


# ── SRV-D1 ─────────────────────────────────────────────────────────────────

class TestLimiteDePeticiones:

    def test_demasiados_intentos_de_login_responden_429(self, central):
        client, conectar = central
        _usuario(conectar, "a@x.co")
        maximo = app_module.LIMITES_PETICIONES["login_post"][0]
        for _ in range(maximo):
            client.post("/login", data={"email": "a@x.co", "password": "incorrecta"})
        resp = client.post("/login", data={"email": "a@x.co", "password": CLAVE})
        assert resp.status_code == 429 and int(resp.headers["Retry-After"]) > 0

    def test_el_limitador_libera_cupos_al_pasar_la_ventana(self):
        from audit_tracer.utils.limitador import LimitadorPeticiones
        reloj = [0.0]
        limitador = LimitadorPeticiones(reloj=lambda: reloj[0])
        assert all(limitador.permitir("k", 3, 60)[0] for _ in range(3))
        permitido, reintentar = limitador.permitir("k", 3, 60)
        assert not permitido and 1 <= reintentar <= 61
        reloj[0] = 61
        assert limitador.permitir("k", 3, 60)[0]

    def test_el_cliente_no_gasta_intentos_cuando_el_servidor_pide_esperar(self, monkeypatch, tmp_path):
        from audit_tracer import sync_client
        from audit_tracer.models.audit_log import insert_event_and_enqueue_sync

        class Respuesta:
            status_code = 429

            def json(self):
                return {}

        conn = get_connection(str(tmp_path / "local.db"))
        insert_event_and_enqueue_sync(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA"})
        monkeypatch.setitem(sync_client._config, "api_url", "http://localhost:1")
        monkeypatch.setitem(sync_client._config, "token", "tk_x")
        monkeypatch.setattr(sync_client.requests, "post", lambda *a, **k: Respuesta())
        resumen = sync_client.sync_pending_events(conn)
        estado = conn.execute("SELECT estado, intentos FROM audit_sync_queue").fetchone()
        conn.close()
        assert resumen["sincronizados"] == 0 and tuple(estado) == ("PENDIENTE", 0)


# ── SRV-I2 / SRV-R3 / DSH-D2 ───────────────────────────────────────────────

class TestErroresYRechazos:

    def test_un_error_interno_no_muestra_el_detalle(self, central, monkeypatch):
        client, conectar = central
        _sesion(client, conectar, "auditor-1", "AUDITOR")
        monkeypatch.setitem(app_module.app.config, "PROPAGATE_EXCEPTIONS", False)

        def explota(*a, **k):
            raise RuntimeError("detalle interno secreto: /srv/audit_central.db")

        monkeypatch.setattr(app_module, "get_events", explota)
        resp = client.get("/eventos")
        texto = resp.get_data(as_text=True)
        assert resp.status_code == 500
        assert "secreto" not in texto and "Traceback" not in texto
        assert "registro del servidor" in texto

    def test_la_depuracion_esta_apagada_por_defecto(self):
        codigo = open(app_module.__file__, encoding="utf-8").read()
        assert "os.environ.get('FLASK_DEBUG', '0') == '1'" in codigo
        assert app_module.app.debug is False

    def test_publicar_merkle_sin_permiso_queda_registrado(self, central):
        client, conectar = central
        _sesion(client, conectar, "analista-1", "ANALISTA")
        assert client.post("/merkle/publicar", json={}).status_code == 403
        conn = conectar()
        try:
            assert get_events(conn, usuario_id="analista-1", tipo_accion="ACCESO_DENEGADO")
        finally:
            conn.close()

    def test_verificacion_completa_solo_admin_o_auditor(self, central):
        client, conectar = central
        _sesion(client, conectar, "cientifico-1", "CIENTIFICO_DATOS")
        resp = client.post("/verificar-integridad", follow_redirects=False)
        assert resp.status_code == 302
        conn = conectar()
        try:
            denegados = get_events(conn, usuario_id="cientifico-1", tipo_accion="ACCESO_DENEGADO")
        finally:
            conn.close()
        assert denegados and "verificacion_integridad" in denegados[0]["motivo_fallo"]


# ── CAN-I2 / CAN-S2 ────────────────────────────────────────────────────────

class TestLoginPorCodigo:

    def test_el_polling_por_post_entrega_el_token(self, central):
        client, conectar = central
        uid = _usuario(conectar, "colab@x.co", "CIENTIFICO_DATOS")
        datos = client.post("/api/auth/dispositivo/iniciar", json={"host": "colab-vm-17"}).get_json()
        _sesion(client, conectar, uid, "CIENTIFICO_DATOS")
        pagina = client.get(f"/auth/dispositivo?codigo={datos['codigo']}").get_data(as_text=True)
        assert "colab-vm-17" in pagina and "Este código lo pidió" in pagina
        client.post("/auth/dispositivo", data={"codigo": datos["codigo"]})
        resp = client.post("/api/auth/dispositivo/estado", json={"device_code": datos["device_code"]})
        assert resp.status_code == 200 and resp.get_json()["token"].startswith("tk_")
        assert client.post("/api/auth/dispositivo/estado",
                           json={"device_code": datos["device_code"]}).status_code == 410

    def test_los_codigos_vencidos_se_purgan(self, central):
        from audit_tracer.models.device_codes import purgar_codigos_vencidos
        client, conectar = central
        client.post("/api/auth/dispositivo/iniciar", json={})
        conn = conectar()
        try:
            conn.execute("UPDATE codigos_dispositivo SET fecha_expiracion = '2000-01-01T00:00:00'")
            conn.commit()
            assert purgar_codigos_vencidos(conn) == 1
        finally:
            conn.close()


# ── B8: gestión de roles ───────────────────────────────────────────────────

class TestGestionDeRoles:

    @pytest.fixture
    def conn(self):
        conexion = get_connection(":memory:")
        yield conexion
        conexion.close()

    def test_cambiar_el_rol_lo_registra(self, conn):
        admin = create_user(conn, "admin@x.co", CLAVE, "ADMIN")
        uid = create_user(conn, "a@x.co", CLAVE, "ANALISTA")
        assign_role(conn, admin, uid, "AUDITOR")
        assert get_user_by_id(conn, uid)["rol"] == "AUDITOR"
        (evento,) = get_events(conn, tipo_accion="MODIFICACION_ROL")
        assert evento["usuario_id"] == admin and "ANALISTA -> AUDITOR" in evento["contexto_ejecucion"]
        assert evento["nivel_alerta"] == "NORMAL"

    def test_dar_o_quitar_admin_es_advertencia(self, conn):
        admin = create_user(conn, "admin@x.co", CLAVE, "ADMIN")
        uid = create_user(conn, "a@x.co", CLAVE, "ANALISTA")
        assign_role(conn, admin, uid, "ADMIN")
        assert get_events(conn, tipo_accion="MODIFICACION_ROL")[0]["nivel_alerta"] == "ADVERTENCIA"

    def test_no_se_puede_degradar_al_unico_admin(self, conn):
        admin = create_user(conn, "admin@x.co", CLAVE, "ADMIN")
        with pytest.raises(ValueError, match="único administrador"):
            assign_role(conn, admin, admin, "ANALISTA")
        assert get_user_by_id(conn, admin)["rol"] == "ADMIN"

    def test_con_dos_admins_si_se_puede_degradar_uno(self, conn):
        admin = create_user(conn, "admin@x.co", CLAVE, "ADMIN")
        otro = create_user(conn, "admin2@x.co", CLAVE, "ADMIN")
        assign_role(conn, admin, otro, "AUDITOR")
        assert get_user_by_id(conn, otro)["rol"] == "AUDITOR"

    @pytest.mark.parametrize("rol", ["HACKER", "", "admin"])
    def test_rol_invalido_se_rechaza(self, conn, rol):
        admin = create_user(conn, "admin@x.co", CLAVE, "ADMIN")
        uid = create_user(conn, "a@x.co", CLAVE, "ANALISTA")
        with pytest.raises(ValueError, match="Rol inválido"):
            assign_role(conn, admin, uid, rol)

    def test_usuario_inexistente_se_rechaza(self, conn):
        admin = create_user(conn, "admin@x.co", CLAVE, "ADMIN")
        with pytest.raises(ValueError, match="no existe"):
            assign_role(conn, admin, "no-existe", "AUDITOR")


# ── B7: retención ──────────────────────────────────────────────────────────

class TestRetencion:

    def test_archivo_verificable_y_deteccion_de_alteraciones(self, tmp_path):
        from audit_tracer.retencion import archivar, fecha_limite, resumen, verificar_archivo
        conn = get_connection(":memory:")
        viejo = (datetime.utcnow() - timedelta(days=365 * 7)).isoformat()
        for i in range(3):
            insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA",
                                "dataset_nombre": f"D{i}.csv", "timestamp": viejo})
        insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA"})
        info = resumen(conn)
        assert info["anios_retencion"] == 6 and info["eventos_archivables"] == 3
        destino = str(tmp_path / "archivo")
        manifiesto = archivar(conn, destino)
        assert manifiesto["eventos"] == 3 and manifiesto["hasta_excluido"] <= fecha_limite()
        assert conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0] == 4   # no borra nada
        conn.close()
        assert verificar_archivo(destino)["valido"] is True

        ruta = os.path.join(destino, manifiesto["archivo"])
        texto = open(ruta, encoding="utf-8").read().replace("D1.csv", "OTRO.csv")
        open(ruta, "w", encoding="utf-8", newline="\n").write(texto)
        resultado = verificar_archivo(destino)
        assert resultado["valido"] is False and not resultado["sha256_coincide"] and resultado["eventos_alterados"]


# ── SRV-T2: sello de tiempo RFC 3161 ───────────────────────────────────────

def _tsa_de_prueba():
    """Certificado autofirmado y función que responde como una TSA RFC 3161."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    from audit_tracer import sello_tiempo as st

    llave = ec.generate_private_key(ec.SECP256R1())
    nombre = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TSA de prueba")])
    ahora = datetime.now(timezone.utc)
    certificado = (x509.CertificateBuilder().subject_name(nombre).issuer_name(nombre)
                   .public_key(llave.public_key()).serial_number(7)
                   .not_valid_before(ahora - timedelta(days=1)).not_valid_after(ahora + timedelta(days=1))
                   .sign(llave, hashes.SHA256()))
    cert_der = certificado.public_bytes(serialization.Encoding.DER)

    def responder(solicitud: bytes) -> bytes:
        _, req, _, _ = st.leer(solicitud)
        imprint = st.hijos(req)[1][2]
        gen_time = st.tlv(0x18, datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ").encode())
        tst = st.der_secuencia(st.der_entero(1), st.der_oid("1.2.3.4.1"), imprint, st.der_entero(42), gen_time)
        import hashlib
        atributos = st.der_secuencia(st.der_oid(st.OID_MESSAGE_DIGEST),
                                     st.tlv(0x31, st.tlv(0x04, hashlib.sha256(tst).digest())))
        firma = llave.sign(st.tlv(0x31, atributos), ec.ECDSA(hashes.SHA256()))
        sha256 = st.der_secuencia(st.der_oid(st.OID_SHA256), b"\x05\x00")
        firmante = st.der_secuencia(
            st.der_entero(1), st.der_secuencia(st.der_secuencia(), st.der_entero(7)), sha256,
            st.tlv(0xA0, atributos), st.der_secuencia(st.der_oid("1.2.840.10045.4.3.2")), st.tlv(0x04, firma))
        signed_data = st.der_secuencia(
            st.der_entero(3), st.tlv(0x31, sha256),
            st.der_secuencia(st.der_oid(st.OID_TST_INFO), st.tlv(0xA0, st.tlv(0x04, tst))),
            st.tlv(0xA0, cert_der), st.tlv(0x31, firmante))
        token = st.der_secuencia(st.der_oid(st.OID_SIGNED_DATA), st.tlv(0xA0, signed_data))
        return st.der_secuencia(st.der_secuencia(st.der_entero(0)), token)

    return responder


class TestSelloDeTiempo:

    def test_un_sello_valido_certifica_la_raiz_y_detecta_otra(self):
        from audit_tracer import sello_tiempo as st
        raiz = "ab" * 32
        token = _tsa_de_prueba()(st.construir_solicitud(bytes.fromhex(raiz)))
        info = st.verificar_sello(token, raiz)
        assert info["huella_coincide"] and info["firma_valida"] and info["tsa"] == "CN=TSA de prueba"
        assert info["hora_certificada"]
        assert st.verificar_sello(token, "cd" * 32)["huella_coincide"] is False

    def test_un_sello_con_firma_alterada_no_es_valido(self):
        from audit_tracer import sello_tiempo as st
        raiz = "ab" * 32
        token = bytearray(_tsa_de_prueba()(st.construir_solicitud(bytes.fromhex(raiz))))
        token[-5] ^= 0xFF   # último byte de la firma ECDSA
        try:
            info = st.verificar_sello(bytes(token), raiz)
        except st.ErrorSelloTiempo:
            return
        assert info["firma_valida"] is False

    def test_el_ancla_de_merkle_lleva_sello_y_lo_verifica(self, tmp_path, monkeypatch):
        from audit_tracer import merkle, sello_tiempo as st
        tsa = _tsa_de_prueba()

        class Respuesta:
            status_code = 200

            def __init__(self, contenido):
                self.content = contenido

        import requests
        monkeypatch.setattr(requests, "post", lambda url, data=None, **k: Respuesta(tsa(data)))
        conn = get_connection(":memory:")
        insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA",
                            "timestamp": "2026-11-21T10:05:00"})
        anclas = str(tmp_path / "anclas")
        ancla = merkle.publish_batch_root(conn, "2026-11-21T10", anclas, tsa_url="http://tsa.test")
        assert ancla["rfc3161"]["token"] and "rfc3161_error" not in ancla
        resultado = merkle.verify_external_anchor(conn, "2026-11-21T10", anclas)
        assert resultado["integrity_ok"] and resultado["sello_tiempo"]["valido"]

        # Reescribir el ancla con otra raíz no engaña al sello de la TSA.
        archivo = os.path.join(anclas, "merkle_2026-11-21T10.json")
        datos = json.load(open(archivo, encoding="utf-8"))
        token = st.de_texto(datos["rfc3161"]["token"])
        insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA",
                            "timestamp": "2026-11-21T10:30:00"})
        datos["root"] = merkle.build_batch_tree(conn, "2026-11-21T10")["root"]
        datos["leaf_count"] = 2
        json.dump(datos, open(archivo, "w", encoding="utf-8"))
        resultado = merkle.verify_external_anchor(conn, "2026-11-21T10", anclas)
        assert resultado["integrity_ok"] is False and "RFC 3161" in resultado["details"]
        conn.close()
        assert st.verificar_sello(token, "00" * 32)["huella_coincide"] is False


# ── LIB-I2: llave privada cifrada ──────────────────────────────────────────

class TestLlavePrivadaProtegida:

    def test_con_frase_de_entorno_la_llave_queda_cifrada(self, tmp_path, monkeypatch):
        from audit_tracer import digital_signatures as ds
        monkeypatch.setenv("AUDIT_TRACER_KEY_PASSPHRASE", "frase-de-prueba")
        privada, _ = ds.generate_keypair()
        ds.save_private_key(privada, tmp_path)
        assert b"ENCRYPTED" in (tmp_path / "private_key.pem").read_bytes()
        assert ds.load_private_key(tmp_path).public_key().public_bytes_raw() == privada.public_key().public_bytes_raw()
        monkeypatch.delenv("AUDIT_TRACER_KEY_PASSPHRASE")
        with pytest.raises(ds.LlaveInaccesibleError):
            ds.load_private_key(tmp_path)

    def test_con_llavero_la_frase_vive_en_el_llavero(self, tmp_path, monkeypatch):
        import keyring
        from keyring.backend import KeyringBackend
        from audit_tracer import digital_signatures as ds

        class LlaveroMemoria(KeyringBackend):
            priority = 1
            datos = {}

            def get_password(self, servicio, usuario):
                return self.datos.get((servicio, usuario))

            def set_password(self, servicio, usuario, clave):
                self.datos[(servicio, usuario)] = clave

            def delete_password(self, servicio, usuario):
                self.datos.pop((servicio, usuario), None)

        anterior = keyring.get_keyring()
        keyring.set_keyring(LlaveroMemoria())
        monkeypatch.setenv("AUDIT_TRACER_KEYRING", "1")
        try:
            privada, _ = ds.generate_keypair()
            ds.save_private_key(privada, tmp_path)
            assert b"ENCRYPTED" in (tmp_path / "private_key.pem").read_bytes()
            assert ds.load_private_key(tmp_path) is not None
            assert LlaveroMemoria.datos
        finally:
            keyring.set_keyring(anterior)

    def test_una_llave_en_claro_anterior_se_cifra_al_usarla(self, tmp_path, monkeypatch):
        from cryptography.hazmat.primitives import serialization
        from audit_tracer import digital_signatures as ds
        privada, publica = ds.generate_keypair()
        (tmp_path / "private_key.pem").write_bytes(privada.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        ds.save_public_key(publica, tmp_path)
        monkeypatch.setenv("AUDIT_TRACER_KEY_PASSPHRASE", "frase-de-prueba")
        ds._keypair_cache.clear()
        ds.get_or_create_user_keypair(str(tmp_path))
        assert b"ENCRYPTED" in (tmp_path / "private_key.pem").read_bytes()

    @pytest.mark.skipif(os.name == "nt", reason="permisos POSIX")
    def test_la_llave_queda_con_permisos_de_solo_dueno(self, tmp_path):
        from audit_tracer import digital_signatures as ds
        from audit_tracer.utils.permisos import es_privado
        ds.save_private_key(ds.generate_keypair()[0], tmp_path)
        assert es_privado(str(tmp_path / "private_key.pem"))


# ── LIB-D2 / CAN-D1 ────────────────────────────────────────────────────────

class TestSesionesSinCierre:

    def test_lista_las_sesiones_de_la_libreria_que_dejaron_de_reportar(self):
        from audit_tracer.monitoreo_sesiones import sesiones_sin_cierre
        conn = get_connection(":memory:")
        hace = (datetime.utcnow() - timedelta(hours=30)).isoformat()
        for sesion, cierra in (("colgada", False), ("cerrada", True)):
            insert_event(conn, {"usuario_id": "u", "sesion_id": sesion, "tipo_accion": "INICIO_SESION",
                                "timestamp": hace, "contexto_ejecucion": "MODO_LIBRERIA | Env: Jupyter"})
            if cierra:
                insert_event(conn, {"usuario_id": "u", "sesion_id": sesion, "tipo_accion": "CIERRE_SESION",
                                    "timestamp": hace})
        insert_event(conn, {"usuario_id": "u", "sesion_id": "web", "tipo_accion": "INICIO_SESION", "timestamp": hace})
        sesiones = sesiones_sin_cierre(conn, horas=24)
        conn.close()
        assert [s["sesion_id"] for s in sesiones] == ["colgada"]

    def test_el_panel_de_sincronizacion_las_muestra(self, central):
        client, conectar = central
        conn = conectar()
        try:
            insert_event(conn, {"usuario_id": "u-colab", "sesion_id": "sesion-colgada-1", "tipo_accion": "INICIO_SESION",
                                "timestamp": (datetime.utcnow() - timedelta(days=2)).isoformat(),
                                "contexto_ejecucion": "MODO_LIBRERIA | Env: Google Colab"})
        finally:
            conn.close()
        _sesion(client, conectar, "admin-1", "ADMIN")
        html = client.get("/admin/sincronizacion").get_data(as_text=True)
        assert "Sesiones de la librería sin cierre" in html and "u-colab" in html


# ── LIB-I1 / LIB-S2: permisos de solo-dueño ────────────────────────────────

class TestPermisos:
    """En Linux/macOS (Colab) se comprueba el modo 0600; en Windows el perfil del usuario ya es privado."""

    def test_la_base_local_nueva_queda_con_permisos_de_solo_dueno(self, tmp_path):
        from audit_tracer.utils.permisos import es_privado
        ruta = str(tmp_path / "audit_trail.db")
        get_connection(ruta).close()
        assert es_privado(ruta)

    def test_el_token_cacheado_queda_con_permisos_de_solo_dueno(self, tmp_path):
        from audit_tracer.device_login import _cache_file_path, _save_cached_token
        from audit_tracer.utils.permisos import es_privado
        _save_cached_token(str(tmp_path), {"token": "tk_x", "usuario_id": "u"})
        ruta = _cache_file_path(str(tmp_path))
        assert json.load(open(ruta, encoding="utf-8"))["token"] == "tk_x"
        assert es_privado(ruta)

    def test_escribir_privado_crea_el_archivo_ya_restringido(self, tmp_path):
        from audit_tracer.utils.permisos import es_privado, escribir_privado
        ruta = str(tmp_path / "sub" / "secreto.bin")
        escribir_privado(ruta, b"123")
        assert open(ruta, "rb").read() == b"123" and es_privado(ruta)


# ── CAN-T2: firma obligatoria para todos ───────────────────────────────────

class TestFirmaObligatoria:

    def _evento(self, uid):
        import uuid
        return {"evento_uuid": str(uuid.uuid4()), "usuario_id": uid, "sesion_id": "s",
                "timestamp": datetime.utcnow().isoformat(), "tipo_accion": "CARGA", "nivel_alerta": "NORMAL"}

    def test_con_firma_obligatoria_se_rechaza_un_evento_sin_firma(self, central, monkeypatch):
        client, conectar = central
        uid = _usuario(conectar, "a@x.co", "CIENTIFICO_DATOS")
        conn = conectar()
        try:
            token = generar_token(conn, uid)["token"]
        finally:
            conn.close()
        cabeceras = {"Authorization": f"Bearer {token}"}
        assert client.post("/api/eventos/sincronizar", json=self._evento(uid), headers=cabeceras).status_code == 201
        monkeypatch.setenv("AUDIT_EXIGIR_FIRMA", "1")
        resp = client.post("/api/eventos/sincronizar", json=self._evento(uid), headers=cabeceras)
        assert resp.status_code == 422 and "exige" in resp.get_json()["mensaje"]
        conn = conectar()
        try:
            assert get_events(conn, usuario_id=uid, tipo_accion="FIRMA_INVALIDA")
        finally:
            conn.close()


# ── Envío real por SMTP (servidor SMTP local) ──────────────────────────────

class _ManejadorSMTP(socketserver.StreamRequestHandler):
    recibidos = []

    def handle(self):
        escribir = lambda texto: self.wfile.write((texto + "\r\n").encode())  # noqa: E731
        escribir("220 smtp-de-prueba ESMTP")
        datos, en_datos, sobre = [], False, {}
        while True:
            linea = self.rfile.readline()
            if not linea:
                return
            texto = linea.decode("utf-8", "replace").rstrip("\r\n")
            if en_datos:
                if texto == ".":
                    en_datos = False
                    _ManejadorSMTP.recibidos.append({**sobre, "mensaje": "\n".join(datos)})
                    escribir("250 OK: mensaje aceptado")
                else:
                    datos.append(texto[1:] if texto.startswith("..") else texto)
                continue
            comando = texto.upper()
            if comando.startswith("EHLO"):
                self.wfile.write(b"250-smtp-de-prueba\r\n250-AUTH PLAIN LOGIN\r\n250 8BITMIME\r\n")
            elif comando.startswith("AUTH PLAIN"):
                sobre["autenticado"] = True
                escribir("235 Autenticado")
            elif comando.startswith("MAIL FROM"):
                sobre["de"] = texto[10:]
                escribir("250 OK")
            elif comando.startswith("RCPT TO"):
                sobre.setdefault("para", []).append(texto[8:])
                escribir("250 OK")
            elif comando == "DATA":
                en_datos = True
                escribir("354 Termine con <CRLF>.<CRLF>")
            elif comando == "QUIT":
                escribir("221 Adios")
                return
            else:
                escribir("250 OK")


def test_el_correo_de_alerta_sale_por_smtp_real():
    """
    Antes solo se había probado la entrega en carpeta. Aquí el mensaje viaja
    por el protocolo SMTP (EHLO, AUTH, MAIL, RCPT, DATA) hasta un servidor
    local, como lo haría hacia el SMTP institucional.
    """
    from audit_tracer.alerts.email_service import ConfiguracionSMTP, ServicioCorreoSMTP, construir_mensaje_prueba
    _ManejadorSMTP.recibidos.clear()
    servidor = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _ManejadorSMTP)
    hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
    hilo.start()
    try:
        config = ConfiguracionSMTP(host="127.0.0.1", port=servidor.server_address[1], usuario="alertas",
                                   password="clave-smtp", remitente="alertas@hospital.test",
                                   starttls=False, ssl=False, timeout=5)
        ServicioCorreoSMTP(config).enviar(
            construir_mensaje_prueba("oficial@hospital.test", "alertas@hospital.test", "https://central.test"))
    finally:
        servidor.shutdown()
        servidor.server_close()
    (recibido,) = _ManejadorSMTP.recibidos
    assert recibido["autenticado"] is True
    assert "oficial@hospital.test" in recibido["para"][0]
    assert "Correo de prueba de alertas" in recibido["mensaje"]
