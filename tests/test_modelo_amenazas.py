"""
tests/test_modelo_amenazas.py
=============================
HU-6.4 — Modelo de amenazas STRIDE (docs/modelo_amenazas_stride.md).

Tres grupos de pruebas:

1. TestDocumento — coherencia del anexo con su CSV, con la matriz de HU-6.6
   y con el código: CA1 (las seis categorías STRIDE en los cuatro
   componentes), CA2 y DoD (toda amenaza tiene mitigación), y que la
   evidencia citada exista.

2. TestMitigacionesVerificadas — mitigaciones que el modelo da por
   implementadas y que no tenían una prueba propia. Atacan el dashboard real
   (cliente de pruebas de Flask) contra una base central temporal.

3. TestRiesgosAbiertos — amenazas confirmadas durante el análisis cuya
   mitigación está PLANEADA o es PARCIAL. Cada prueba describe el
   comportamiento seguro esperado y está marcada xfail(strict=True): hoy
   falla, y cuando alguien implemente la mitigación pasará, y la suite lo
   obligará a quitar el xfail y actualizar el estado de la amenaza en el anexo.
"""

import csv
import re
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin, urlparse

import pytest

import app as app_module
from audit_tracer.auth.gestion_roles import assign_role
from audit_tracer.auth.tokens import generar_token, validar_token
from audit_tracer.db import get_central_connection
from audit_tracer.digital_signatures import generate_keypair, public_key_to_pem
from audit_tracer.models.audit_log import get_events, insert_event, verify_integrity
from audit_tracer.models.usuarios import create_user
from audit_tracer.utils.hashing import hash_event

RAIZ = Path(__file__).resolve().parent.parent
MODELO_CSV = RAIZ / "docs" / "modelo_amenazas_stride.csv"
MODELO_MD = RAIZ / "docs" / "modelo_amenazas_stride.md"
MATRIZ_CSV = RAIZ / "docs" / "matriz_trazabilidad_normativa.csv"
MATRIZ_MD = RAIZ / "docs" / "matriz_trazabilidad_normativa.md"

COLUMNAS = [
    "id", "componente", "categoria", "amenaza", "superficie",
    "mitigacion_implementada", "mitigacion_planeada", "estado",
    "hu", "controles", "evidencia", "riesgo_residual",
]
COMPONENTES = {
    "LIB": "Librería",
    "CAN": "Canal de transmisión",
    "SRV": "Servidor central",
    "DSH": "Dashboard",
}
CATEGORIAS = [
    "Spoofing", "Tampering", "Repudiation",
    "Information Disclosure", "Denial of Service", "Elevation of Privilege",
]
ESTADOS = {"IMPLEMENTADA", "PARCIAL", "PLANEADA"}
RIESGOS = {"Alto", "Medio", "Bajo"}
PASSWORD = "Password123!"


def _filas():
    with open(MODELO_CSV, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _lista(celda):
    return [p.strip() for p in celda.split(";") if p.strip()]


FILAS = _filas()


# ══════════════════════════════════════════════════════════════
# 1. COHERENCIA DEL DOCUMENTO
# ══════════════════════════════════════════════════════════════

class TestDocumento:

    def test_columnas_del_csv(self):
        with open(MODELO_CSV, encoding="utf-8", newline="") as f:
            assert next(csv.reader(f)) == COLUMNAS

    def test_ids_unicos_y_coherentes_con_componente_y_categoria(self):
        ids = [f["id"] for f in FILAS]
        assert len(ids) == len(set(ids)), "IDs repetidos"
        for fila in FILAS:
            m = re.fullmatch(r"(LIB|CAN|SRV|DSH)-([STRIDE])(\d+)", fila["id"])
            assert m, f"ID con formato inválido: {fila['id']}"
            assert COMPONENTES[m.group(1)] == fila["componente"], fila["id"]
            assert fila["categoria"] in CATEGORIAS, fila["id"]
            assert fila["categoria"][0] == m.group(2), fila["id"]

    @pytest.mark.parametrize("componente", COMPONENTES.values())
    @pytest.mark.parametrize("categoria", CATEGORIAS)
    def test_ca1_cada_componente_tiene_amenazas_de_las_seis_categorias(self, componente, categoria):
        assert any(
            f["componente"] == componente and f["categoria"] == categoria for f in FILAS
        ), f"Falta al menos una amenaza {categoria} para {componente}"

    @pytest.mark.parametrize("fila", FILAS, ids=lambda f: f["id"])
    def test_ca2_cada_amenaza_tiene_mitigacion_y_estado_coherente(self, fila):
        assert fila["amenaza"].strip() and fila["superficie"].strip()
        implementada = fila["mitigacion_implementada"].strip()
        planeada = fila["mitigacion_planeada"].strip()
        assert implementada or planeada, f"{fila['id']}: sin mitigación (DoD)"
        assert fila["estado"] in ESTADOS
        assert fila["riesgo_residual"] in RIESGOS
        assert all(re.fullmatch(r"HU-\d+\.\d+", hu) for hu in _lista(fila["hu"]))

        if fila["estado"] == "IMPLEMENTADA":
            assert implementada and not planeada, f"{fila['id']}: implementada sin pendientes"
        elif fila["estado"] == "PARCIAL":
            assert implementada and planeada, f"{fila['id']}: parcial necesita lo hecho y lo pendiente"
        else:
            assert planeada, f"{fila['id']}: planeada sin acción"

        if fila["estado"] != "PLANEADA":
            # CA2: lo que ya existe se referencia con su HU y su evidencia.
            assert _lista(fila["hu"]), f"{fila['id']}: sin HU de la mitigación"
            assert _lista(fila["evidencia"]), f"{fila['id']}: sin evidencia"

    @pytest.mark.parametrize("fila", [f for f in FILAS if f["riesgo_residual"] == "Alto"],
                             ids=lambda f: f["id"])
    def test_riesgo_alto_siempre_tiene_accion_planeada(self, fila):
        assert fila["mitigacion_planeada"].strip()

    def test_controles_y_brechas_citados_existen_en_la_matriz_hu_6_6(self):
        with open(MATRIZ_CSV, encoding="utf-8", newline="") as f:
            controles = {fila["id"] for fila in csv.DictReader(f)}
        brechas = set(re.findall(r"^\| (B\d+) \|", MATRIZ_MD.read_text(encoding="utf-8"), re.M))
        for fila in FILAS:
            for ref in _lista(fila["controles"]):
                if ref.startswith("CT-"):
                    assert ref in controles, f"{fila['id']}: {ref} no está en la matriz"
                else:
                    assert ref in brechas, f"{fila['id']}: brecha {ref} no está en la matriz"

    @pytest.mark.parametrize("fila", [f for f in FILAS if f["evidencia"].strip()],
                             ids=lambda f: f["id"])
    def test_evidencia_citada_existe(self, fila):
        for referencia in _lista(fila["evidencia"]):
            archivo, *nombres = referencia.split("::")
            ruta = RAIZ / archivo
            assert ruta.is_file(), f"{fila['id']}: no existe {archivo}"
            if not nombres:
                continue
            codigo = ruta.read_text(encoding="utf-8")
            *clases, funcion = nombres
            for clase in clases:
                assert re.search(rf"^class {clase}\b", codigo, re.M), f"{fila['id']}: falta {referencia}"
            assert re.search(rf"^\s*def {funcion}\(", codigo, re.M), f"{fila['id']}: falta {referencia}"

    def test_cada_riesgo_abierto_probado_esta_documentado_como_no_implementado(self):
        codigo = Path(__file__).read_text(encoding="utf-8")
        pruebas = set(re.findall(r"def (test_riesgo_abierto_\w+)\(", codigo))
        assert pruebas
        citadas = {}
        for fila in FILAS:
            for ref in _lista(fila["evidencia"]):
                nombre = ref.split("::")[-1]
                if nombre.startswith("test_riesgo_abierto_"):
                    citadas.setdefault(nombre, []).append(fila)
        assert pruebas == set(citadas), "Cada prueba de riesgo abierto debe citarse en el CSV"
        for nombre, filas in citadas.items():
            for fila in filas:
                assert fila["estado"] != "IMPLEMENTADA", (
                    f"{fila['id']} cita {nombre} (xfail) pero dice estar implementada"
                )

    def test_anexo_incluye_todas_las_amenazas_y_componentes(self):
        texto = MODELO_MD.read_text(encoding="utf-8")
        for fila in FILAS:
            assert f"| {fila['id']} |" in texto, f"{fila['id']} no aparece en el anexo"
        for componente in COMPONENTES.values():
            assert componente in texto
        for categoria in CATEGORIAS:
            assert categoria in texto


# ══════════════════════════════════════════════════════════════
# FIXTURES DE SERVIDOR
# ══════════════════════════════════════════════════════════════

@pytest.fixture
def servidor(monkeypatch, tmp_path):
    """Dashboard Flask real contra una base central temporal."""
    db_path = str(tmp_path / "central_stride.db")
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    app_module.app.config["TESTING"] = True

    def conectar():
        conn = get_central_connection(db_path)
        conn.row_factory = sqlite3.Row
        return conn

    with app_module.app.test_client() as client:
        yield client, conectar


def _usuario(conectar, email, rol):
    conn = conectar()
    try:
        return create_user(conn, email, PASSWORD, rol)
    finally:
        conn.close()


def _token(conectar, usuario_id):
    conn = conectar()
    try:
        return generar_token(conn, usuario_id)["token"]
    finally:
        conn.close()


def _login(client, email, **extra):
    return client.post("/login", data={"email": email, "password": PASSWORD, **extra})


def _sesion(client, usuario_id, rol):
    with client.session_transaction() as sess:
        sess["usuario_id"] = usuario_id
        sess["rol"] = rol
        sess["nombre"] = "test"
        sess["sesion_id"] = "s-stride"


def _evento(usuario_id, **extra):
    evento = {
        "evento_uuid": str(uuid.uuid4()),
        "usuario_id": usuario_id,
        "sesion_id": "sesion-colab",
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": "CARGA",
        "dataset_nombre": "PATIENTS.csv",
        "nivel_alerta": "NORMAL",
    }
    evento.update(extra)
    return evento


def _sincronizar(client, token, evento, **kwargs):
    return client.post("/api/eventos/sincronizar", json=evento,
                       headers={"Authorization": f"Bearer {token}", **kwargs.pop("headers", {})},
                       **kwargs)


def _fila(conectar, evento_uuid):
    conn = conectar()
    try:
        return conn.execute("SELECT * FROM audit_log WHERE evento_uuid = ?", (evento_uuid,)).fetchone()
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════
# 2. MITIGACIONES VERIFICADAS
# ══════════════════════════════════════════════════════════════

class TestMitigacionesVerificadas:

    def test_token_personal_no_abre_el_dashboard(self, servidor):
        """LIB-E1: el token de la librería no reemplaza la sesión del dashboard."""
        client, conectar = servidor
        uid = _usuario(conectar, "cientifico@x.co", "CIENTIFICO_DATOS")
        token = _token(conectar, uid)
        for ruta in ("/eventos", "/reportes", "/admin/usuarios", "/admin/tokens"):
            resp = client.get(ruta, headers={"Authorization": f"Bearer {token}"})
            assert resp.status_code == 302, ruta
            assert "/login" in resp.headers["Location"], ruta

    def test_x_forwarded_proto_falsificado_no_salta_el_https(self, servidor):
        """CAN-E1: sin TRUST_PROXY_HEADERS=1 el encabezado de proxy se ignora."""
        client, conectar = servidor
        uid = _usuario(conectar, "a@x.co", "CIENTIFICO_DATOS")
        token = _token(conectar, uid)
        evento = _evento(uid)
        resp = _sincronizar(client, token, evento, base_url="http://central.example",
                            headers={"X-Forwarded-Proto": "https"})
        assert resp.status_code == 426
        assert _fila(conectar, evento["evento_uuid"]) is None

    def test_payload_no_puede_fijar_hash_ni_event_id(self, servidor):
        """SRV-E1: campos fuera de la lista blanca se ignoran y el hash se recalcula."""
        client, conectar = servidor
        uid = _usuario(conectar, "a@x.co", "CIENTIFICO_DATOS")
        token = _token(conectar, uid)
        evento = _evento(uid, event_id=987654, hash_integridad="0" * 64, columna_inventada="x")
        assert _sincronizar(client, token, evento).status_code == 201

        fila = _fila(conectar, evento["evento_uuid"])
        assert fila["event_id"] != 987654
        assert fila["hash_integridad"] != "0" * 64
        conn = conectar()
        try:
            assert verify_integrity(conn) == []
        finally:
            conn.close()

    def test_inyeccion_sql_en_el_payload_se_guarda_como_texto(self, servidor):
        """SRV-E1: las consultas son parametrizadas."""
        client, conectar = servidor
        uid = _usuario(conectar, "a@x.co", "CIENTIFICO_DATOS")
        token = _token(conectar, uid)
        malicioso = "x'); DROP TABLE audit_log; --"
        evento = _evento(uid, dataset_nombre=malicioso)
        assert _sincronizar(client, token, evento).status_code == 201
        assert _fila(conectar, evento["evento_uuid"])["dataset_nombre"] == malicioso

    def test_revocar_token_por_api_exige_sesion_admin(self, servidor):
        """SRV-E2: un token Bearer no autoriza la revocación."""
        client, conectar = servidor
        uid = _usuario(conectar, "a@x.co", "CIENTIFICO_DATOS")
        token = _token(conectar, uid)
        resp = client.post("/api/tokens/revocar", json={"token": token},
                           headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 302 and "/login" in resp.headers["Location"]
        conn = conectar()
        try:
            assert validar_token(conn, token)[0] is True
        finally:
            conn.close()

    @pytest.mark.parametrize("destino", [
        "//sitio-falso.example/login",
        "https://sitio-falso.example/login",
        "/\\sitio-falso.example/login",
    ])
    def test_next_externo_no_redirige_fuera_del_dashboard(self, servidor, destino):
        """DSH-S4: el parámetro next solo acepta rutas propias."""
        client, conectar = servidor
        _usuario(conectar, "analista@x.co", "ANALISTA")
        resp = _login(client, "analista@x.co", next=destino)
        assert resp.status_code == 302
        final = urljoin("http://localhost/", resp.headers["Location"])
        assert urlparse(final).netloc == "localhost"

    def test_datos_del_evento_se_escapan_en_listados_y_reportes(self, servidor):
        """DSH-I1 (parte implementada): el autoescape de Jinja protege estas vistas."""
        client, conectar = servidor
        _sembrar_evento_con_xss(conectar)
        _sesion(client, "auditor", "AUDITOR")
        for ruta in ("/eventos", "/reportes", "/dashboard"):
            html = client.get(ruta).get_data(as_text=True)
            assert XSS not in html, ruta
        for ruta in ("/eventos", "/reportes"):  # vistas que muestran dataset_nombre
            assert "&lt;script&gt;" in client.get(ruta).get_data(as_text=True), ruta


XSS = "<script>alert('xss')</script>"


def _sembrar_evento_con_xss(conectar):
    """Evento con HTML en todos los campos de texto que controla la librería."""
    conn = conectar()
    try:
        return insert_event(conn, {
            "usuario_id": "u-xss", "sesion_id": "s", "tipo_accion": "EXPORTACION",
            "dataset_nombre": XSS, "columnas_afectadas": XSS, "ruta_destino": XSS,
            "contexto_ejecucion": XSS, "nivel_alerta": "CRITICO", "motivo_alerta": XSS,
        })
    finally:
        conn.close()


# ══════════════════════════════════════════════════════════════
# 3. RIESGOS ABIERTOS (xfail estricto)
# ══════════════════════════════════════════════════════════════

def riesgo_abierto(amenaza):
    """Marca una prueba que describe la mitigación pendiente de `amenaza`."""
    return pytest.mark.xfail(
        strict=True, raises=AssertionError,
        reason=f"{amenaza}: riesgo abierto documentado en docs/modelo_amenazas_stride.md",
    )


class TestRiesgosAbiertos:

    @riesgo_abierto("SRV-S1")
    def test_riesgo_abierto_evento_a_nombre_de_otro_usuario_es_rechazado(self, servidor):
        client, conectar = servidor
        atacante = _usuario(conectar, "atacante@x.co", "CIENTIFICO_DATOS")
        victima = _usuario(conectar, "victima@x.co", "CIENTIFICO_DATOS")
        token = _token(conectar, atacante)
        evento = _evento(victima, tipo_accion="EXPORTACION", filas_exportadas=10)

        resp = _sincronizar(client, token, evento)
        assert resp.status_code == 403
        assert _fila(conectar, evento["evento_uuid"]) is None

    @riesgo_abierto("SRV-S2")
    def test_riesgo_abierto_cambio_de_llave_publica_queda_registrado(self, servidor):
        client, conectar = servidor
        uid = _usuario(conectar, "a@x.co", "CIENTIFICO_DATOS")
        token = _token(conectar, uid)
        headers = {"Authorization": f"Bearer {token}"}
        for _ in range(2):
            _, pub = generate_keypair()
            ultima = client.post("/api/usuarios/llave-publica",
                                 json={"llave_publica": public_key_to_pem(pub)}, headers=headers)
        conn = conectar()
        try:
            rastro = [e for e in get_events(conn, usuario_id=uid) if "LLAVE" in e["tipo_accion"]]
        finally:
            conn.close()
        # Seguro: el reemplazo se rechaza, o al menos queda registrado.
        assert ultima.status_code >= 400 or rastro

    @riesgo_abierto("SRV-T3")
    def test_riesgo_abierto_servidor_reclasifica_exportacion_masiva(self, servidor):
        client, conectar = servidor
        uid = _usuario(conectar, "a@x.co", "CIENTIFICO_DATOS")
        token = _token(conectar, uid)
        evento = _evento(uid, tipo_accion="EXPORTACION", filas_exportadas=50_000,
                         ruta_destino="/content/todo.csv", nivel_alerta="NORMAL")
        assert _sincronizar(client, token, evento).status_code == 201
        assert _fila(conectar, evento["evento_uuid"])["nivel_alerta"] == "CRITICO"

    @riesgo_abierto("SRV-D1")
    def test_riesgo_abierto_el_servidor_limita_el_tamano_de_la_peticion(self):
        assert app_module.app.config.get("MAX_CONTENT_LENGTH") is not None

    @riesgo_abierto("DSH-S3")
    def test_riesgo_abierto_cookie_de_sesion_es_secure_y_samesite(self):
        config = app_module.app.config
        assert config.get("SESSION_COOKIE_SECURE") is True
        assert config.get("SESSION_COOKIE_SAMESITE") in ("Lax", "Strict")

    @riesgo_abierto("DSH-T1")
    def test_riesgo_abierto_post_sin_token_csrf_es_rechazado(self, servidor):
        client, conectar = servidor
        admin = _usuario(conectar, "admin@x.co", "ADMIN")
        analista = _usuario(conectar, "analista@x.co", "ANALISTA")
        _sesion(client, admin, "ADMIN")
        # Un formulario de otro sitio no conoce ningún token CSRF.
        client.post(f"/admin/usuarios/editar/{analista}", data={"rol": "ADMIN"})
        conn = conectar()
        try:
            rol = conn.execute("SELECT rol FROM usuarios WHERE usuario_id = ?", (analista,)).fetchone()[0]
        finally:
            conn.close()
        assert rol == "ANALISTA"

    @riesgo_abierto("DSH-I1")
    def test_riesgo_abierto_detalle_de_evento_escapa_los_datos_de_la_libreria(self, servidor):
        client, conectar = servidor
        event_id = _sembrar_evento_con_xss(conectar)
        _sesion(client, "auditor", "AUDITOR")
        resp = client.get(f"/eventos/{event_id}")
        assert resp.status_code == 200
        assert XSS not in resp.get_data(as_text=True)

    @riesgo_abierto("DSH-R1")
    def test_riesgo_abierto_descarga_de_reporte_queda_registrada(self, servidor):
        client, conectar = servidor
        _sesion(client, "auditor-1", "AUDITOR")
        assert client.get("/reportes/exportar").status_code == 200
        conn = conectar()
        try:
            assert get_events(conn, usuario_id="auditor-1")
        finally:
            conn.close()

    @riesgo_abierto("DSH-I2")
    def test_riesgo_abierto_csv_neutraliza_formulas(self, servidor):
        client, conectar = servidor
        formula = '=HYPERLINK("http://sitio-falso.example","ver")'
        conn = conectar()
        try:
            insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA",
                                "dataset_nombre": formula})
        finally:
            conn.close()
        _sesion(client, "auditor-1", "AUDITOR")
        filas = list(csv.DictReader(client.get("/reportes/exportar").get_data(as_text=True).splitlines()))
        assert filas
        assert not any(f["dataset_nombre"].startswith(("=", "+", "-", "@")) for f in filas)

    @riesgo_abierto("DSH-I3")
    def test_riesgo_abierto_token_personal_no_viaja_en_la_cookie(self, servidor):
        client, conectar = servidor
        _usuario(conectar, "analista@x.co", "ANALISTA")
        assert _login(client, "analista@x.co").status_code == 302
        cookie = client.get_cookie("session").value
        datos = app_module.app.session_interface.get_signing_serializer(app_module.app).loads(cookie)
        assert "token" not in datos

    @riesgo_abierto("DSH-E2")
    def test_riesgo_abierto_rol_degradado_pierde_privilegios_en_la_sesion_activa(self, servidor):
        client, conectar = servidor
        admin = _usuario(conectar, "admin@x.co", "ADMIN")
        analista = _usuario(conectar, "analista@x.co", "ANALISTA")
        assert _login(client, "analista@x.co").status_code == 302
        assert client.get("/eventos").status_code == 200

        conn = conectar()
        try:
            assign_role(conn, admin, analista, "CIENTIFICO_DATOS")
        finally:
            conn.close()
        assert client.get("/eventos").status_code == 403
