"""
HU-7.2 — Alertas en tiempo real de eventos críticos.

  CA1  catálogo y clasificación de eventos críticos
  CA2  notificación automática por correo al rol / correos configurados
  CA3  contenido mínimo del correo + enlace directo al detalle
  CA4  el envío no bloquea ni afecta el registro del evento
  Sub-tarea 4  configuración de destinatarios y severidad desde el dashboard

Todas las pruebas usan bases temporales y ServicioCorreoMemoria: ninguna
toca audit_central.db ni manda correos reales.
"""

import sqlite3
import time
import uuid
from datetime import datetime, timedelta

import pytest

from conftest import crear_sesion_web

import app as app_module
from audit_tracer.alerts import (
    CATALOGO_EVENTOS_CRITICOS,
    DespachadorAlertas,
    ServicioCorreoMemoria,
    clasificar_evento,
    configurar_alertas,
    desactivar_alertas,
    obtener_despachador,
)
from audit_tracer.alerts.catalogo import UMBRAL_ACCESOS_DENEGADOS
from audit_tracer.alerts.email_service import (
    ConfiguracionSMTP,
    ServicioCorreoArchivo,
    ServicioCorreoSMTP,
    construir_mensaje,
    crear_servicio_correo_desde_entorno,
)
from audit_tracer.auth.tokens import generar_token
from audit_tracer.db import get_central_connection, get_connection
from audit_tracer.export_capture import UMBRAL_EXPORTACION_MASIVA
from audit_tracer.models import alertas as modelo
from audit_tracer.models.audit_log import (
    _hooks_post_insercion,
    get_event_by_id,
    insert_event,
    registrar_hook_post_insercion,
    eliminar_hook_post_insercion,
)
from audit_tracer.models.usuarios import create_user


# ──────────────────────────────────────────────────────────────
# Fixtures y helpers
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "central_alertas.db")


@pytest.fixture
def conn(db_path):
    c = get_central_connection(db_path)
    yield c
    c.close()


@pytest.fixture
def usuarios(conn):
    """Un auditor (oficial de cumplimiento), un admin, y un auditor inactivo."""
    auditor = create_user(conn, "oficial@hospital.org", "Password123!", "AUDITOR")
    admin = create_user(conn, "admin@hospital.org", "Password123!", "ADMIN")
    inactivo = create_user(conn, "ex.auditor@hospital.org", "Password123!", "AUDITOR")
    conn.execute("UPDATE usuarios SET activo = 0 WHERE usuario_id = ?", (inactivo,))
    conn.commit()
    return {"auditor": auditor, "admin": admin, "inactivo": inactivo}


@pytest.fixture
def correo():
    return ServicioCorreoMemoria()


@pytest.fixture
def despachador(db_path, correo, usuarios):
    """Despachador SIN hilo: las pruebas procesan la cola de forma síncrona."""
    d = DespachadorAlertas(db_path, servicio_correo=correo, url_base="https://audit.example.org",
                           backoff_base_segundos=0)
    registrar_hook_post_insercion(d.hook_post_insercion)
    yield d
    eliminar_hook_post_insercion(d.hook_post_insercion)


def _evento(**kw):
    base = {
        "usuario_id": "u-analista",
        "sesion_id": "s1",
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": "CARGA",
        "dataset_nombre": "PACIENTES.csv",
        "nivel_alerta": "NORMAL",
    }
    base.update(kw)
    return base


def _insertar_y_leer(conn, **kw):
    event_id = insert_event(conn, _evento(**kw))
    return get_event_by_id(conn, event_id)


# ──────────────────────────────────────────────────────────────
# CA1 — Catálogo y clasificación
# ──────────────────────────────────────────────────────────────

class TestCatalogo:
    def test_catalogo_incluye_los_tipos_exigidos_por_ca1(self):
        for codigo in ("EXPORTACION_MASIVA", "ACCESOS_DENEGADOS_REPETIDOS", "ANOMALIA_DETECTADA"):
            assert codigo in CATALOGO_EVENTOS_CRITICOS

    def test_cada_tipo_tiene_severidad_valida_y_descripcion(self):
        for t in CATALOGO_EVENTOS_CRITICOS.values():
            assert t.severidad in modelo.SEVERIDADES
            assert t.nombre and t.descripcion and t.origen

    def test_evento_normal_no_es_critico(self, conn):
        assert clasificar_evento(conn, _insertar_y_leer(conn)) is None

    def test_exportacion_masiva_por_filas(self, conn):
        ev = _insertar_y_leer(conn, tipo_accion="EXPORTACION",
                              filas_exportadas=UMBRAL_EXPORTACION_MASIVA + 1)
        c = clasificar_evento(conn, ev)
        assert c.tipos == ["EXPORTACION_MASIVA"]
        assert c.severidad == "ALTA"

    def test_exportacion_en_el_umbral_no_es_masiva(self, conn):
        ev = _insertar_y_leer(conn, tipo_accion="EXPORTACION", filas_exportadas=UMBRAL_EXPORTACION_MASIVA)
        assert clasificar_evento(conn, ev) is None

    def test_exportacion_marcada_masiva_por_el_interceptor(self, conn):
        ev = _insertar_y_leer(conn, tipo_accion="EXPORTACION", nivel_alerta="CRITICO",
                              motivo_alerta="Exportación masiva: 5000 filas (> 1000)")
        assert clasificar_evento(conn, ev).tipos == ["EXPORTACION_MASIVA"]

    def test_accesos_denegados_por_debajo_del_umbral_no_son_criticos(self, conn):
        for _ in range(UMBRAL_ACCESOS_DENEGADOS - 1):
            ev = _insertar_y_leer(conn, tipo_accion="ACCESO_DENEGADO", nivel_alerta="ADVERTENCIA")
        assert clasificar_evento(conn, ev) is None

    def test_accesos_denegados_repetidos_al_alcanzar_el_umbral(self, conn):
        for _ in range(UMBRAL_ACCESOS_DENEGADOS):
            ev = _insertar_y_leer(conn, tipo_accion="ACCESO_DENEGADO", nivel_alerta="ADVERTENCIA")
        c = clasificar_evento(conn, ev)
        assert c.tipos == ["ACCESOS_DENEGADOS_REPETIDOS"]
        assert str(UMBRAL_ACCESOS_DENEGADOS) in c.motivos["ACCESOS_DENEGADOS_REPETIDOS"]

    def test_accesos_fallidos_y_denegados_se_suman(self, conn):
        _insertar_y_leer(conn, tipo_accion="ACCESO_FALLIDO")
        _insertar_y_leer(conn, tipo_accion="ACCESO_DENEGADO")
        ev = _insertar_y_leer(conn, tipo_accion="ACCESO_FALLIDO")
        assert clasificar_evento(conn, ev).tipos == ["ACCESOS_DENEGADOS_REPETIDOS"]

    def test_accesos_denegados_fuera_de_la_ventana_no_cuentan(self, conn):
        viejo = (datetime.utcnow() - timedelta(hours=2)).isoformat()
        for _ in range(UMBRAL_ACCESOS_DENEGADOS - 1):
            _insertar_y_leer(conn, tipo_accion="ACCESO_DENEGADO", timestamp=viejo)
        ev = _insertar_y_leer(conn, tipo_accion="ACCESO_DENEGADO")
        assert clasificar_evento(conn, ev) is None

    def test_timestamps_identicos_se_desempatan_por_event_id(self, conn):
        """Reloj de Windows (~15 ms): ráfagas pueden compartir timestamp exacto."""
        ts = datetime.utcnow().isoformat()
        eventos = [_insertar_y_leer(conn, tipo_accion="ACCESO_DENEGADO", timestamp=ts)
                   for _ in range(UMBRAL_ACCESOS_DENEGADOS + 1)]
        criticos = [clasificar_evento(conn, ev) is not None for ev in eventos]
        assert criticos == [False] * (UMBRAL_ACCESOS_DENEGADOS - 1) + [True, True]

    def test_accesos_denegados_de_otro_usuario_no_cuentan(self, conn):
        for i in range(UMBRAL_ACCESOS_DENEGADOS - 1):
            _insertar_y_leer(conn, tipo_accion="ACCESO_DENEGADO", usuario_id=f"otro-{i}")
        ev = _insertar_y_leer(conn, tipo_accion="ACCESO_DENEGADO")
        assert clasificar_evento(conn, ev) is None

    def test_evento_marcado_como_anomalia_hu_6_3(self, conn):
        ev = _insertar_y_leer(conn, nivel_alerta="ANOMALIA", motivo_alerta="Horario inusual: 03:00")
        c = clasificar_evento(conn, ev)
        assert c.tipos == ["ANOMALIA_DETECTADA"]
        assert c.severidad == "MEDIA"
        assert "Horario inusual" in c.motivos["ANOMALIA_DETECTADA"]

    def test_firma_invalida_y_auditoria_desactivada_son_criticas(self, conn):
        for tipo in ("FIRMA_INVALIDA", "AUDITORIA_DESACTIVADA"):
            ev = _insertar_y_leer(conn, tipo_accion=tipo, nivel_alerta="CRITICO")
            c = clasificar_evento(conn, ev)
            assert c.tipos == [tipo]
            assert c.severidad == "CRITICA"

    def test_varios_tipos_un_solo_resultado_con_la_severidad_mayor(self, conn):
        ev = _insertar_y_leer(conn, tipo_accion="EXPORTACION", filas_exportadas=50_000,
                              nivel_alerta="ANOMALIA", motivo_alerta="Volumen anómalo")
        c = clasificar_evento(conn, ev)
        assert c.tipos == ["EXPORTACION_MASIVA", "ANOMALIA_DETECTADA"]
        assert c.severidad == "ALTA"


# ──────────────────────────────────────────────────────────────
# Sub-tarea 4 — Destinatarios (modelo)
# ──────────────────────────────────────────────────────────────

class TestDestinatarios:
    def test_siembra_por_defecto_auditor_y_admin(self, conn):
        dest = {(d["tipo_destino"], d["valor"]): d for d in modelo.listar_destinatarios(conn)}
        assert dest[("ROL", "AUDITOR")]["severidad_minima"] == "MEDIA"
        assert dest[("ROL", "ADMIN")]["severidad_minima"] == "ALTA"

    def test_la_siembra_no_se_repite_si_se_eliminan(self, conn):
        for d in modelo.listar_destinatarios(conn):
            modelo.eliminar_destinatario(conn, d["destinatario_id"])
        modelo.ensure_alert_tables(conn)
        assert modelo.listar_destinatarios(conn) == []

    def test_rol_se_expande_solo_a_usuarios_activos(self, conn, usuarios):
        correos = modelo.resolver_correos_destino(conn, "MEDIA", ["ANOMALIA_DETECTADA"])
        assert correos == ["oficial@hospital.org"]  # admin exige ALTA; el inactivo se excluye

    def test_severidad_alta_llega_a_auditor_y_admin(self, conn, usuarios):
        correos = modelo.resolver_correos_destino(conn, "ALTA", ["EXPORTACION_MASIVA"])
        assert sorted(correos) == ["admin@hospital.org", "oficial@hospital.org"]

    def test_filtro_por_tipos_de_evento(self, conn, usuarios):
        modelo.crear_destinatario(conn, "EMAIL", "Seguridad@Hospital.org", "MEDIA",
                                  tipos_evento=["ACCESOS_DENEGADOS_REPETIDOS"])
        assert "seguridad@hospital.org" in modelo.resolver_correos_destino(
            conn, "ALTA", ["ACCESOS_DENEGADOS_REPETIDOS"])
        assert "seguridad@hospital.org" not in modelo.resolver_correos_destino(
            conn, "ALTA", ["EXPORTACION_MASIVA"])

    def test_destinatario_inactivo_no_recibe(self, conn, usuarios):
        aud = next(d for d in modelo.listar_destinatarios(conn) if d["valor"] == "AUDITOR")
        modelo.actualizar_destinatario(conn, aud["destinatario_id"], activo=False)
        assert modelo.resolver_correos_destino(conn, "MEDIA", ["ANOMALIA_DETECTADA"]) == []

    def test_correos_no_se_duplican(self, conn, usuarios):
        modelo.crear_destinatario(conn, "EMAIL", "oficial@hospital.org", "MEDIA")
        correos = modelo.resolver_correos_destino(conn, "CRITICA", ["FIRMA_INVALIDA"])
        assert correos.count("oficial@hospital.org") == 1

    def test_destinatario_duplicado_lanza_integrity_error(self, conn):
        modelo.crear_destinatario(conn, "EMAIL", "x@y.org")
        with pytest.raises(sqlite3.IntegrityError):
            modelo.crear_destinatario(conn, "EMAIL", "X@Y.org")


# ──────────────────────────────────────────────────────────────
# CA3 — Contenido del correo
# ──────────────────────────────────────────────────────────────

class TestContenidoCorreo:
    def test_incluye_informacion_minima_y_enlace(self, conn):
        ev = _insertar_y_leer(conn, tipo_accion="EXPORTACION", filas_exportadas=20_000,
                              usuario_id="u-garcia", dataset_nombre="HISTORIAS.csv",
                              timestamp="2026-11-04T10:15:30")
        msg = construir_mensaje(ev, clasificar_evento(conn, ev),
                                f"https://audit.example.org/eventos/{ev['event_id']}",
                                ["oficial@hospital.org"], "alertas@hospital.org")
        texto = msg.get_body(preferencelist=("plain",)).get_content()
        html = msg.get_body(preferencelist=("html",)).get_content()
        for cuerpo in (texto, html):
            assert "u-garcia" in cuerpo
            assert "EXPORTACION" in cuerpo
            assert "HISTORIAS.csv" in cuerpo
            assert "2026-11-04 10:15:30" in cuerpo
            assert f"https://audit.example.org/eventos/{ev['event_id']}" in cuerpo
        assert "[ALTA]" in msg["Subject"] and "Exportación masiva" in msg["Subject"]
        assert msg["Bcc"] == "oficial@hospital.org"

    def test_html_escapa_valores_del_evento(self, conn):
        ev = _insertar_y_leer(conn, nivel_alerta="ANOMALIA", dataset_nombre="<script>x</script>")
        msg = construir_mensaje(ev, clasificar_evento(conn, ev), "https://a/eventos/1",
                                ["a@b.org"], "c@d.org")
        assert "<script>x</script>" not in msg.get_body(preferencelist=("html",)).get_content()


# ──────────────────────────────────────────────────────────────
# CA2 — Disparo de la notificación
# ──────────────────────────────────────────────────────────────

class TestDisparo:
    @pytest.mark.parametrize("campos, tipo", [
        ({"tipo_accion": "EXPORTACION", "filas_exportadas": 5000}, "EXPORTACION_MASIVA"),
        ({"nivel_alerta": "ANOMALIA", "motivo_alerta": "Correlación"}, "ANOMALIA_DETECTADA"),
        ({"tipo_accion": "FIRMA_INVALIDA", "nivel_alerta": "CRITICO"}, "FIRMA_INVALIDA"),
        ({"tipo_accion": "AUDITORIA_DESACTIVADA", "nivel_alerta": "CRITICO"}, "AUDITORIA_DESACTIVADA"),
    ])
    def test_cada_tipo_critico_envia_correo(self, conn, despachador, correo, campos, tipo):
        event_id = insert_event(conn, _evento(**campos))
        despachador.procesar_pendientes()

        notif = modelo.obtener_notificacion_por_evento(conn, event_id)
        assert notif["estado"] == modelo.ESTADO_ENVIADA
        assert notif["tipos_criticos"] == tipo
        assert len(correo.enviados) == 1
        assert "oficial@hospital.org" in correo.enviados[0]["Bcc"]

    def test_accesos_denegados_repetidos_envia_un_solo_correo_por_rafaga(self, conn, despachador, correo):
        for _ in range(UMBRAL_ACCESOS_DENEGADOS + 3):
            insert_event(conn, _evento(tipo_accion="ACCESO_DENEGADO", nivel_alerta="ADVERTENCIA"))
        despachador.procesar_pendientes()

        assert len(correo.enviados) == 1
        estados = [n["estado"] for n in modelo.listar_notificaciones(conn)]
        assert estados.count(modelo.ESTADO_ENVIADA) == 1
        assert estados.count(modelo.ESTADO_AGRUPADA) == 3

    def test_evento_no_critico_no_notifica(self, conn, despachador, correo):
        insert_event(conn, _evento())
        assert despachador.procesar_pendientes() == [None]
        assert correo.enviados == []
        assert modelo.listar_notificaciones(conn) == []

    def test_rol_correspondiente_segun_severidad(self, conn, despachador, correo):
        insert_event(conn, _evento(nivel_alerta="ANOMALIA"))  # MEDIA → solo auditor
        insert_event(conn, _evento(tipo_accion="EXPORTACION", filas_exportadas=9999))  # ALTA → ambos
        despachador.procesar_pendientes()
        assert correo.enviados[0]["Bcc"] == "oficial@hospital.org"
        assert sorted(correo.enviados[1]["Bcc"].split(", ")) == ["admin@hospital.org", "oficial@hospital.org"]

    def test_un_evento_nunca_se_notifica_dos_veces(self, conn, despachador, correo):
        event_id = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        despachador.procesar_pendientes()
        assert despachador.procesar_evento(event_id) is None
        assert len(correo.enviados) == 1

    def test_sin_destinatarios_queda_registrado(self, conn, despachador, correo):
        for d in modelo.listar_destinatarios(conn):
            modelo.eliminar_destinatario(conn, d["destinatario_id"])
        event_id = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        despachador.procesar_pendientes()
        assert modelo.obtener_notificacion_por_evento(conn, event_id)["estado"] == modelo.ESTADO_SIN_DESTINATARIOS
        assert correo.enviados == []

    def test_sin_servicio_de_correo_queda_registrado(self, conn, despachador):
        despachador.servicio_correo = None
        event_id = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        despachador.procesar_pendientes()
        assert modelo.obtener_notificacion_por_evento(conn, event_id)["estado"] == modelo.ESTADO_SIN_SERVICIO

    def test_reintenta_y_luego_envia(self, conn, despachador):
        despachador.servicio_correo = ServicioCorreoMemoria(fallos=2)
        event_id = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        despachador.procesar_pendientes()
        notif = modelo.obtener_notificacion_por_evento(conn, event_id)
        assert notif["estado"] == modelo.ESTADO_ENVIADA
        assert notif["intentos"] == 3

    def test_agota_reintentos_y_marca_fallida(self, conn, despachador):
        despachador.servicio_correo = ServicioCorreoMemoria(fallos=99)
        event_id = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        despachador.procesar_pendientes()
        notif = modelo.obtener_notificacion_por_evento(conn, event_id)
        assert notif["estado"] == modelo.ESTADO_FALLIDA
        assert notif["intentos"] == despachador.max_intentos
        assert "Fallo simulado" in notif["error"]

    def test_ignora_inserciones_en_otra_base(self, tmp_path, despachador, correo):
        otra = get_connection(str(tmp_path / "local.db"))
        insert_event(otra, _evento(nivel_alerta="ANOMALIA"))
        otra.close()
        assert despachador.procesar_pendientes() == []
        assert correo.enviados == []

    def test_enlace_apunta_al_detalle_del_evento(self, conn, despachador, correo):
        event_id = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        despachador.procesar_pendientes()
        texto = correo.enviados[0].get_body(preferencelist=("plain",)).get_content()
        assert f"https://audit.example.org/eventos/{event_id}" in texto

    def test_hilo_en_segundo_plano_procesa_la_cola(self, conn, despachador, correo):
        despachador.iniciar()
        try:
            insert_event(conn, _evento(tipo_accion="EXPORTACION", filas_exportadas=2000))
            assert despachador.esperar(timeout=5)
            assert len(correo.enviados) == 1
        finally:
            despachador.detener()


# ──────────────────────────────────────────────────────────────
# CA4 — El envío no bloquea ni afecta el registro
# ──────────────────────────────────────────────────────────────

class TestDesacoplamiento:
    def test_correo_lento_no_retrasa_el_insert(self, conn, despachador):
        despachador.servicio_correo = ServicioCorreoMemoria(demora_segundos=2.0)
        despachador.iniciar()
        try:
            inicio = time.perf_counter()
            event_id = insert_event(conn, _evento(tipo_accion="EXPORTACION", filas_exportadas=5000))
            duracion = time.perf_counter() - inicio
            assert duracion < 0.5, f"insert_event tardó {duracion:.2f}s esperando al correo"
            assert get_event_by_id(conn, event_id) is not None
            assert despachador.esperar(timeout=10)
        finally:
            despachador.detener()

    def test_fallo_del_correo_no_afecta_el_registro(self, conn, despachador):
        despachador.servicio_correo = ServicioCorreoMemoria(fallos=99)
        despachador.iniciar()
        try:
            event_id = insert_event(conn, _evento(tipo_accion="EXPORTACION", filas_exportadas=5000))
            assert despachador.esperar(timeout=5)
        finally:
            despachador.detener()
        ev = get_event_by_id(conn, event_id)
        assert ev["filas_exportadas"] == 5000
        assert modelo.obtener_notificacion_por_evento(conn, event_id)["estado"] == modelo.ESTADO_FALLIDA

    def test_excepcion_en_un_hook_no_rompe_el_insert(self, conn):
        def hook_roto(*_):
            raise RuntimeError("boom")
        registrar_hook_post_insercion(hook_roto)
        try:
            event_id = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        finally:
            eliminar_hook_post_insercion(hook_roto)
        assert get_event_by_id(conn, event_id) is not None

    def test_hook_corre_despues_del_commit(self, db_path, conn):
        visto = {}

        def hook(c, event_id, _):
            otra = sqlite3.connect(db_path)  # otra conexión: solo ve datos ya confirmados
            visto["existe"] = otra.execute(
                "SELECT 1 FROM audit_log WHERE event_id = ?", (event_id,)).fetchone() is not None
            otra.close()

        registrar_hook_post_insercion(hook)
        try:
            insert_event(conn, _evento())
        finally:
            eliminar_hook_post_insercion(hook)
        assert visto["existe"] is True

    def test_cola_llena_descarta_la_alerta_no_el_evento(self, db_path, conn, correo):
        d = DespachadorAlertas(db_path, servicio_correo=correo, tamano_cola=1)
        registrar_hook_post_insercion(d.hook_post_insercion)
        try:
            id1 = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
            id2 = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        finally:
            eliminar_hook_post_insercion(d.hook_post_insercion)
        assert d.descartados == 1
        assert get_event_by_id(conn, id1) and get_event_by_id(conn, id2)

    def test_error_en_la_clasificacion_no_mata_el_hilo(self, conn, despachador, correo, monkeypatch):
        from audit_tracer.alerts import dispatcher as mod
        llamadas = {"n": 0}
        original = mod.clasificar_evento

        def falla_una_vez(c, ev):
            llamadas["n"] += 1
            if llamadas["n"] == 1:
                raise RuntimeError("fallo inesperado")
            return original(c, ev)

        monkeypatch.setattr(mod, "clasificar_evento", falla_una_vez)
        despachador.iniciar()
        try:
            insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
            insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
            assert despachador.esperar(timeout=5)
            assert despachador.activo
        finally:
            despachador.detener()
        assert len(correo.enviados) == 1


# ──────────────────────────────────────────────────────────────
# Servicio de correo — configuración por entorno
# ──────────────────────────────────────────────────────────────

class TestServicioCorreo:
    def test_sin_configuracion_no_hay_servicio(self, monkeypatch):
        monkeypatch.delenv("AUDIT_SMTP_HOST", raising=False)
        monkeypatch.delenv("AUDIT_ALERTAS_OUTBOX", raising=False)
        assert crear_servicio_correo_desde_entorno() is None

    def test_smtp_desde_entorno(self, monkeypatch):
        monkeypatch.setenv("AUDIT_SMTP_HOST", "smtp.example.org")
        monkeypatch.setenv("AUDIT_SMTP_USER", "alertas@example.org")
        monkeypatch.setenv("AUDIT_SMTP_PASSWORD", "secreto")
        s = crear_servicio_correo_desde_entorno()
        assert isinstance(s, ServicioCorreoSMTP)
        assert s.config.port == 587 and s.config.starttls and not s.config.ssl
        assert s.remitente == "alertas@example.org"
        assert "secreto" not in s.descripcion()

    def test_smtp_ssl_usa_puerto_465(self, monkeypatch):
        monkeypatch.setenv("AUDIT_SMTP_HOST", "smtp.example.org")
        monkeypatch.setenv("AUDIT_SMTP_SSL", "1")
        cfg = ConfiguracionSMTP.desde_entorno()
        assert cfg.port == 465 and cfg.ssl and not cfg.starttls

    def test_smtp_envia_con_starttls_y_login(self, monkeypatch, conn):
        enviados = {}

        class SMTPFalso:
            def __init__(self, host, port, timeout):
                enviados["destino"] = (host, port)
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def starttls(self, context=None): enviados["tls"] = True
            def login(self, u, p): enviados["login"] = u
            def send_message(self, m): enviados["mensaje"] = m

        import audit_tracer.alerts.email_service as es
        monkeypatch.setattr(es.smtplib, "SMTP", SMTPFalso)
        s = ServicioCorreoSMTP(ConfiguracionSMTP(host="smtp.x.org", usuario="u@x.org",
                                                 password="p", remitente="u@x.org"))
        ev = _insertar_y_leer(conn, nivel_alerta="ANOMALIA")
        s.enviar(construir_mensaje(ev, clasificar_evento(conn, ev), "https://a/eventos/1",
                                   ["o@x.org"], s.remitente))
        assert enviados["destino"] == ("smtp.x.org", 587)
        assert enviados["tls"] and enviados["login"] == "u@x.org"

    def test_error_smtp_se_convierte_en_error_envio(self, monkeypatch):
        import audit_tracer.alerts.email_service as es

        def conexion_rechazada(*a, **k):
            raise ConnectionRefusedError("sin servidor")

        monkeypatch.setattr(es.smtplib, "SMTP", conexion_rechazada)
        s = ServicioCorreoSMTP(ConfiguracionSMTP(host="smtp.x.org"))
        with pytest.raises(es.ErrorEnvioCorreo):
            s.enviar(es.construir_mensaje_prueba("a@b.org", "c@d.org", "https://x"))

    def test_outbox_guarda_eml(self, tmp_path, monkeypatch):
        monkeypatch.delenv("AUDIT_SMTP_HOST", raising=False)
        monkeypatch.setenv("AUDIT_ALERTAS_OUTBOX", str(tmp_path / "outbox"))
        s = crear_servicio_correo_desde_entorno()
        assert isinstance(s, ServicioCorreoArchivo)
        from audit_tracer.alerts.email_service import construir_mensaje_prueba
        s.enviar(construir_mensaje_prueba("a@b.org", s.remitente, "https://x"))
        assert len(list((tmp_path / "outbox").glob("*.eml"))) == 1


# ──────────────────────────────────────────────────────────────
# Integración con la app: endpoints reales + configuración desde el dashboard
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def app_alertas(monkeypatch, db_path, usuarios):
    """App con get_db() a una base aislada y un despachador global con hilo real."""
    monkeypatch.setattr(app_module, "get_db", lambda: get_central_connection(db_path))
    app_module.app.config["TESTING"] = True
    correo = ServicioCorreoMemoria()
    d = configurar_alertas(db_path, servicio_correo=correo, backoff_base_segundos=0)
    try:
        with app_module.app.test_client() as client:
            yield client, d, correo
    finally:
        desactivar_alertas()


def _login(client, usuario_id, rol):
    crear_sesion_web(client, usuario_id, rol, f"{rol.lower()}@hospital.org", "s-test")


class TestIntegracionApp:
    def test_exportacion_masiva_sincronizada_dispara_correo(self, app_alertas, db_path, conn):
        client, d, correo = app_alertas
        cientifico = create_user(conn, "colab@hospital.org", "Password123!", "CIENTIFICO_DATOS")
        token = generar_token(conn, cientifico)["token"]

        resp = client.post("/api/eventos/sincronizar", json={
            "evento_uuid": str(uuid.uuid4()),
            "usuario_id": cientifico,
            "sesion_id": "s-colab",
            "timestamp": datetime.utcnow().replace(hour=10).isoformat(),
            "tipo_accion": "EXPORTACION",
            "dataset_nombre": "PACIENTES_UCI.csv",
            "filas_exportadas": 25_000,
            "nivel_alerta": "CRITICO",
        }, headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 201  # CA4: la respuesta no depende del correo
        event_id = resp.get_json()["event_id"]

        assert d.esperar(timeout=5)
        assert len(correo.enviados) == 1
        texto = correo.enviados[0].get_body(preferencelist=("plain",)).get_content()
        assert "PACIENTES_UCI.csv" in texto
        assert f"/eventos/{event_id}" in texto

    def test_accesos_denegados_repetidos_en_el_dashboard_disparan_correo(self, app_alertas, conn):
        client, d, correo = app_alertas
        cientifico = create_user(conn, "curioso@hospital.org", "Password123!", "CIENTIFICO_DATOS")
        _login(client, cientifico, "CIENTIFICO_DATOS")
        for _ in range(UMBRAL_ACCESOS_DENEGADOS):
            assert client.get("/reportes").status_code == 403

        assert d.esperar(timeout=5)
        assert len(correo.enviados) == 1
        assert "Accesos denegados repetidos" in correo.enviados[0]["Subject"]

    def test_pagina_de_alertas_solo_para_admin(self, app_alertas, usuarios):
        client, _, _ = app_alertas
        _login(client, usuarios["auditor"], "AUDITOR")
        assert client.get("/admin/alertas").status_code == 302
        _login(client, usuarios["admin"], "ADMIN")
        resp = client.get("/admin/alertas")
        assert resp.status_code == 200
        html = resp.get_data(as_text=True)
        for t in CATALOGO_EVENTOS_CRITICOS.values():
            assert t.nombre in html

    def test_admin_agrega_edita_desactiva_y_elimina_destinatario(self, app_alertas, usuarios, conn):
        client, _, _ = app_alertas
        _login(client, usuarios["admin"], "ADMIN")

        client.post("/admin/alertas/destinatarios", data={
            "tipo_destino": "EMAIL", "valor_email": "cumplimiento@hospital.org",
            "severidad_minima": "ALTA", "tipos_evento": ["EXPORTACION_MASIVA"],
        })
        dest = next(x for x in modelo.listar_destinatarios(conn) if x["valor"] == "cumplimiento@hospital.org")
        assert dest["severidad_minima"] == "ALTA" and dest["tipos_evento"] == ["EXPORTACION_MASIVA"]

        url = f"/admin/alertas/destinatarios/{dest['destinatario_id']}"
        client.post(url, data={"accion": "actualizar", "severidad_minima": "CRITICA"})
        assert modelo.obtener_destinatario(conn, dest["destinatario_id"])["severidad_minima"] == "CRITICA"
        assert modelo.obtener_destinatario(conn, dest["destinatario_id"])["tipos_evento"] == []

        client.post(url, data={"accion": "alternar"})
        assert modelo.obtener_destinatario(conn, dest["destinatario_id"])["activo"] is False

        client.post(url, data={"accion": "eliminar"})
        assert modelo.obtener_destinatario(conn, dest["destinatario_id"]) is None

        cambios = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE tipo_accion = 'CONFIGURACION_ALERTAS'").fetchone()[0]
        assert cambios == 4

    def test_correo_invalido_se_rechaza(self, app_alertas, usuarios, conn):
        client, _, _ = app_alertas
        _login(client, usuarios["admin"], "ADMIN")
        resp = client.post("/admin/alertas/destinatarios", data={
            "tipo_destino": "EMAIL", "valor_email": "no-es-correo", "severidad_minima": "MEDIA",
        }, follow_redirects=True)
        assert "Correo electrónico inválido" in resp.get_data(as_text=True)
        assert all(x["valor"] != "no-es-correo" for x in modelo.listar_destinatarios(conn))

    def test_no_admin_no_puede_cambiar_destinatarios(self, app_alertas, usuarios, conn):
        client, _, _ = app_alertas
        _login(client, usuarios["auditor"], "AUDITOR")
        client.post("/admin/alertas/destinatarios", data={
            "tipo_destino": "EMAIL", "valor_email": "intruso@x.org", "severidad_minima": "MEDIA",
        })
        assert all(x["valor"] != "intruso@x.org" for x in modelo.listar_destinatarios(conn))

    def test_correo_de_prueba(self, app_alertas, usuarios):
        client, _, correo = app_alertas
        _login(client, usuarios["admin"], "ADMIN")
        resp = client.post("/admin/alertas/prueba", data={"destino": "yo@hospital.org"},
                           follow_redirects=True)
        assert "Correo de prueba enviado" in resp.get_data(as_text=True)
        assert correo.enviados[0]["To"] == "yo@hospital.org"

    def test_configuracion_afecta_el_siguiente_envio(self, app_alertas, usuarios, conn):
        """Sub-tarea 4: subir la severidad mínima del auditor a ALTA silencia las anomalías (MEDIA)."""
        client, d, correo = app_alertas
        _login(client, usuarios["admin"], "ADMIN")
        aud = next(x for x in modelo.listar_destinatarios(conn) if x["valor"] == "AUDITOR")
        client.post(f"/admin/alertas/destinatarios/{aud['destinatario_id']}",
                    data={"accion": "actualizar", "severidad_minima": "ALTA"})

        event_id = insert_event(conn, _evento(nivel_alerta="ANOMALIA"))
        assert d.esperar(timeout=5)
        assert correo.enviados == []
        assert modelo.obtener_notificacion_por_evento(conn, event_id)["estado"] == modelo.ESTADO_SIN_DESTINATARIOS


def test_no_quedan_hooks_registrados_tras_las_pruebas():
    """Los fixtures limpian sus hooks: nada de este archivo se filtra a otras suites."""
    assert obtener_despachador() is None
    assert not any(getattr(h, "__self__", None).__class__.__name__ == "DespachadorAlertas"
                   for h in _hooks_post_insercion)
