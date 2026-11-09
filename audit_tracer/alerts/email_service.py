"""
email_service.py — HU-7.2 CA2/CA3 / Sub-tarea 2: integración con el servicio de correo.

Solo librería estándar (smtplib + email.message): sin dependencias nuevas.

Configuración por variables de entorno (nunca en el código ni en la base,
igual que SECRET_KEY — el repositorio es legible por terceros):

  AUDIT_SMTP_HOST       servidor SMTP (p. ej. smtp.gmail.com, smtp.office365.com)
  AUDIT_SMTP_PORT       puerto (por defecto 587)
  AUDIT_SMTP_USER       usuario SMTP (opcional si el relay no autentica)
  AUDIT_SMTP_PASSWORD   contraseña / app password
  AUDIT_SMTP_FROM       remitente (por defecto = AUDIT_SMTP_USER)
  AUDIT_SMTP_STARTTLS   1 (por defecto) usa STARTTLS; 0 lo desactiva
  AUDIT_SMTP_SSL        1 usa SMTP_SSL (puerto 465); por defecto 0
  AUDIT_SMTP_TIMEOUT    segundos (por defecto 10)

  AUDIT_ALERTAS_OUTBOX  alternativa para desarrollo/demo: si no hay SMTP,
                        cada correo se guarda como .eml en esta carpeta
                        (se abre con cualquier cliente de correo).

Si no hay ni SMTP ni outbox, crear_servicio_correo_desde_entorno() devuelve
None y el dispatcher deja la notificación registrada como
SIN_SERVICIO_CORREO — visible en el dashboard, nunca un fallo silencioso.
"""

import html
import os
import smtplib
import ssl
import threading
from dataclasses import dataclass
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Dict, List, Optional

from .catalogo import CATALOGO_EVENTOS_CRITICOS, ClasificacionCritica


class ErrorEnvioCorreo(Exception):
    """Fallo al entregar un correo al servicio de envío."""


# ──────────────────────────────────────────────────────────────
# Configuración
# ──────────────────────────────────────────────────────────────

def _env_bool(nombre: str, defecto: bool) -> bool:
    valor = os.environ.get(nombre)
    if valor is None or valor.strip() == "":
        return defecto
    return valor.strip().lower() in ("1", "true", "si", "sí", "yes", "on")


@dataclass
class ConfiguracionSMTP:
    host: str
    port: int = 587
    usuario: Optional[str] = None
    password: Optional[str] = None
    remitente: Optional[str] = None
    starttls: bool = True
    ssl: bool = False
    timeout: float = 10.0

    @classmethod
    def desde_entorno(cls) -> Optional["ConfiguracionSMTP"]:
        host = (os.environ.get("AUDIT_SMTP_HOST") or "").strip()
        if not host:
            return None
        usuario = (os.environ.get("AUDIT_SMTP_USER") or "").strip() or None
        usar_ssl = _env_bool("AUDIT_SMTP_SSL", False)
        return cls(
            host=host,
            port=int(os.environ.get("AUDIT_SMTP_PORT") or (465 if usar_ssl else 587)),
            usuario=usuario,
            password=os.environ.get("AUDIT_SMTP_PASSWORD") or None,
            remitente=(os.environ.get("AUDIT_SMTP_FROM") or "").strip() or usuario,
            starttls=_env_bool("AUDIT_SMTP_STARTTLS", not usar_ssl),
            ssl=usar_ssl,
            timeout=float(os.environ.get("AUDIT_SMTP_TIMEOUT") or 10),
        )


# ──────────────────────────────────────────────────────────────
# Servicios de envío
# ──────────────────────────────────────────────────────────────

class ServicioCorreo:
    """Interfaz: enviar(mensaje) entrega un EmailMessage o lanza ErrorEnvioCorreo."""

    nombre = "base"
    remitente = "audit-tracer@localhost"

    def enviar(self, mensaje: EmailMessage) -> None:  # pragma: no cover - interfaz
        raise NotImplementedError

    def descripcion(self) -> str:
        return self.nombre


class ServicioCorreoSMTP(ServicioCorreo):
    nombre = "SMTP"

    def __init__(self, config: ConfiguracionSMTP):
        self.config = config
        self.remitente = config.remitente or "audit-tracer@localhost"

    def descripcion(self) -> str:
        modo = "SSL" if self.config.ssl else ("STARTTLS" if self.config.starttls else "sin TLS")
        return f"SMTP {self.config.host}:{self.config.port} ({modo})"

    def enviar(self, mensaje: EmailMessage) -> None:
        c = self.config
        try:
            if c.ssl:
                servidor = smtplib.SMTP_SSL(c.host, c.port, timeout=c.timeout,
                                            context=ssl.create_default_context())
            else:
                servidor = smtplib.SMTP(c.host, c.port, timeout=c.timeout)
            with servidor:
                if not c.ssl and c.starttls:
                    servidor.starttls(context=ssl.create_default_context())
                if c.usuario and c.password:
                    servidor.login(c.usuario, c.password)
                servidor.send_message(mensaje)
        except (smtplib.SMTPException, OSError) as exc:
            # El mensaje del error nunca incluye la contraseña: smtplib no la repite.
            raise ErrorEnvioCorreo(f"{type(exc).__name__}: {exc}") from exc


class ServicioCorreoArchivo(ServicioCorreo):
    """Desarrollo/demo: guarda cada correo como .eml en una carpeta."""

    nombre = "Archivo (.eml)"

    def __init__(self, carpeta: str, remitente: str = "audit-tracer@localhost"):
        self.carpeta = carpeta
        self.remitente = remitente

    def descripcion(self) -> str:
        return f"Carpeta de salida {self.carpeta}"

    def enviar(self, mensaje: EmailMessage) -> None:
        try:
            os.makedirs(self.carpeta, exist_ok=True)
            nombre = datetime.utcnow().strftime("%Y%m%dT%H%M%S%f") + ".eml"
            with open(os.path.join(self.carpeta, nombre), "wb") as f:
                f.write(bytes(mensaje))
        except OSError as exc:
            raise ErrorEnvioCorreo(f"{type(exc).__name__}: {exc}") from exc


class ServicioCorreoMemoria(ServicioCorreo):
    """Pruebas: acumula los mensajes en memoria. Puede simular fallos o lentitud."""

    nombre = "Memoria"

    def __init__(self, fallos: int = 0, demora_segundos: float = 0.0):
        self.enviados: List[EmailMessage] = []
        self.fallos_restantes = fallos
        self.demora_segundos = demora_segundos
        self.intentos = 0
        self._lock = threading.Lock()

    def enviar(self, mensaje: EmailMessage) -> None:
        if self.demora_segundos:
            import time
            time.sleep(self.demora_segundos)
        with self._lock:
            self.intentos += 1
            if self.fallos_restantes > 0:
                self.fallos_restantes -= 1
                raise ErrorEnvioCorreo("Fallo simulado del servidor de correo")
            self.enviados.append(mensaje)


def crear_servicio_correo_desde_entorno() -> Optional[ServicioCorreo]:
    config = ConfiguracionSMTP.desde_entorno()
    if config is not None:
        return ServicioCorreoSMTP(config)
    outbox = (os.environ.get("AUDIT_ALERTAS_OUTBOX") or "").strip()
    if outbox:
        return ServicioCorreoArchivo(
            outbox, remitente=(os.environ.get("AUDIT_SMTP_FROM") or "audit-tracer@localhost")
        )
    return None


# ──────────────────────────────────────────────────────────────
# Contenido del correo (CA3)
# ──────────────────────────────────────────────────────────────

def _valor(v) -> str:
    return "—" if v in (None, "", "None") else str(v)


def campos_minimos(evento: Dict) -> List[tuple]:
    """CA3 — Información mínima del evento, en el orden en que se muestra."""
    return [
        ("Usuario", _valor(evento.get("usuario_id"))),
        ("Tipo de acción", _valor(evento.get("tipo_accion"))),
        ("Dataset", _valor(evento.get("dataset_nombre"))),
        ("Timestamp (UTC)", _valor((evento.get("timestamp") or "").replace("T", " ")[:19] or None)),
        ("ID de evento", _valor(evento.get("event_id"))),
    ]


def construir_mensaje(
    evento: Dict,
    clasificacion: ClasificacionCritica,
    url_detalle: str,
    destinatarios: List[str],
    remitente: str,
) -> EmailMessage:
    """
    CA3 — Arma el correo: usuario, tipo de acción, dataset, timestamp,
    motivo de la alerta y un enlace directo al detalle del evento en el
    dashboard (/eventos/<event_id>, HU-4.3). Versión texto plano + HTML.
    """
    nombres = ", ".join(clasificacion.nombres)
    asunto = (
        f"[Audit Tracer][{clasificacion.severidad}] {nombres} — "
        f"usuario {_valor(evento.get('usuario_id'))}"
    )

    filas = campos_minimos(evento)
    motivos = [
        (CATALOGO_EVENTOS_CRITICOS[t].nombre, clasificacion.motivos.get(t, ""))
        for t in clasificacion.tipos
    ]

    texto = [
        "Se detectó un evento crítico de auditoría que requiere revisión.",
        "",
        f"Severidad: {clasificacion.severidad}",
        "",
    ]
    texto += [f"{k}: {v}" for k, v in filas]
    texto += ["", "Motivo:"]
    texto += [f"  - {n}: {m}" for n, m in motivos]
    texto += [
        "",
        f"Ver detalle en el dashboard: {url_detalle}",
        "",
        "— Audit Tracer · notificación automática (HU-7.2). No responda a este correo.",
    ]

    e = html.escape
    color = {"CRITICA": "#B91C1C", "ALTA": "#C2410C", "MEDIA": "#A16207"}.get(
        clasificacion.severidad, "#334155"
    )
    filas_html = "".join(
        f'<tr><td style="padding:6px 12px;color:#64748B;">{e(k)}</td>'
        f'<td style="padding:6px 12px;font-weight:600;">{e(v)}</td></tr>'
        for k, v in filas
    )
    motivos_html = "".join(f"<li><strong>{e(n)}:</strong> {e(m)}</li>" for n, m in motivos)
    cuerpo_html = f"""\
<!doctype html>
<html><body style="font-family:Arial,Helvetica,sans-serif;color:#0F172A;background:#F8FAFC;padding:24px;">
  <div style="max-width:560px;margin:auto;background:#fff;border:1px solid #E2E8F0;border-radius:12px;padding:24px;">
    <div style="display:inline-block;background:{color};color:#fff;border-radius:999px;padding:4px 12px;font-size:12px;font-weight:700;">
      Severidad {e(clasificacion.severidad)}
    </div>
    <h2 style="margin:12px 0 4px;">{e(nombres)}</h2>
    <p style="margin:0 0 16px;color:#475569;">Se detectó un evento crítico de auditoría que requiere revisión.</p>
    <table style="border-collapse:collapse;width:100%;font-size:14px;">{filas_html}</table>
    <p style="margin:16px 0 4px;font-weight:700;">Motivo</p>
    <ul style="margin:0 0 20px;padding-left:20px;font-size:14px;">{motivos_html}</ul>
    <a href="{e(url_detalle, quote=True)}"
       style="display:inline-block;background:#0F172A;color:#fff;text-decoration:none;padding:10px 18px;border-radius:8px;font-weight:600;">
      Ver detalle del evento
    </a>
    <p style="margin-top:20px;font-size:12px;color:#94A3B8;">Audit Tracer · notificación automática (HU-7.2). No responda a este correo.</p>
  </div>
</body></html>
"""

    msg = EmailMessage()
    msg["Subject"] = asunto
    msg["From"] = remitente
    # Los destinatarios van en Bcc implícito: To es el propio remitente para no
    # exponer a cada destinatario la lista completa de quienes reciben alertas.
    msg["To"] = remitente
    msg["Bcc"] = ", ".join(destinatarios)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="audit-tracer")
    msg["X-Audit-Event-Id"] = str(evento.get("event_id"))
    msg.set_content("\n".join(texto))
    msg.add_alternative(cuerpo_html, subtype="html")
    return msg


def construir_mensaje_prueba(destinatario: str, remitente: str, url_dashboard: str) -> EmailMessage:
    """Correo de prueba enviado desde /admin/alertas para validar la configuración."""
    msg = EmailMessage()
    msg["Subject"] = "[Audit Tracer] Correo de prueba de alertas"
    msg["From"] = remitente
    msg["To"] = destinatario
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="audit-tracer")
    msg.set_content(
        "Este es un correo de prueba de las alertas en tiempo real de Audit Tracer (HU-7.2).\n"
        "Si lo recibió, el servicio de envío está configurado correctamente.\n\n"
        f"Dashboard: {url_dashboard}\n"
    )
    return msg
