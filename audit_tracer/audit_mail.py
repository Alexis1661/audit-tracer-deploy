"""Entrega de avisos críticos desde un proceso separado del servidor web."""

import os
import secrets
import smtplib
import sqlite3
import ssl
import time
from email.message import EmailMessage

import click

from .audit_workspace import can_review_alerts, workspace_db
from .auth.control_acceso import PERMISSION_MATRIX


def smtp_configured():
    return bool(os.getenv("AUDIT_SMTP_HOST") and os.getenv("AUDIT_SMTP_FROM"))


def _claim(get_db):
    now = int(time.time())
    roles = tuple(role for role in PERMISSION_MATRIX if can_review_alerts(role))
    placeholders = ", ".join("?" for _ in roles)
    with workspace_db(get_db) as conn, conn:
        conn.execute("BEGIN IMMEDIATE")
        recipient = conn.execute(
            f"""SELECT s.usuario_id, u.email, s.correo_hasta FROM audit_notification_settings s
                JOIN usuarios u ON u.usuario_id = s.usuario_id
                WHERE s.por_correo = 1 AND s.correo_reserva_hasta <= ? AND u.activo = 1
                  AND u.rol IN ({placeholders})
                  AND EXISTS (SELECT 1 FROM audit_log WHERE nivel_alerta = 'CRITICO' AND event_id > s.correo_hasta)
                ORDER BY s.correo_reserva_hasta, s.usuario_id LIMIT 1""",
            (now, *roles),
        ).fetchone()
        if not recipient:
            return None
        events = conn.execute(
            """SELECT event_id, count(*) OVER () AS total FROM audit_log
               WHERE nivel_alerta = 'CRITICO' AND event_id > ? ORDER BY event_id DESC LIMIT 50""",
            (recipient["correo_hasta"],),
        ).fetchall()
        token = secrets.token_hex(16)
        conn.execute(
            "UPDATE audit_notification_settings SET correo_reserva = ?, correo_reserva_hasta = ? WHERE usuario_id = ?",
            (token, now + 300, recipient["usuario_id"]),
        )
        return recipient, events, token


def _send(recipient, events):
    host = os.environ["AUDIT_SMTP_HOST"]
    implicit_tls = os.getenv("AUDIT_SMTP_TLS") == "implicit"
    port = int(os.getenv("AUDIT_SMTP_PORT", "465" if implicit_tls else "587"))
    message = EmailMessage()
    message["From"] = os.environ["AUDIT_SMTP_FROM"]
    message["To"] = recipient
    message["Subject"] = "Audit Tracer · Nuevas alertas críticas"
    entries = "\n".join(f"• Evento #{row['event_id']}" for row in events)
    message.set_content(
        f"Se registraron {events[0]['total']} alertas críticas. Abre el Centro de alertas para revisarlas.\n\n"
        f"Identificadores más recientes:\n{entries}"
    )
    tls = ssl.create_default_context()
    server = smtplib.SMTP_SSL(host, port, context=tls, timeout=20) if implicit_tls else smtplib.SMTP(host, port, timeout=20)
    try:
        if not implicit_tls:
            server.starttls(context=tls)
        username = os.getenv("AUDIT_SMTP_USER")
        if username:
            server.login(username, os.environ["AUDIT_SMTP_PASSWORD"])
        server.send_message(message)
    finally:
        server.close()


def _deliver_pending(get_db):
    sent, failed = 0, 0
    for _ in range(100):
        batch = _claim(get_db)
        if not batch:
            break
        recipient, events, token = batch
        user_id = recipient["usuario_id"]
        with workspace_db(get_db) as conn:
            account = conn.execute(
                """SELECT u.rol, u.email FROM usuarios u
                   JOIN audit_notification_settings s ON u.usuario_id = s.usuario_id
                   WHERE u.usuario_id = ? AND u.activo = 1 AND s.por_correo = 1
                     AND s.correo_reserva = ? AND s.correo_reserva_hasta > ?""",
                (user_id, token, int(time.time())),
            ).fetchone()
        if not account or not can_review_alerts(account["rol"]):
            continue
        try:
            _send(account["email"], events)
        except (OSError, ValueError, KeyError) as exc:
            failed += 1
            click.echo(f"Envío SMTP pendiente ({type(exc).__name__}). Se reintentará.", err=True)
            continue  # La reserva vence y permite reintentar sin avanzar el cursor.
        with workspace_db(get_db) as conn, conn:
            conn.execute(
                """UPDATE audit_notification_settings
                   SET correo_hasta = ?, correo_reserva = NULL, correo_reserva_hasta = ?
                   WHERE usuario_id = ? AND correo_reserva = ?""",
                (events[0]["event_id"], int(time.time()) + 900, user_id, token),
            )
        sent += 1
    return sent, failed


def register_audit_mail_command(app, get_db):
    @app.cli.command("audit-email")
    @click.option("--watch", is_flag=True, help="Mantiene el envío activo, con consultas cada 30 segundos.")
    def audit_email(watch):
        """Envía avisos críticos pendientes a usuarios suscritos."""
        if not smtp_configured():
            raise click.ClickException("Define AUDIT_SMTP_HOST y AUDIT_SMTP_FROM.")
        while True:
            try:
                sent, failed = _deliver_pending(get_db)
            except sqlite3.OperationalError as exc:
                if not watch:
                    raise click.ClickException("No se pudo consultar la base de auditoría.") from exc
                click.echo("Base de auditoría temporalmente no disponible. Se reintentará.", err=True)
                time.sleep(30)
                continue
            if not watch:
                click.echo(f"Resúmenes enviados: {sent}. Fallidos: {failed}.")
                if failed:
                    raise click.ClickException("Hay entregas que requieren reintento.")
                return
            time.sleep(30)
