"""Vistas de investigación y seguimiento sobre el registro central."""

import json
import secrets
import sqlite3
from contextlib import closing, contextmanager
from datetime import date, datetime, timedelta, timezone

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, session, url_for

from .auth.control_acceso import has_permission
from .db import _init_from_schema


LEVELS = ("NORMAL", "ADVERTENCIA", "ANOMALIA", "CRITICO")
ALERT_LEVELS = LEVELS[1:]
ALERT_ENDPOINTS = frozenset(("alerts", "alert_review", "notifications", "notification_status"))
STATES = ("PENDIENTE", "EN_REVISION", "RESUELTA")
PAGE_SIZE = 25
SQLITE_MAX_INT = (1 << 63) - 1
FILTER_FIELDS = (
    "q", "usuario_id", "dataset_nombre", "sesion_id", "tipo_accion",
    "nivel_alerta", "fecha_inicio", "fecha_fin", "periodo",
)
EVENT_FIELDS = """
    e.event_id, e.timestamp, e.usuario_id, u.email, e.tipo_accion,
    e.dataset_nombre, e.sesion_id, e.nivel_alerta, e.hash_integridad
"""
EVENT_SOURCE = "audit_log e LEFT JOIN usuarios u ON u.usuario_id = e.usuario_id"


def can_review_alerts(role):
    return has_permission(role, "consulta_reportes") and has_permission(role, "visualizacion_alertas")


@contextmanager
def workspace_db(get_db):
    with closing(get_db()) as conn:
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        if not conn.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'audit_notification_settings'"
        ).fetchone():
            _init_from_schema(conn, ["audit_workspace.sql"])
        yield conn


def _filters(source):
    values = {key: source.get(key, "").strip() for key in FILTER_FIELDS}
    for key, value in values.items():
        if len(value) > 512:
            raise ValueError("El filtro supera la longitud permitida.")
    for key in ("fecha_inicio", "fecha_fin"):
        if values[key]:
            try:
                values[key] = date.fromisoformat(values[key]).isoformat()
            except ValueError:
                raise ValueError("Selecciona una fecha válida.") from None
    if values["fecha_inicio"] and values["fecha_fin"] and values["fecha_inicio"] > values["fecha_fin"]:
        raise ValueError("La fecha inicial debe ser anterior o igual a la fecha final.")
    if values["periodo"] not in ("", "mes_actual") or values["nivel_alerta"] not in ("", *LEVELS):
        raise ValueError("El periodo o nivel de alerta no es válido.")
    return {key: value for key, value in values.items() if value}


def _filter_sql(filters):
    conditions, params = [], []
    for key in ("usuario_id", "dataset_nombre", "sesion_id", "tipo_accion", "nivel_alerta"):
        if key == "nivel_alerta" and filters.get(key) == "NORMAL":
            conditions.append("(e.nivel_alerta = 'NORMAL' OR e.nivel_alerta IS NULL)")
        elif filters.get(key):
            conditions.append(f"e.{key} = ?")
            params.append(filters[key])
    term = filters.get("q", "")
    if term.startswith("#") and term[1:].isascii() and term[1:].isdigit():
        conditions.append("CAST(e.event_id AS TEXT) = ?")
        params.append(term[1:].lstrip("0") or "0")
    elif term:
        conditions.append(
            "(" + " OR ".join(f"instr(lower(coalesce({column}, '')), lower(?)) > 0" for column in (
                "e.usuario_id", "u.email", "e.dataset_nombre", "e.sesion_id",
                "e.hash_integridad", "e.evento_uuid",
            )) + " OR CAST(e.event_id AS TEXT) = ?)"
        )
        params.extend([term] * 7)
    start, end = filters.get("fecha_inicio"), filters.get("fecha_fin")
    if filters.get("periodo") == "mes_actual":
        today = datetime.now(timezone.utc).date()
        month_start = today.replace(day=1)
        month_end = (month_start + timedelta(days=32)).replace(day=1) - timedelta(days=1)
        start = max(start or month_start.isoformat(), month_start.isoformat())
        end = min(end or month_end.isoformat(), month_end.isoformat())
    if start:
        conditions.append("e.timestamp >= ?")
        params.append(start)
    if end and end != date.max.isoformat():
        conditions.append("e.timestamp < ?")
        params.append((date.fromisoformat(end) + timedelta(days=1)).isoformat())
    return (" AND ".join(conditions) if conditions else "1 = 1"), params


def _select_events(conn, filters, limit, offset=0):
    where, params = _filter_sql(filters)
    return conn.execute(
        f"""SELECT {EVENT_FIELDS} FROM {EVENT_SOURCE} WHERE {where}
            ORDER BY e.timestamp DESC, e.event_id DESC LIMIT ? OFFSET ?""",
        (*params, limit, offset),
    ).fetchall()


def create_audit_blueprint(get_db, login_required, modulo_required):
    audit = Blueprint("audit", __name__, url_prefix="/auditoria")
    require_reports = modulo_required("consulta_reportes")

    @modulo_required("visualizacion_alertas")
    def protect_alerts():
        return None

    @audit.before_request
    @login_required
    @require_reports
    def protect_workspace():
        if request.endpoint.rsplit(".", 1)[-1] in ALERT_ENDPOINTS:
            denied = protect_alerts()
            if denied is not None:
                return denied
        if request.method == "POST":
            expected = session.get("audit_csrf")
            supplied = request.form.get("csrf_token", "")
            if not expected or not secrets.compare_digest(expected.encode(), supplied.encode()):
                abort(400, "Formulario caducado. Vuelve a cargar la página.")

    @audit.context_processor
    def workspace_context():
        if "audit_csrf" not in session:
            session["audit_csrf"] = secrets.token_hex(32)
        return {"csrf_token": session["audit_csrf"]}

    @audit.get("")
    def explore():
        try:
            filters = _filters(request.args)
        except ValueError as exc:
            flash(str(exc), "warning")
            return redirect(url_for("audit.explore"))
        page = max(1, min(request.args.get("page", 1, type=int), 100000))
        with workspace_db(get_db) as conn:
            events = _select_events(conn, filters, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE)
            actions = [row[0] for row in conn.execute(
                "SELECT DISTINCT tipo_accion FROM audit_log ORDER BY tipo_accion"
            )]
            saved = [
                dict(row, filtros=json.loads(row["filtros"]))
                for row in conn.execute(
                    "SELECT id, nombre, filtros FROM audit_saved_filters WHERE usuario_id = ? ORDER BY nombre COLLATE NOCASE",
                    (session["usuario_id"],),
                )
            ]
        return render_template(
            "dashboard/audit_explore.html", filters=filters, actions=actions,
            levels=LEVELS, events=events[:PAGE_SIZE], page=page, has_next=len(events) > PAGE_SIZE, saved=saved,
        )

    @audit.post("/filtros")
    def save_filter():
        try:
            filters = _filters(request.form)
            name = request.form.get("nombre", "").strip()
            if not name or len(name) > 80 or not filters:
                raise ValueError("Escribe un nombre de hasta 80 caracteres y aplica al menos un filtro.")
        except ValueError as exc:
            flash(str(exc), "warning")
            return redirect(url_for("audit.explore"))
        with workspace_db(get_db) as conn, conn:
            conn.execute(
                """INSERT INTO audit_saved_filters (usuario_id, nombre, filtros) VALUES (?, ?, ?)
                   ON CONFLICT(usuario_id, nombre COLLATE NOCASE) DO UPDATE SET filtros = excluded.filtros""",
                (session["usuario_id"], name, json.dumps(filters, ensure_ascii=False)),
            )
        flash("Búsqueda guardada.", "success")
        return redirect(url_for("audit.explore", **filters))

    @audit.post("/filtros/<int:filter_id>/eliminar")
    def delete_filter(filter_id):
        if not 0 < filter_id <= SQLITE_MAX_INT:
            abort(404)
        with workspace_db(get_db) as conn, conn:
            result = conn.execute(
                "DELETE FROM audit_saved_filters WHERE id = ? AND usuario_id = ?",
                (filter_id, session["usuario_id"]),
            )
            if not result.rowcount:
                abort(404)
        flash("Búsqueda eliminada.", "success")
        return redirect(url_for("audit.explore"))

    @audit.get("/relaciones/<int:event_id>")
    def relations(event_id):
        if not 0 < event_id <= SQLITE_MAX_INT:
            abort(404)
        with workspace_db(get_db) as conn:
            event = conn.execute(
                f"SELECT {EVENT_FIELDS} FROM {EVENT_SOURCE} WHERE e.event_id = ?", (event_id,)
            ).fetchone()
            if not event:
                abort(404)
            relations = []
            placeholders = {
                "usuario_id": {"DESCONOCIDO", "SISTEMA"},
                "sesion_id": {"N/A", "SIN_SESION", "SINCRONIZACION"},
                "dataset_nombre": set(),
            }
            for label, key in (("Usuario", "usuario_id"), ("Dataset", "dataset_nombre"), ("Sesión", "sesion_id")):
                value = event[key]
                if value and value not in placeholders[key]:
                    candidates = _select_events(conn, {key: value}, 7)
                    relations.append({
                        "label": label, "value": value, "filter": key,
                        "events": [row for row in candidates if row["event_id"] != event_id][:6],
                    })
        return render_template("dashboard/audit_relations.html", event=event, relations=relations)

    @audit.get("/actividad")
    def activity():
        with workspace_db(get_db) as conn:
            events = conn.execute(
                "SELECT event_id, timestamp, tipo_accion, nivel_alerta FROM audit_log ORDER BY event_id DESC LIMIT 12"
            ).fetchall()
        return jsonify(events=[
            dict(row, url=url_for("detalle_evento", event_id=row["event_id"])) for row in events
        ])

    _register_alert_routes(audit, get_db)
    _register_notification_routes(audit, get_db)
    return audit


def _register_alert_routes(audit, get_db):
    @audit.get("/alertas")
    def alerts():
        state = request.args.get("estado", "")
        level = request.args.get("nivel", "")
        page = max(1, min(request.args.get("page", 1, type=int), 100000))
        where = ["e.nivel_alerta IN ('ADVERTENCIA', 'ANOMALIA', 'CRITICO')"]
        params = []
        if state in STATES:
            where.append("coalesce(r.estado, 'PENDIENTE') = ?")
            params.append(state)
        count_where = " AND ".join(where)
        count_params = tuple(params)
        if level in ALERT_LEVELS:
            where.append("e.nivel_alerta = ?")
            params.append(level)
        with workspace_db(get_db) as conn:
            counts = dict(conn.execute(
                f"""SELECT e.nivel_alerta, COUNT(*) FROM audit_log e
                    LEFT JOIN audit_alert_reviews r ON r.event_id = e.event_id
                    WHERE {count_where} GROUP BY e.nivel_alerta""",
                count_params,
            ).fetchall())
            rows = conn.execute(
                f"""SELECT {EVENT_FIELDS}, coalesce(r.estado, 'PENDIENTE') AS estado, a.email AS responsable
                    FROM {EVENT_SOURCE}
                    LEFT JOIN audit_alert_reviews r ON r.event_id = e.event_id
                    LEFT JOIN usuarios a ON a.usuario_id = r.responsable_id
                    WHERE {' AND '.join(where)}
                    ORDER BY e.timestamp DESC, e.event_id DESC LIMIT ? OFFSET ?""",
                (*params, PAGE_SIZE + 1, (page - 1) * PAGE_SIZE),
            ).fetchall()
        return render_template(
            "dashboard/audit_alerts.html", alerts=rows[:PAGE_SIZE], counts=counts, states=STATES,
            levels=ALERT_LEVELS, state=state, level=level, page=page, has_next=len(rows) > PAGE_SIZE,
        )

    @audit.route("/alertas/<int:event_id>", methods=["GET", "POST"])
    def alert_review(event_id):
        if not 0 < event_id <= SQLITE_MAX_INT:
            abort(404)
        history_page = max(1, min(request.args.get("historial", 1, type=int), 100000))
        with workspace_db(get_db) as conn:
            event = conn.execute(
                f"""SELECT {EVENT_FIELDS}, e.motivo_alerta,
                           coalesce(r.estado, 'PENDIENTE') AS estado, r.responsable_id,
                           coalesce(r.version, 0) AS version
                    FROM {EVENT_SOURCE}
                    LEFT JOIN audit_alert_reviews r ON r.event_id = e.event_id
                    WHERE e.event_id = ? AND e.nivel_alerta IN ('ADVERTENCIA', 'ANOMALIA', 'CRITICO')""",
                (event_id,),
            ).fetchone()
            if not event:
                abort(404)
            assignees = [
                row for row in conn.execute(
                    "SELECT usuario_id, email, rol FROM usuarios WHERE activo = 1 ORDER BY email"
                ) if can_review_alerts(row["rol"])
            ]
            if request.method == "POST":
                state = request.form.get("estado")
                assignee = request.form.get("responsable_id") or None
                comment = request.form.get("comentario", "").strip()
                version = request.form.get("version", type=int)
                if state not in STATES or len(comment) > 2000 or version is None or not 0 <= version < SQLITE_MAX_INT:
                    abort(400, "Estado, versión o comentario no válido.")
                eligible = {row["usuario_id"] for row in assignees}
                if assignee and assignee not in eligible and assignee != event["responsable_id"]:
                    abort(400, "Selecciona un responsable activo con acceso al módulo.")
                with conn:
                    conn.execute("INSERT OR IGNORE INTO audit_alert_reviews (event_id) VALUES (?)", (event_id,))
                    updated = conn.execute(
                        """UPDATE audit_alert_reviews SET estado = ?, responsable_id = ?, version = version + 1
                           WHERE event_id = ? AND version = ?""",
                        (state, assignee, event_id, version),
                    )
                    if not updated.rowcount:
                        abort(409, "La alerta cambió durante la revisión. Recarga la página antes de guardar.")
                    conn.execute(
                        """INSERT INTO audit_alert_history
                           (event_id, autor_id, estado, responsable_id, comentario) VALUES (?, ?, ?, ?, ?)""",
                        (event_id, session["usuario_id"], state, assignee, comment),
                    )
                flash("Revisión guardada.", "success")
                return redirect(url_for("audit.alert_review", event_id=event_id))
            history = conn.execute(
                """SELECT h.fecha, h.estado, h.comentario, u.email AS autor, a.email AS responsable
                   FROM audit_alert_history h LEFT JOIN usuarios u ON u.usuario_id = h.autor_id
                   LEFT JOIN usuarios a ON a.usuario_id = h.responsable_id
                   WHERE h.event_id = ? ORDER BY h.id DESC LIMIT ? OFFSET ?""",
                (event_id, PAGE_SIZE + 1, (history_page - 1) * PAGE_SIZE),
            ).fetchall()
        return render_template(
            "dashboard/audit_alert_review.html", event=event, assignees=assignees,
            states=STATES, history=history[:PAGE_SIZE], history_page=history_page, history_more=len(history) > PAGE_SIZE,
        )


def _register_notification_routes(audit, get_db):
    @audit.get("/notificaciones/estado")
    def notification_status():
        with workspace_db(get_db) as conn:
            return jsonify(unread=_unread_count(conn, session["usuario_id"]))

    @audit.route("/notificaciones", methods=["GET", "POST"])
    def notifications():
        from .audit_mail import smtp_configured

        user_id = session["usuario_id"]
        configured = smtp_configured()
        with workspace_db(get_db) as conn:
            if request.method == "POST":
                action = request.form.get("accion")
                with conn:
                    conn.execute(
                        "INSERT OR IGNORE INTO audit_notification_settings (usuario_id) VALUES (?)", (user_id,)
                    )
                    if action == "preferencias":
                        email = int(request.form.get("por_correo") == "1")
                        if email and not configured:
                            abort(400, "Configura primero el servicio de correo SMTP.")
                        if not configured:
                            email = conn.execute(
                                "SELECT por_correo FROM audit_notification_settings WHERE usuario_id = ?", (user_id,)
                            ).fetchone()[0]
                        conn.execute(
                            """UPDATE audit_notification_settings SET en_panel = ?,
                               correo_hasta = CASE WHEN por_correo = 0 AND ? = 1
                                   THEN (SELECT coalesce(MAX(event_id), 0) FROM audit_log) ELSE correo_hasta END,
                               correo_reserva = CASE WHEN ? <> por_correo THEN NULL ELSE correo_reserva END,
                               correo_reserva_hasta = CASE WHEN ? <> por_correo THEN 0 ELSE correo_reserva_hasta END,
                               por_correo = ? WHERE usuario_id = ?""",
                            (int(request.form.get("en_panel") == "1"), email, email, email, email, user_id),
                        )
                    elif action == "leidas":
                        through = request.form.get("hasta", 0, type=int)
                        if not 0 <= through <= SQLITE_MAX_INT:
                            abort(400, "Identificador de notificación no válido.")
                        conn.execute(
                            """UPDATE audit_notification_settings
                               SET leido_hasta = max(leido_hasta, (
                                   SELECT coalesce(MAX(event_id), 0) FROM audit_log WHERE event_id <= ?
                               )) WHERE usuario_id = ?""",
                            (through, user_id),
                        )
                    else:
                        abort(400)
                flash("Notificaciones actualizadas.", "success")
                return redirect(url_for("audit.notifications"))
            prefs = conn.execute(
                "SELECT en_panel, por_correo, leido_hasta FROM audit_notification_settings WHERE usuario_id = ?",
                (user_id,),
            ).fetchone() or {"en_panel": 1, "por_correo": 0, "leido_hasta": 0}
            rows = conn.execute(
                """SELECT event_id, timestamp, tipo_accion, nivel_alerta FROM audit_log
                   WHERE nivel_alerta = 'CRITICO' ORDER BY event_id DESC LIMIT 30"""
            ).fetchall() if prefs["en_panel"] else []
            unread = _unread_count(conn, user_id)
        return render_template(
            "dashboard/audit_notifications.html", preferences=prefs, notifications=rows,
            unread=unread, smtp_configured=configured,
        )


def _unread_count(conn, user_id):
    return conn.execute(
        """SELECT COUNT(*) FROM audit_log e
           LEFT JOIN audit_notification_settings s ON s.usuario_id = ?
           WHERE e.nivel_alerta = 'CRITICO' AND coalesce(s.en_panel, 1) = 1
             AND e.event_id > coalesce(s.leido_hasta, 0)""",
        (user_id,),
    ).fetchone()[0]
