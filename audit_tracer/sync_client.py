"""
audit_tracer/sync_client.py
=============================
HU-5.8 — Sincronización de eventos hacia el servidor central.

Cliente HTTP que envía los eventos encolados en audit_sync_queue (base
LOCAL) al endpoint receptor central (POST /api/eventos/sincronizar),
con autenticación por token personal (HU-5.5) y reintentos acotados con
backoff exponencial.

CA1 — La persistencia local siempre ocurre antes de llamar a este módulo
(ver models/audit_log.py::insert_event_and_enqueue_sync()); este cliente
nunca inserta nada, solo lee/actualiza el estado de filas ya persistidas.

CA2 — Reintentos acotados (MAX_INTENTOS_POR_EVENTO), con backoff
exponencial, solo para fallos transitorios (red/timeout/5xx). Nunca un
bucle infinito en memoria: el estado vive en SQLite (audit_sync_queue),
así que un evento sobrevive al cierre del proceso/notebook y puede
retomarse en cualquier sincronización posterior.

CA4 — Un rechazo de autenticación (401/403) no se reintenta en este
módulo: el token es inválido y reintentar con el mismo token no cambia
el resultado. El token nunca se imprime ni se guarda en ultimo_error.
"""

import sqlite3
import threading
import time
from datetime import datetime
from typing import Dict, Optional
from urllib.parse import urlparse

from .utils.lazy import lazy_import

requests = lazy_import("requests")   # HU-5.1 CA3: solo se carga al enviar (hilo de fondo)

from .db import get_connection
from .models.audit_log import (
    get_pending_sync_events,
    get_sync_queue_summary,
    mark_event_synced,
    mark_event_sync_failed,
)
from .utils.error_log import log_internal_error

# ──────────────────────────────────────────────────────────────
# CONFIGURACIÓN
# ──────────────────────────────────────────────────────────────

REQUEST_TIMEOUT_SECONDS = 5
MAX_INTENTOS_POR_EVENTO = 3          # CA2: acotado, nada de reintentos infinitos en memoria
BACKOFF_BASE_SEGUNDOS = 0.5          # backoff exponencial: 0.5s, 1s, 2s, ...
SYNC_INTERVAL_SECONDS = 30           # cadencia del hilo de reintento periódico

# Campos de audit_log que viajan en el payload de sincronización (mismos
# nombres que audit_tracer/schema/audit_log.sql y audit_tracer/schema/audit_log_central.sql).
_CAMPOS_PAYLOAD = [
    "evento_uuid", "usuario_id", "sesion_id", "timestamp", "tipo_accion",
    "dataset_nombre", "columnas_afectadas", "ruta_destino", "filas_exportadas",
    "sobrescritura", "contexto_ejecucion", "motivo_fallo", "nivel_alerta",
    "motivo_alerta",
    "firma_digital",   # HU-6.1 CA2 — la firma viaja junto al evento
]

_config: Dict[str, Optional[str]] = {"api_url": None, "token": None}
_sync_thread: Optional[threading.Thread] = None
_stop_event: Optional[threading.Event] = None
_wake_event: Optional[threading.Event] = None
_pending_key_registration = threading.Event()
_estado = {"servidor_caido": False}

# Presupuesto total de la sincronización final al cerrar el proceso: con el
# servidor caído, cerrar el script no debe tardar más que esto (HU-5.1 CA4).
EXIT_FLUSH_BUDGET_SECONDS = 2.0


def _validar_https(api_url: str) -> None:
    """Debe usar HTTPS — se permite http:// solo contra localhost/127.0.0.1 (pruebas/dev)."""
    parsed = urlparse(api_url)
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1"):
        raise ValueError(
            "La URL del servidor central debe usar HTTPS "
            "(excepto localhost/127.0.0.1, permitido solo para pruebas)."
        )


def configure_sync(api_url: str, token: str, auto: bool = True) -> None:
    """
    Registra el servidor central y el token personal (HU-5.5) que este
    cliente usará para autenticarse. Es lo primero que debe llamar un
    notebook/script que quiera sincronizar.

    Args:
        api_url: Base URL del servidor central (ej. 'https://audit.miorg.com').
        token:   Token personal de acceso (ver /admin/tokens o generar_token()).
        auto:    Si True (por defecto), arranca un hilo daemon que reintenta
                 la cola automáticamente cada SYNC_INTERVAL_SECONDS — así un
                 evento capturado sin conexión se sincroniza solo en cuanto
                 el servidor vuelve a estar disponible, sin acción manual.
    """
    _validar_https(api_url)
    api_url = api_url.rstrip("/")
    _config["api_url"] = api_url
    _config["token"] = token

    if auto:
        # HU-5.1 CA4: el registro de la llave (HU-6.1 CA1) y todo envío HTTP
        # ocurren en el hilo de fondo — configurar nunca bloquea al usuario.
        _pending_key_registration.set()
        _start_background_sync()
        schedule_sync()
    else:
        _registrar_llave_publica()


def _registrar_llave_publica() -> bool:
    """HU-6.1 CA1: registra la llave pública Ed25519 en el servidor central."""
    try:
        from audit_tracer.digital_signatures import get_or_create_user_keypair, public_key_to_pem
        _, public_key = get_or_create_user_keypair()
        pem = public_key_to_pem(public_key)
        resp = requests.post(
            f"{_config['api_url']}/api/usuarios/llave-publica",
            json={"llave_publica": pem},
            headers={"Authorization": f"Bearer {_config['token']}"},
            timeout=REQUEST_TIMEOUT_SECONDS,
        )
        return getattr(resp, "status_code", 0) == 200
    except Exception as e:
        if isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)):
            _estado["servidor_caido"] = True
        log_internal_error("No se pudo registrar la llave pública en el servidor", e)
        return False


def unconfigure_sync() -> None:
    """Olvida servidor y token (p. ej. si el servidor rechazó el token cacheado)."""
    _config["api_url"] = None
    _config["token"] = None


def schedule_sync() -> None:
    """
    HU-5.1 CA4 — Pide al hilo de fondo un barrido de la cola. No hace red
    ni espera nada en el hilo que lo llama: es lo único que invocan los
    interceptores después de persistir un evento, así que una operación de
    pandas nunca queda esperando al servidor central.
    """
    if _wake_event is not None and is_configured():
        _wake_event.set()


def is_configured() -> bool:
    return bool(_config["api_url"] and _config["token"])


def _endpoint_url() -> str:
    return f"{_config['api_url']}/api/eventos/sincronizar"


def _payload_from_row(row: Dict) -> Dict:
    return {campo: row.get(campo) for campo in _CAMPOS_PAYLOAD}


# ──────────────────────────────────────────────────────────────
# ENVÍO CON REINTENTOS ACOTADOS Y BACKOFF (CA2, CA4)
# ──────────────────────────────────────────────────────────────

def _intentar_envio(
    payload: Dict,
    max_intentos: int = MAX_INTENTOS_POR_EVENTO,
    timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> Dict:
    """
    Intenta enviar un evento al endpoint central.

    Returns:
        Dict: {'ok': bool, 'motivo': str, 'mensaje': str, 'event_id_central': int|None}
        motivo en {'creado', 'duplicado', 'SIN_CONEXION', 'AUTENTICACION',
                   'ERROR_SERVIDOR', 'SIN_CONFIGURAR'}.
    """
    if not is_configured():
        return {"ok": False, "motivo": "SIN_CONFIGURAR", "mensaje": "Sincronización no configurada (llama a configure_sync())."}

    token = _config["token"]
    url = _endpoint_url()
    ultimo_error = "Sin conexión con el servidor central"

    for intento in range(1, max_intentos + 1):
        try:
            resp = requests.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
                timeout=timeout,
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as exc:
            ultimo_error = f"{type(exc).__name__}: sin conexión con el servidor central"
            if intento < max_intentos:
                time.sleep(BACKOFF_BASE_SEGUNDOS * (2 ** (intento - 1)))
                continue
            return {"ok": False, "motivo": "SIN_CONEXION", "mensaje": ultimo_error, "event_id_central": None}

        if resp.status_code in (200, 201):
            try:
                data = resp.json()
            except ValueError:
                data = {}
            return {
                "ok": True,
                "motivo": data.get("status", "creado"),
                "mensaje": "Evento confirmado por el servidor central",
                "event_id_central": data.get("event_id"),
            }

        if resp.status_code in (401, 403):
            # CA4: token inválido/expirado/revocado — no tiene sentido reintentar
            # con el mismo token, así que no se reintenta (evita retry infinito).
            return {
                "ok": False,
                "motivo": "AUTENTICACION",
                "mensaje": "Token rechazado por el servidor central (401/403)",
                "event_id_central": None,
            }

        if resp.status_code >= 500 and intento < max_intentos:
            ultimo_error = f"HTTP {resp.status_code} del servidor central"
            time.sleep(BACKOFF_BASE_SEGUNDOS * (2 ** (intento - 1)))
            continue

        return {
            "ok": False,
            "motivo": "ERROR_SERVIDOR",
            "mensaje": f"HTTP {resp.status_code} del servidor central",
            "event_id_central": None,
        }

    return {"ok": False, "motivo": "SIN_CONEXION", "mensaje": ultimo_error, "event_id_central": None}


def _aplicar_resultado(conn, event_id: int, resultado: Dict) -> None:
    ahora = datetime.utcnow().isoformat()
    if resultado["ok"]:
        mark_event_synced(conn, event_id, ahora)
    else:
        mark_event_sync_failed(conn, event_id, resultado.get("mensaje", resultado["motivo"]), ahora)


# ──────────────────────────────────────────────────────────────
# API PRINCIPAL (CA1, CA2, CA3)
# ──────────────────────────────────────────────────────────────

def try_sync_event(conn, event_id: int) -> Dict:
    """
    CA1 — Intento best-effort de sincronizar UN evento recién capturado.
    Se llama justo después de insert_event_and_enqueue_sync(), nunca antes.
    Nunca lanza: cualquier fallo deja el evento en la cola para el próximo
    barrido (try_sync_event posterior, sync_now() o el hilo automático).
    """
    conn.row_factory = sqlite3.Row
    fila = conn.execute(
        """
        SELECT a.*, q.estado FROM audit_sync_queue q
        JOIN audit_log a ON a.event_id = q.event_id
        WHERE q.event_id = ?
        """,
        (event_id,),
    ).fetchone()

    if fila is None:
        return {"ok": False, "motivo": "NO_ENCOLADO", "mensaje": "Evento sin fila en audit_sync_queue"}

    fila_dict = dict(fila)

    if fila_dict.get("estado") == "SINCRONIZADO":
        return {"ok": True, "motivo": "YA_SINCRONIZADO", "mensaje": "El evento ya estaba sincronizado"}

    resultado = _intentar_envio(_payload_from_row(fila_dict))
    _aplicar_resultado(conn, event_id, resultado)
    return resultado


def sync_pending_events(conn=None, deadline: Optional[float] = None) -> Dict:
    """
    CA2/CA3 — Barrido de reintento sobre TODOS los eventos PENDIENTE/FALLIDO
    de la base local. Es lo que usa sync_now() y el hilo automático.

    Si un evento falla por falta de conexión, se detiene el barrido (no
    tiene sentido martillar el resto de la cola contra un servidor caído);
    los eventos restantes quedan igual en la cola para el próximo barrido.

    HU-5.1: con `deadline` (time.monotonic()), cada evento se intenta una
    sola vez con un timeout acotado al tiempo restante, y el barrido se
    corta al vencer — lo usa la sincronización final al cerrar el proceso.
    """
    conn_propia = conn is None
    conn_local = conn or get_connection()
    try:
        pendientes = get_pending_sync_events(conn_local)
        resumen = {"total": len(pendientes), "sincronizados": 0, "fallidos": 0}

        for fila in pendientes:
            if deadline is None:
                resultado = _intentar_envio(_payload_from_row(fila))
            else:
                restante = deadline - time.monotonic()
                if restante <= 0:
                    break
                resultado = _intentar_envio(
                    _payload_from_row(fila), max_intentos=1,
                    timeout=min(REQUEST_TIMEOUT_SECONDS, restante),
                )
            _aplicar_resultado(conn_local, fila["event_id"], resultado)

            if resultado["ok"]:
                resumen["sincronizados"] += 1
                _estado["servidor_caido"] = False
            else:
                resumen["fallidos"] += 1
                if resultado["motivo"] == "SIN_CONEXION":
                    _estado["servidor_caido"] = True
                if resultado["motivo"] in ("SIN_CONEXION", "SIN_CONFIGURAR"):
                    break

        return resumen
    finally:
        if conn_propia:
            conn_local.close()


# ──────────────────────────────────────────────────────────────
# HILO DE REINTENTO AUTOMÁTICO (CA2 — "reintentarse automáticamente")
# ──────────────────────────────────────────────────────────────

def _background_loop(stop_event: threading.Event, wake_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            llave_lista = True
            if _pending_key_registration.is_set() and is_configured():
                llave_lista = _registrar_llave_publica()
                if llave_lista:
                    _pending_key_registration.clear()
            # Sin la llave registrada, el servidor rechaza los eventos firmados:
            # se espera al próximo ciclo en vez de gastar los reintentos.
            if llave_lista and is_configured():
                sync_pending_events()
        except Exception as exc:
            log_internal_error("Barrido de sincronización en segundo plano", exc)
        # Despierta por un evento nuevo (schedule_sync) o, si no, cada
        # SYNC_INTERVAL_SECONDS para reintentar lo que haya quedado pendiente.
        wake_event.wait(SYNC_INTERVAL_SECONDS)
        wake_event.clear()


def _start_background_sync() -> None:
    global _sync_thread, _stop_event, _wake_event
    if _sync_thread is not None and _sync_thread.is_alive():
        return
    _stop_event = threading.Event()
    _wake_event = threading.Event()
    _sync_thread = threading.Thread(
        target=_background_loop, args=(_stop_event, _wake_event),
        name="audit_tracer-sync", daemon=True,
    )
    _sync_thread.start()


def stop_background_sync() -> None:
    """Detiene el hilo de reintento periódico. Uso principal: limpieza en tests."""
    if _stop_event is not None:
        _stop_event.set()
    if _wake_event is not None:
        _wake_event.set()


def flush_pending(budget_seconds: float = EXIT_FLUSH_BUDGET_SECONDS) -> None:
    """
    Último intento de sincronizar la cola al cerrar el proceso, acotado a
    `budget_seconds` en total. Lo que no alcance queda en la base local y
    se envía en la próxima sesión. Nunca lanza. Si el último barrido ya
    encontró el servidor caído, no se reintenta: cerrar no debe esperar.
    """
    # Si el hilo de fondo ni siquiera logró registrar la llave, el servidor
    # no ha respondido en toda la sesión: esperar al cierre no aporta nada.
    if not is_configured() or _estado["servidor_caido"] or _pending_key_registration.is_set():
        return
    try:
        sync_pending_events(deadline=time.monotonic() + budget_seconds)
    except Exception as exc:
        log_internal_error("Sincronización final al cerrar el proceso", exc)


# ──────────────────────────────────────────────────────────────
# API PÚBLICA DE NOTEBOOK (Sub-tarea 5 — indicador visible)
# ──────────────────────────────────────────────────────────────

def sync_now() -> Dict:
    """Fuerza un barrido inmediato de la cola de sincronización local."""
    return sync_pending_events()


def sync_status() -> Dict:
    """
    Sub-tarea 5 — Indicador de estado de sincronización visible en el
    notebook: imprime un resumen legible y devuelve los datos crudos por
    si el usuario quiere inspeccionarlos.
    """
    conn = get_connection()
    try:
        resumen = get_sync_queue_summary(conn)
    finally:
        conn.close()

    linea = (
        f"Sincronización: {resumen['sincronizados']} sincronizados · "
        f"{resumen['pendientes']} pendientes · {resumen['fallidos']} con error"
    )
    if resumen["ultimo_intento"]:
        linea += f" · último intento: {resumen['ultimo_intento']}"
    if resumen["ultimo_error"]:
        linea += f" · último error: {resumen['ultimo_error']}"
    print(f"[AuditTracer] {linea}")

    return resumen
