"""
audit_tracer/failed_access.py
==============================
HU-2.4 — Registrar intentos fallidos de acceso a datos clínicos

Intercepta excepciones de acceso a datasets clínicos y las registra
en audit_log como eventos ACCESO_FALLIDO, incluyendo motivo_fallo,
usuario_id, sesion_id, dataset_nombre y nivel_alerta.

Además, detecta si un mismo usuario acumula más de 3 intentos fallidos
en una ventana de 5 minutos y escala el nivel_alerta a CRITICO (CA3).

Subtareas cubiertas:
  PDGTRAZDSA-63 — Interceptar excepciones de acceso
  PDGTRAZDSA-64 — Capturar motivo del fallo
  PDGTRAZDSA-65 — Registro en audit_log
  PDGTRAZDSA-66 — Detección de intentos repetidos

Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
"""

import os
import inspect
import functools
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional, Callable

from .db import get_connection
from .models.audit_log import insert_event_and_enqueue_sync
from .utils.session import detect_environment, get_hostname


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-63 — Tipos de fallos de acceso reconocidos (CA1 DOR)
# ──────────────────────────────────────────────────────────────

#: Excepciones Python que se consideran intento fallido de acceso
ACCESS_FAILURE_EXCEPTIONS = (
    FileNotFoundError,   # archivo / dataset no existe
    PermissionError,     # sin permisos para leer
    IsADirectoryError,   # ruta apunta a directorio, no a archivo
    OSError,             # error de I/O genérico del sistema operativo
)

#: Mapeo de tipo de excepción a motivo_fallo canónico (CA2)
_MOTIVO_MAP: dict[type, str] = {
    FileNotFoundError: "archivo no existe",
    PermissionError:   "permiso denegado",
    IsADirectoryError: "ruta es un directorio",
    OSError:           "error de sistema de archivos",
}

#: Ventana temporal para detección de intentos repetidos (CA3)
_ALERT_WINDOW_MINUTES: int = 5

#: Umbral de intentos fallidos antes de generar alerta CRITICO (CA3)
_ALERT_THRESHOLD: int = 3


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-66 — Registro en memoria de intentos fallidos por usuario
# ──────────────────────────────────────────────────────────────

# Estructura: { usuario_id: [datetime, datetime, ...] }
_failed_attempts: dict[str, list[datetime]] = defaultdict(list)


def _purge_old_attempts(usuario_id: str, now: datetime) -> None:
    """
    Elimina del registro los intentos fuera de la ventana de tiempo.

    Args:
        usuario_id: Identificador del usuario.
        now:        Momento actual de referencia.
    """
    cutoff = now - timedelta(minutes=_ALERT_WINDOW_MINUTES)
    _failed_attempts[usuario_id] = [
        ts for ts in _failed_attempts[usuario_id] if ts >= cutoff
    ]


def _register_attempt(usuario_id: str) -> tuple[str, Optional[str]]:
    """
    Registra un nuevo intento fallido para usuario_id y determina
    el nivel de alerta resultante (CA3).

    Args:
        usuario_id: Identificador del usuario (puede ser 'DESCONOCIDO').

    Returns:
        tuple[str, str | None]: (nivel_alerta, motivo_alerta)
    """
    now = datetime.utcnow()
    _purge_old_attempts(usuario_id, now)
    _failed_attempts[usuario_id].append(now)

    count = len(_failed_attempts[usuario_id])

    if count > _ALERT_THRESHOLD:
        motivo = (
            f"{count} intentos fallidos en menos de "
            f"{_ALERT_WINDOW_MINUTES} minutos"
        )
        return "CRITICO", motivo

    return "NORMAL", None


def reset_attempts(usuario_id: Optional[str] = None) -> None:
    """
    Reinicia el contador de intentos fallidos.
    Útil principalmente para tests y para reiniciar tras autenticación.

    Args:
        usuario_id: Si se proporciona, reinicia solo ese usuario.
                    Si es None, reinicia todos los contadores.
    """
    if usuario_id is not None:
        _failed_attempts[usuario_id] = []
    else:
        _failed_attempts.clear()


# ──────────────────────────────────────────────────────────────
# HELPERS INTERNOS
# ──────────────────────────────────────────────────────────────

def _get_session() -> tuple[str, str]:
    """
    Obtiene (usuario_id, sesion_id) desde SessionTracker.
    Devuelve ('DESCONOCIDO', 'SIN_SESION') si no es posible (CA2).
    """
    try:
        from .session_tracker import SessionTracker
        tracker = SessionTracker.get_instance()
        usuario_id = tracker.usuario_id or "DESCONOCIDO"
        sesion_id = tracker.sesion_id
        return usuario_id, sesion_id
    except Exception:
        return "DESCONOCIDO", "SIN_SESION"


def _build_contexto() -> str:
    """Construye contexto_ejecucion con entorno y script de origen."""
    env = detect_environment()
    host = get_hostname()

    caller_file = "desconocido"
    stack = inspect.stack()
    for frame_info in stack:
        filename = frame_info.filename
        if (
            filename != __file__
            and "audit_tracer" not in filename
            and "pandas" not in filename
            and "<frozen" not in filename
        ):
            caller_file = os.path.basename(filename)
            break

    return f"Script: {caller_file} | Env: {env} | Host: {host}"


def _resolve_motivo(exc: Exception) -> str:
    """
    Determina el motivo_fallo canónico a partir de la excepción (CA2 PDGTRAZDSA-64).

    Args:
        exc: Excepción capturada.

    Returns:
        str: Descripción del motivo de fallo.
    """
    for exc_type, motivo in _MOTIVO_MAP.items():
        if isinstance(exc, exc_type):
            return motivo
    return f"error inesperado: {type(exc).__name__}"


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-65 — Registro en audit_log
# ──────────────────────────────────────────────────────────────

def log_failed_access(
    dataset_nombre: str,
    exc: Exception,
    usuario_id: Optional[str] = None,
    sesion_id: Optional[str] = None,
) -> int | None:
    """
    Registra un intento fallido de acceso a un dataset clínico (CA1, CA2).

    Determina automáticamente el nivel de alerta según la frecuencia de
    intentos del mismo usuario en los últimos 5 minutos (CA3).

    Args:
        dataset_nombre: Nombre del dataset al que se intentó acceder.
        exc:            Excepción que causó el fallo.
        usuario_id:     ID del usuario (si None, se obtiene del SessionTracker).
        sesion_id:      ID de sesión (si None, se obtiene del SessionTracker).

    Returns:
        int | None: event_id del registro insertado, o None si falló la inserción.
    """
    # Obtener identidad si no fue provista
    if usuario_id is None or sesion_id is None:
        uid, sid = _get_session()
        usuario_id = usuario_id or uid
        sesion_id = sesion_id or sid

    # Determinar motivo del fallo (PDGTRAZDSA-64)
    motivo_fallo = _resolve_motivo(exc)

    # Registrar intento y determinar nivel de alerta (PDGTRAZDSA-66)
    nivel_alerta, motivo_alerta = _register_attempt(usuario_id)

    event = {
        "usuario_id":        usuario_id,           # CA2
        "sesion_id":         sesion_id,             # CA2 / DoD
        "timestamp":         datetime.utcnow().isoformat(),   # CA2
        "tipo_accion":       "ACCESO_FALLIDO",      # CA1
        "dataset_nombre":    dataset_nombre,        # CA2
        "motivo_fallo":      motivo_fallo,          # CA2 / PDGTRAZDSA-64
        "nivel_alerta":      nivel_alerta,          # CA3
        "motivo_alerta":     motivo_alerta,         # CA3
        "contexto_ejecucion": _build_contexto(),
    }

    try:
        conn = get_connection()
        # CA4: persistencia inmediata / PDGTRAZDSA-65.
        # HU-5.8 CA1: se encola para sincronización en la misma operación.
        resultado = insert_event_and_enqueue_sync(conn, event)
        try:
            from .sync_client import try_sync_event
            try_sync_event(conn, resultado["event_id"])  # best-effort, nunca lanza
        except Exception:
            pass
        conn.close()
        return resultado["event_id"]
    except Exception as db_exc:
        # No interrumpir el flujo del usuario si falla la auditoría
        print(f"[AuditTracer] Advertencia: no se pudo registrar ACCESO_FALLIDO — {db_exc}")
        return None


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-63 — Decorador para interceptar excepciones de acceso
# ──────────────────────────────────────────────────────────────

def intercept_access_failures(
    dataset_nombre: Optional[str] = None,
    dataset_arg: Optional[str] = None,
):
    """
    Decorador que intercepta excepciones de acceso a datos clínicos y
    las registra automáticamente como ACCESO_FALLIDO (CA1).

    Uso:
        @intercept_access_failures(dataset_nombre="PATIENTS.csv")
        def cargar_datos(ruta: str) -> pd.DataFrame:
            return pd.read_csv(ruta)

    O para extraer el nombre del dataset de un argumento de la función:
        @intercept_access_failures(dataset_arg="ruta")
        def cargar_datos(ruta: str) -> pd.DataFrame:
            return pd.read_csv(ruta)

    Args:
        dataset_nombre: Nombre fijo del dataset (usado si dataset_arg es None).
        dataset_arg:    Nombre del parámetro de la función que contiene la ruta
                        del dataset (se extrae el basename automáticamente).

    Note:
        La excepción se re-lanza después de registrarla, para no ocultar errores.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except ACCESS_FAILURE_EXCEPTIONS as exc:
                # Resolver nombre del dataset
                nombre = dataset_nombre or "dataset_desconocido"
                if dataset_arg is not None:
                    # Intentar extraer desde kwargs primero, luego por posición
                    raw_path = kwargs.get(dataset_arg)
                    if raw_path is None:
                        sig = inspect.signature(func)
                        param_names = list(sig.parameters.keys())
                        if dataset_arg in param_names:
                            idx = param_names.index(dataset_arg)
                            if idx < len(args):
                                raw_path = args[idx]
                    if raw_path and isinstance(raw_path, str):
                        nombre = os.path.basename(raw_path)

                log_failed_access(dataset_nombre=nombre, exc=exc)
                raise   # Re-lanzar para no ocultar el error al llamador
        return wrapper
    return decorator
