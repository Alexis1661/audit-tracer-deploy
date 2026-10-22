"""
audit_tracer/utils/error_log.py
================================
HU-5.1 CA4 — Aislamiento de errores internos de la librería.

- `guard()` ejecuta lógica de auditoría y nunca deja escapar una excepción
  propia de audit_tracer hacia el código del usuario.
- Los errores internos se escriben en un log de sistema
  (`~/.audit_tracer/errores_sistema.log`), nunca en la tabla audit_log.
- `audit_scope()` marca que el hilo actual está dentro de una operación ya
  auditada, para que las llamadas internas de pandas (que pueden volver a
  pasar por métodos interceptados) no generen eventos duplicados.

Solo se captura `Exception`: KeyboardInterrupt/SystemExit siguen llegando
al usuario como siempre.
"""

import logging
import sys
import threading
from contextlib import contextmanager

from .paths import error_log_path

_LOGGER_NAME = "audit_tracer.internal"
_handler_path = None
_state = threading.local()


def _get_logger() -> logging.Logger:
    """Logger dedicado con su propio archivo; no propaga al logger raíz."""
    global _handler_path
    logger = logging.getLogger(_LOGGER_NAME)
    path = error_log_path()
    if _handler_path != path:
        for h in list(logger.handlers):
            logger.removeHandler(h)
            h.close()
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
        _handler_path = path
    return logger


def log_internal_error(contexto: str, exc: BaseException = None) -> None:
    """Registra un error interno de audit_tracer. Nunca lanza."""
    try:
        logger = _get_logger()
        if exc is not None:
            logger.error("%s: %s: %s", contexto, type(exc).__name__, exc,
                         exc_info=(type(exc), exc, exc.__traceback__))
        else:
            logger.error("%s", contexto)
    except Exception:
        try:
            sys.stderr.write(f"[AuditTracer] error interno ({contexto}): {exc}\n")
        except Exception:
            pass


def guard(fn, *args, _contexto: str = None, _default=None, **kwargs):
    """
    Ejecuta `fn(*args, **kwargs)`. Si lanza una excepción, la registra en el
    log de errores del sistema y retorna `_default` en vez de propagarla.
    """
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        log_internal_error(_contexto or getattr(fn, "__qualname__", repr(fn)), exc)
        return _default


def in_audit_scope() -> bool:
    """True si el hilo actual ya está dentro de una operación auditada."""
    return getattr(_state, "depth", 0) > 0


@contextmanager
def audit_scope():
    """Marca el hilo actual como 'dentro de una operación auditada'."""
    _state.depth = getattr(_state, "depth", 0) + 1
    try:
        yield
    finally:
        _state.depth -= 1
