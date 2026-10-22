"""
audit_tracer/utils/contexto.py
===============================
HU-5.1 CA2/CA3 — Contexto de ejecución (`contexto_ejecucion`) igual de
útil en scripts .py, Jupyter y Google Colab, y barato de calcular.

Recorre la pila con `sys._getframe()` en vez de `inspect.stack()`:
`inspect.stack()` lee el código fuente de cada frame en cada evento, que
es lento, y en un kernel de notebook solo devuelve el nombre del archivo
temporal del kernel (p. ej. `2311463826.py`), que no le dice nada a un
auditor. En notebooks se registra la celda (`execution_count`) y, si el
entorno lo expone, el nombre del notebook.
"""

import functools
import os
import socket
import sys

_PACKAGE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + os.sep
_PANDAS_MARK = os.sep + "pandas" + os.sep


def detect_environment() -> str:
    """'Google Colab', 'Jupyter' o 'Script (.py)'."""
    if "google.colab" in sys.modules:
        return "Google Colab"
    if "ipykernel" in sys.modules:
        return "Jupyter"
    return "Script (.py)"


@functools.lru_cache(maxsize=1)
def get_hostname() -> str:
    return socket.gethostname()


def _is_internal(filename: str) -> bool:
    return (
        filename.startswith("<frozen")
        or filename == "<string>"
        or os.path.abspath(filename).startswith(_PACKAGE_DIR)
        or _PANDAS_MARK in filename
    )


def _is_notebook_cell(filename: str) -> bool:
    return "ipykernel_" in filename or filename.startswith("<ipython-input-")


def _notebook_name() -> str:
    """Nombre del notebook si el entorno lo expone; si no, cadena vacía."""
    session_name = os.environ.get("JPY_SESSION_NAME")  # Jupyter Server >= 2
    if session_name:
        return os.path.basename(session_name)
    try:
        from IPython import get_ipython
        ip = get_ipython()
        vsc = ip.user_ns.get("__vsc_ipynb_file__") if ip is not None else None  # VS Code
        if vsc:
            return os.path.basename(vsc)
    except Exception:
        pass
    return ""


def _cell_number():
    try:
        from IPython import get_ipython
        ip = get_ipython()
        return ip.execution_count if ip is not None else None
    except Exception:
        return None


def caller_label(skip: int = 1) -> str:
    """Nombre del script del usuario, o 'notebook.ipynb [celda N]' en notebooks."""
    frame = sys._getframe(skip)
    while frame is not None:
        filename = frame.f_code.co_filename
        if not _is_internal(filename):
            if _is_notebook_cell(filename):
                nombre = _notebook_name() or "notebook"
                celda = _cell_number()
                return f"{nombre} [celda {celda}]" if celda is not None else nombre
            return os.path.basename(filename)
        frame = frame.f_back
    return "desconocido"


def build_contexto(extra: str = None) -> str:
    """Formato histórico: 'Script: X | Env: Y | Host: Z[ | extra]'."""
    base = f"Script: {caller_label(2)} | Env: {detect_environment()} | Host: {get_hostname()}"
    return f"{base} | {extra}" if extra else base
