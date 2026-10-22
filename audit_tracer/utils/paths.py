"""
audit_tracer/utils/paths.py
============================
HU-5.1 CA2 — Ubicación fija de los datos locales de la librería.

Todo lo que la librería guarda en disco vive en `~/.audit_tracer/`, no en
el directorio de trabajo: así el mismo usuario usa la misma base local, el
mismo par de llaves (HU-6.1) y el mismo log de errores aunque cambie de
carpeta (`%cd` en Colab, scripts lanzados desde otro directorio, etc.).
"""

import os

_DIR_NAME = ".audit_tracer"
_created: set = set()


def data_dir() -> str:
    """Carpeta de datos de la librería (`~/.audit_tracer`), creada si no existe."""
    path = os.path.join(os.path.expanduser("~"), _DIR_NAME)
    if path not in _created:
        os.makedirs(path, exist_ok=True)
        _created.add(path)
    return path


def local_db_path() -> str:
    """Base SQLite local (caché de eventos + cola de sincronización)."""
    return os.path.join(data_dir(), "audit_trail.db")


def keys_dir() -> str:
    """Par de llaves Ed25519 del usuario (HU-6.1)."""
    return os.path.join(data_dir(), "keys")


def error_log_path() -> str:
    """Log de errores internos de la librería, separado de audit_log (HU-5.1 CA4)."""
    return os.path.join(data_dir(), "errores_sistema.log")
