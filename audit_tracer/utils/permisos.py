"""
audit_tracer/utils/permisos.py
==============================
LIB-I1 / LIB-S2 / B2 — Archivos sensibles legibles solo por su dueño.

La base local, el token cacheado y la llave de firma se crean con permisos
0600 en Linux/macOS (Colab incluido). En Windows los archivos viven en el
perfil del usuario, cuyo ACL ya excluye a los demás usuarios del equipo;
os.chmod allí solo controla el atributo de solo lectura, así que no se toca.
"""

import os
import stat


def es_windows() -> bool:
    return os.name == "nt"


def restringir_a_dueno(ruta: str) -> bool:
    """
    Deja `ruta` con permisos 0600 (archivo) o 0700 (carpeta) en POSIX.
    Devuelve True si los permisos quedaron restringidos o no aplica (Windows).
    Nunca lanza: un fallo de permisos no puede romper el script del usuario.
    """
    if es_windows():
        return True
    try:
        modo = 0o700 if os.path.isdir(ruta) else 0o600
        os.chmod(ruta, modo)
        return True
    except OSError:
        return False


def es_privado(ruta: str) -> bool:
    """True si ni el grupo ni otros usuarios pueden leer `ruta` (siempre True en Windows)."""
    if es_windows():
        return True
    try:
        return not (os.stat(ruta).st_mode & (stat.S_IRWXG | stat.S_IRWXO))
    except OSError:
        return False


def escribir_privado(ruta: str, datos: bytes) -> None:
    """Escribe `datos` en `ruta` creando el archivo ya con permisos 0600 (sin ventana de exposición)."""
    carpeta = os.path.dirname(ruta)
    if carpeta:
        os.makedirs(carpeta, exist_ok=True)
    banderas = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0)
    fd = os.open(ruta, banderas, 0o600)
    try:
        os.write(fd, datos)
    finally:
        os.close(fd)
    restringir_a_dueno(ruta)
