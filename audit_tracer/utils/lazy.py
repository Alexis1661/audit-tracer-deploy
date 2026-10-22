"""
audit_tracer/utils/lazy.py
===========================
HU-5.1 CA3 — Import diferido de dependencias pesadas.

`requests` solo hace falta para hablar con el servidor central, y eso
ocurre en el hilo de fondo; importarlo dentro de `import audit_tracer`
costaba ~0,8 s en frío en el camino del usuario. El módulo diferido se
comporta como el real (incluido monkeypatch en tests): se carga de
verdad en el primer acceso a un atributo.
"""

import importlib.util
import sys


def lazy_import(nombre: str):
    """Devuelve el módulo `nombre`, cargándolo recién en su primer uso."""
    if nombre in sys.modules:
        return sys.modules[nombre]
    spec = importlib.util.find_spec(nombre)
    loader = importlib.util.LazyLoader(spec.loader)
    spec.loader = loader
    modulo = importlib.util.module_from_spec(spec)
    sys.modules[nombre] = modulo
    loader.exec_module(modulo)
    return modulo
