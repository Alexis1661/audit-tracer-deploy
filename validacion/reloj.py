"""
validacion/reloj.py
===================
Ejecuta un script de analista con el reloj de audit_tracer desplazado a una
hora fija del día.

Uso:
    python validacion/reloj.py <inicio_utc_iso> <script.py> [args...]

Por qué existe: los casos de uso de la validación (sección 7.4 del documento)
necesitan que ciertas operaciones ocurran en horario laboral y otras a las
3 a. m. Esperar a esas horas haría la prueba irreproducible, así que el
proceso del analista arranca con un reloj que empieza en `inicio_utc_iso` y
avanza al ritmo del reloj real (time.monotonic). Solo cambia lo que devuelve
datetime.now()/utcnow() dentro de audit_tracer; el código del analista, pandas
y la lógica del sistema no se modifican.

Mecánica: se importan pandas, requests, sqlite3 y cryptography con el módulo
datetime real; después se instala en sys.modules un módulo `datetime` cuya
clase `datetime` es RelojSimulado (subclase de la real), y recién entonces se
importa audit_tracer, de modo que `from datetime import datetime` dentro de la
librería toma el reloj simulado. Esta herramienta es solo de validación: no se
empaqueta con la librería.
"""

import datetime as _dt_real
import os
import runpy
import sys
import time
import types

# Librerías de terceros con el datetime real (antes del cambio).
import pandas  # noqa: F401
import requests  # noqa: F401
import sqlite3  # noqa: F401
import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401

_REAL = _dt_real.datetime
_UTC = _dt_real.timezone.utc


def _instalar(inicio_utc: "_dt_real.datetime") -> None:
    inicio_monotonic = time.monotonic()

    def _ahora_utc() -> "_dt_real.datetime":
        return inicio_utc + _dt_real.timedelta(seconds=time.monotonic() - inicio_monotonic)

    class RelojSimulado(_REAL):
        @classmethod
        def utcnow(cls):
            a = _ahora_utc()
            return cls(a.year, a.month, a.day, a.hour, a.minute, a.second, a.microsecond)

        @classmethod
        def now(cls, tz=None):
            a = _ahora_utc().replace(tzinfo=_UTC)
            if tz is None:
                a = a.astimezone().replace(tzinfo=None)
            else:
                a = a.astimezone(tz)
            return cls(a.year, a.month, a.day, a.hour, a.minute, a.second, a.microsecond, a.tzinfo)

    falso = types.ModuleType("datetime")
    falso.__dict__.update({k: v for k, v in _dt_real.__dict__.items() if not k.startswith("__")})
    falso.datetime = RelojSimulado
    falso.__doc__ = "datetime con reloj simulado (validacion/reloj.py)"
    sys.modules["datetime"] = falso


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit("Uso: python validacion/reloj.py <inicio_utc_iso> <script.py> [args...]")
    inicio = _REAL.fromisoformat(sys.argv[1].replace("Z", ""))
    if inicio.tzinfo is not None:
        inicio = inicio.astimezone(_UTC).replace(tzinfo=None)
    script = sys.argv[2]
    _instalar(inicio)
    # El script se ejecuta como __main__ con sus propios argumentos.
    sys.argv = [script, *sys.argv[3:]]
    sys.path.insert(0, os.path.dirname(os.path.abspath(script)))
    runpy.run_path(script, run_name="__main__")


if __name__ == "__main__":
    main()
