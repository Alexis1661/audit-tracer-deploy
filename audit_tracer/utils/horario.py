"""
audit_tracer/utils/horario.py
==============================
HU-4.4 — Horario laboral configurable.

Define el rango de horas consideradas "horario laboral" para clasificar
accesos fuera de horario como eventos CRITICO (CA1).

Configurable vía variables de entorno (horas en formato 24h, 0-23):
  AUDIT_HORARIO_INICIO — hora de inicio del horario laboral (default 8)
  AUDIT_HORARIO_FIN    — hora de fin del horario laboral, exclusiva (default 18)

Los timestamps del sistema se registran en UTC (ver datetime.utcnow() en el
resto de audit_tracer), por lo que el horario configurado aquí también se
interpreta en UTC.
"""

import os
from datetime import datetime

HORA_INICIO_LABORAL = int(os.environ.get("AUDIT_HORARIO_INICIO", "8"))
HORA_FIN_LABORAL = int(os.environ.get("AUDIT_HORARIO_FIN", "18"))


def es_horario_laboral(dt: datetime) -> bool:
    """True si `dt` cae dentro del horario laboral configurado [inicio, fin)."""
    return HORA_INICIO_LABORAL <= dt.hour < HORA_FIN_LABORAL
