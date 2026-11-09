"""
audit_tracer/utils/horario.py
==============================
HU-4.4 — Horario laboral configurable.

Define el rango de horas consideradas "horario laboral" para clasificar
accesos fuera de horario como eventos CRITICO (CA1).

Configurable vía variables de entorno (horas en formato 24h, 0-23):
  AUDIT_HORARIO_INICIO — hora de inicio del horario laboral (default 8)
  AUDIT_HORARIO_FIN    — hora de fin del horario laboral, exclusiva (default 18)

Los timestamps del sistema se registran en UTC, pero el horario laboral es
el de la institución: las horas configuradas se interpretan en hora de
Colombia (UTC-5). Antes se comparaban contra la hora UTC, y una consulta a
las 2 p. m. en Colombia (19:00 UTC) quedaba como "fuera de horario".
"""

import os
from datetime import datetime

from .zona_horaria import a_hora_colombia

HORA_INICIO_LABORAL = int(os.environ.get("AUDIT_HORARIO_INICIO", "8"))
HORA_FIN_LABORAL = int(os.environ.get("AUDIT_HORARIO_FIN", "18"))


def es_horario_laboral(dt: datetime) -> bool:
    """
    True si `dt` cae dentro del horario laboral configurado [inicio, fin),
    medido en hora de Colombia. Un `dt` sin zona se asume UTC.
    """
    return HORA_INICIO_LABORAL <= a_hora_colombia(dt).hour < HORA_FIN_LABORAL
