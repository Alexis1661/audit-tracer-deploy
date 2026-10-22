"""
Aislamiento global de la suite (HU-5.1).

La librería guarda sus datos locales en ~/.audit_tracer (base local, llaves,
log de errores, token cacheado). Antes de que cualquier test importe
audit_tracer, el home se redirige a una carpeta temporal: la suite nunca
lee el token real del desarrollador (que la identificaría y abriría
conexiones al servidor central) ni escribe en su base local.
"""

import os
import tempfile

_HOME_TEMPORAL = tempfile.mkdtemp(prefix="audit_tracer_tests_home_")
os.environ["HOME"] = _HOME_TEMPORAL
os.environ["USERPROFILE"] = _HOME_TEMPORAL
os.environ.pop("AUDIT_TRACER_API_URL", None)
