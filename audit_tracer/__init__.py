# Package initialization
#
# HU-5.1 — `import audit_tracer` es la única línea necesaria: identifica al
# usuario con el token cacheado si existe (sin red), registra INICIO_SESION
# y activa toda la captura (carga, consulta, transformación, exportación e
# intentos fallidos). Reimportar o recargar no vuelve a parchear pandas
# (cada interceptor se reconoce a sí mismo) ni duplica eventos. Si algo de
# esto falla, el error va al log de errores del sistema y el import termina
# igual: la librería nunca rompe el script del usuario (CA4).
from .utils.error_log import guard as _guard
from .session_tracker import init_tracker, login, logout
from .data_capture import activate as _activate_data_capture
from .export_capture import activate as _activate_export_capture
from .transform_capture import activate as _activate_transform_capture
from .sync_client import configure_sync, sync_now, sync_status  # HU-5.8
# HU-5.7: audit_tracer.login() (sin credenciales) ya cubre el login por
# código de dispositivo — no se reexporta device_login() a nivel de
# paquete a propósito, para no sombrear el submódulo audit_tracer.device_login
# con una función del mismo nombre. Uso directo: from audit_tracer.device_login import device_login

# HU-2.1 / HU-2.4: carga (read_csv, read_excel), consulta (df[], df.query())
# e intentos fallidos de acceso.
_guard(_activate_data_capture, _contexto="Activación de data_capture")

# HU-2.2: transformaciones (fillna, dropna, drop, rename, apply, merge).
_guard(_activate_transform_capture, _contexto="Activación de transform_capture")

# HU-2.3: exportación (to_csv, to_excel, to_json, to_parquet).
_guard(_activate_export_capture, _contexto="Activación de export_capture")

# Inicializar rastreo de sesión automático para scripts y Jupyter
_guard(init_tracker, _contexto="Inicialización de la sesión de auditoría")
