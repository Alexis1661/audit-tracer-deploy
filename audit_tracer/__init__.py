# Package initialization
from .session_tracker import init_tracker, login, logout
from .data_capture import activate as _activate_data_capture
from .export_capture import activate as _activate_export_capture
from .sync_client import configure_sync, sync_now, sync_status  # HU-5.8
# HU-5.7: audit_tracer.login() (sin credenciales) ya cubre el login por
# código de dispositivo — no se reexporta device_login() a nivel de
# paquete a propósito, para no sombrear el submódulo audit_tracer.device_login
# con una función del mismo nombre. Uso directo: from audit_tracer.device_login import device_login

# Inicializar rastreo de sesión automático para scripts y Jupyter
init_tracker()

# HU-2.1: Activar interceptor automático de accesos a datos clínicos
# Intercepta pd.read_csv, pd.read_excel, df[], df.query()
_activate_data_capture()

# HU-2.3: Activar interceptor automático de exportación de datos
# Intercepta df.to_csv, df.to_excel, df.to_json, df.to_parquet
_activate_export_capture()