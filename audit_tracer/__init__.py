# Package initialization
from .session_tracker import init_tracker, login, logout
from .data_capture import activate as _activate_data_capture
from .sync_client import configure_sync, sync_now, sync_status  # HU-5.8

# Inicializar rastreo de sesión automático para scripts y Jupyter
init_tracker()

# HU-2.1: Activar interceptor automático de accesos a datos clínicos
# Intercepta pd.read_csv, pd.read_excel, df[], df.query()
_activate_data_capture()