import atexit
import os
import signal
from datetime import datetime
from .db import get_connection
from .auth.autenticacion import logout
from .models.audit_log import insert_event
from .utils.session import generate_session_id, get_hostname, detect_environment

class SessionTracker:
    _instance = None

    def __init__(self):
        self.sesion_id = generate_session_id()
        self.start_time = datetime.utcnow()
        self.usuario_id = os.environ.get('AUDIT_TRACER_USER', 'SISTEMA_LOCAL')
        self.conn = None
        self._active = False
        
        # Manejo de señales para cierre abrupto
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)

    def _handle_signal(self, signum, frame):
        """Manejador de señales del sistema."""
        self.end_session(abrupt=True)
        # Re-levantar la señal para que el programa termine normalmente
        signal.default_int_handler(signum, frame)

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def start_session(self):
        """Inicia el registro de la sesión."""
        if self._active:
            return

        try:
            self.conn = get_connection()
            insert_event(self.conn, {
                'usuario_id': self.usuario_id,
                'sesion_id': self.sesion_id,
                'timestamp': self.start_time.isoformat(),
                'tipo_accion': 'INICIO_SESION',
                'contexto_ejecucion': f"MODO_LIBRERIA | Env: {detect_environment()} | Host: {get_hostname()}",
                'nivel_alerta': 'NORMAL'
            })
            self._active = True
            # Registrar el cierre automático para terminación normal
            atexit.register(self.end_session)
        except Exception as e:
            # En modo librería no bloqueamos la ejecución si falla la auditoría, 
            # pero notificamos por consola
            print(f"Audit Tracer Error: No se pudo iniciar la sesión de auditoría: {e}")

    def end_session(self, abrupt=False):
        """Finaliza el registro de la sesión."""
        if not self._active:
            return

        try:
            tipo = 'CIERRE_SESION' if not abrupt else 'SESION_INTERRUMPIDA'
            now = datetime.utcnow()
            duration = int((now - self.start_time).total_seconds())

            insert_event(self.conn, {
                'usuario_id': self.usuario_id,
                'sesion_id': self.sesion_id,
                'timestamp': now.isoformat(),
                'tipo_accion': tipo,
                'contexto_ejecucion': f"Duración: {duration}s",
                'nivel_alerta': 'NORMAL' if not abrupt else 'ADVERTENCIA'
            })
            self.conn.close()
            self._active = False
        except:
            pass

def init_tracker():
    """Inicializa el tracker global."""
    tracker = SessionTracker.get_instance()
    tracker.start_session()
