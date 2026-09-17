import atexit
import os
import signal
from datetime import datetime
from typing import Dict, Optional
from .db import get_connection
from .auth.autenticacion import login as _auth_login, logout as _auth_logout
from .models.audit_log import insert_event_and_enqueue_sync
from .utils.session import generate_session_id, get_hostname, detect_environment

class SessionTracker:
    _instance = None

    def __init__(self):
        self.sesion_id = generate_session_id()
        self.start_time = datetime.utcnow()
        # HU-2.5 CA4: usuario_id solo se establece tras un login() válido
        # contra el mismo mecanismo de autenticación que usa la app web.
        # Hasta entonces el usuario es DESCONOCIDO (CA2).
        self.usuario_id = 'DESCONOCIDO'
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
            # HU-5.8 CA1: persistencia local + encolado antes de cualquier envío.
            resultado = insert_event_and_enqueue_sync(self.conn, {
                'usuario_id': self.usuario_id,
                'sesion_id': self.sesion_id,
                'timestamp': self.start_time.isoformat(),
                'tipo_accion': 'INICIO_SESION',
                'contexto_ejecucion': f"MODO_LIBRERIA | Env: {detect_environment()} | Host: {get_hostname()}",
                'nivel_alerta': 'NORMAL'
            })
            try:
                from .sync_client import try_sync_event
                try_sync_event(self.conn, resultado['event_id'])  # best-effort, nunca lanza
            except Exception:
                pass
            self._active = True
            # Registrar el cierre automático para terminación normal
            atexit.register(self.end_session)
        except Exception as e:
            # En modo librería no bloqueamos la ejecución si falla la auditoría, 
            # pero notificamos por consola
            print(f"Audit Tracer Error: No se pudo iniciar la sesión de auditoría: {e}")

    def login(
        self,
        email: Optional[str] = None,
        password: Optional[str] = None,
        api_url: Optional[str] = None,
        cache_dir: Optional[str] = None,
    ) -> Dict:
        """
        HU-2.5 CA4 / HU-5.7 — Autentica al usuario activo del modo librería.
        Dos caminos, según los argumentos recibidos:

        - email + password: autenticación directa (HU-2.5), sin cambios de
          comportamiento respecto a como funcionaba antes de HU-5.7.
        - sin credenciales: login por código de dispositivo (HU-5.7 CA1-CA5)
          — genera/reusa un token vía audit_tracer.device_login.device_login(),
          y además configura la sincronización automática hacia el servidor
          central con ese token, para que "un solo comando" deje todo listo.

        En éxito, self.usuario_id pasa a ser el usuario autenticado y los
        eventos posteriores (CARGA, CONSULTA, EXPORTACION, ...) quedan
        correctamente atribuidos. En fallo, self.usuario_id no se modifica
        (permanece DESCONOCIDO si no había login previo).

        Args:
            email: Email del usuario (camino HU-2.5).
            password: Contraseña del usuario (camino HU-2.5).
            api_url: Base URL del servidor central (camino HU-5.7). Si se
                omite, se usa la variable de entorno AUDIT_TRACER_API_URL.
            cache_dir: Carpeta donde cachear el token (camino HU-5.7).

        Returns:
            Dict: resultado de autenticación (success, message, ...).
        """
        if email and password:
            conn = self.conn or get_connection()
            try:
                result = _auth_login(conn, email, password, self.sesion_id)
            finally:
                if conn is not self.conn:
                    conn.close()

            if result.get('success'):
                self.usuario_id = result['usuario_id']

            return result

        # HU-5.7: sin credenciales -> login por código de dispositivo.
        resolved_api_url = api_url or os.environ.get('AUDIT_TRACER_API_URL')
        if not resolved_api_url:
            return {
                'success': False,
                'message': (
                    'Debes indicar api_url (o definir la variable de entorno '
                    'AUDIT_TRACER_API_URL) para el login por código.'
                ),
            }

        from .device_login import device_login
        resultado = device_login(resolved_api_url, cache_dir=cache_dir)

        if resultado.get('success'):
            self.usuario_id = resultado['usuario_id']
            try:
                from .sync_client import configure_sync
                configure_sync(resolved_api_url, resultado['token'])
            except Exception:
                pass  # la identidad local ya quedó establecida aunque falle configurar el sync

        return resultado

    def logout(self) -> None:
        """
        HU-2.5 CA4 — Cierra la identificación del usuario activo (registra
        CIERRE_SESION vía auth.autenticacion.logout) y vuelve a DESCONOCIDO,
        para que cualquier operación posterior no se atribuya erróneamente
        al usuario anterior.
        """
        if self.usuario_id == 'DESCONOCIDO':
            return

        conn = self.conn or get_connection()
        try:
            _auth_logout(conn, self.usuario_id, self.sesion_id, self.start_time.isoformat())
        finally:
            if conn is not self.conn:
                conn.close()
            self.usuario_id = 'DESCONOCIDO'

    def end_session(self, abrupt=False):
        """Finaliza el registro de la sesión."""
        if not self._active:
            return

        try:
            tipo = 'CIERRE_SESION' if not abrupt else 'SESION_INTERRUMPIDA'
            now = datetime.utcnow()
            duration = int((now - self.start_time).total_seconds())

            resultado = insert_event_and_enqueue_sync(self.conn, {
                'usuario_id': self.usuario_id,
                'sesion_id': self.sesion_id,
                'timestamp': now.isoformat(),
                'tipo_accion': tipo,
                'contexto_ejecucion': f"Duración: {duration}s",
                'nivel_alerta': 'NORMAL' if not abrupt else 'ADVERTENCIA'
            })
            try:
                from .sync_client import try_sync_event
                try_sync_event(self.conn, resultado['event_id'])  # best-effort, nunca lanza
            except Exception:
                pass
            self.conn.close()
            self._active = False
        except:
            pass

def init_tracker():
    """Inicializa el tracker global."""
    tracker = SessionTracker.get_instance()
    tracker.start_session()


def login(
    email: Optional[str] = None,
    password: Optional[str] = None,
    api_url: Optional[str] = None,
    cache_dir: Optional[str] = None,
) -> Dict:
    """
    API pública de modo librería:
      - audit_tracer.login(email, password) — HU-2.5, autenticación directa.
      - audit_tracer.login() — HU-5.7, login por código de dispositivo.
    Ver SessionTracker.login().
    """
    return SessionTracker.get_instance().login(email, password, api_url, cache_dir)


def logout() -> None:
    """HU-2.5 CA4 — API pública de modo librería. Ver SessionTracker.logout()."""
    SessionTracker.get_instance().logout()
