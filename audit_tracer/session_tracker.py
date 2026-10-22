import atexit
import os
import signal
import sys
import threading
from datetime import datetime
from typing import Dict, Optional
from .db import get_connection
from .auth.autenticacion import login as _auth_login, logout as _auth_logout
from .models.audit_log import insert_event_and_enqueue_sync
from .utils.error_log import guard, log_internal_error
from .utils.session import generate_session_id, get_hostname, detect_environment

_AVISO_SIN_USUARIO = (
    "[AuditTracer] La auditoría está activa, pero no hay un usuario identificado: "
    "los eventos se registran como DESCONOCIDO (nivel CRITICO). "
    "Ejecuta audit_tracer.login(api_url=...) para identificarte."
)


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
        self._recordado = False

        # Manejo de señales para cierre abrupto
        self._install_signal_handlers()

    def _install_signal_handlers(self):
        """
        HU-5.1 CA2: signal.signal() solo puede llamarse desde el hilo
        principal (si no, ValueError y el import fallaría). En un kernel de
        notebook, SIGINT es "Interrumpir kernel": detiene la celda, no
        termina la sesión, así que ahí no se intercepta.
        """
        if threading.current_thread() is not threading.main_thread():
            return
        try:
            if 'ipykernel' not in sys.modules:
                signal.signal(signal.SIGINT, self._handle_signal)
            signal.signal(signal.SIGTERM, self._handle_signal)
        except (ValueError, OSError) as exc:
            log_internal_error("No se pudieron instalar los manejadores de señales", exc)

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
            insert_event_and_enqueue_sync(self.conn, {
                'usuario_id': self.usuario_id,
                'sesion_id': self.sesion_id,
                'timestamp': self.start_time.isoformat(),
                'tipo_accion': 'INICIO_SESION',
                'contexto_ejecucion': f"MODO_LIBRERIA | Env: {detect_environment()} | Host: {get_hostname()}",
                'nivel_alerta': 'NORMAL'
            })
            _schedule_sync()
            self._active = True
            # Registrar el cierre automático para terminación normal
            atexit.register(self.end_session)
        except Exception as e:
            # En modo librería no bloqueamos la ejecución si falla la auditoría
            # (HU-5.1 CA4: el detalle va al log de errores del sistema).
            log_internal_error("No se pudo iniciar la sesión de auditoría", e)

    def remind_if_unidentified(self) -> None:
        """
        HU-5.1 — Recordatorio (una sola vez por sesión) en el primer evento
        de datos capturado sin usuario identificado. Solo en notebooks: ahí
        el aviso del import queda en otra celda; en un .py ya se vio.
        """
        if self._recordado or self.usuario_id != 'DESCONOCIDO':
            return
        self._recordado = True
        if detect_environment() != 'Script (.py)':
            _avisar(_AVISO_SIN_USUARIO)

    def identify_from_cache(self) -> bool:
        """
        HU-5.1 — Si hay un token cacheado por un login() anterior (HU-5.7),
        identifica al usuario sin pedir nada y sin tocar la red: solo lee
        el caché en disco. El token se valida en segundo plano; si el
        servidor lo rechaza, se vuelve a DESCONOCIDO y se avisa.
        """
        from .device_login import load_cached_identity
        identidad = load_cached_identity()
        if identidad is None:
            return False

        self.usuario_id = identidad['usuario_id']
        from . import sync_client
        sync_client.configure_sync(identidad['api_url'], identidad['token'])
        threading.Thread(
            target=self._validar_identidad_cacheada,
            args=(identidad['api_url'], identidad['token']),
            name="audit_tracer-validar-token", daemon=True,
        ).start()
        return True

    def _validar_identidad_cacheada(self, api_url: str, token: str) -> None:
        try:
            from .device_login import token_status, clear_cached_token
            if token_status(api_url, token) != 'INVALIDO':
                return  # válido, o sin conexión: se valida de nuevo al sincronizar
            from . import sync_client
            sync_client.unconfigure_sync()
            clear_cached_token()
            self.usuario_id = 'DESCONOCIDO'
            self._recordado = False
            _avisar(
                "[AuditTracer] El token guardado ya no es válido (expiró o fue revocado). "
                "Los eventos siguientes se registran como DESCONOCIDO. "
                "Ejecuta audit_tracer.login(api_url=...) de nuevo."
            )
        except Exception as exc:
            log_internal_error("Validación en segundo plano del token cacheado", exc)

    def _registrar_atribucion(self) -> None:
        """
        HU-5.1 — audit_log es inmutable y usuario_id forma parte del hash:
        los eventos registrados como DESCONOCIDO antes del login no se
        pueden reescribir. En su lugar se agrega un evento ATRIBUCION_SESION
        que liga este sesion_id con el usuario recién identificado.
        """
        conn = get_connection()
        try:
            previos = conn.execute(
                "SELECT COUNT(*) FROM audit_log WHERE sesion_id = ? AND usuario_id = 'DESCONOCIDO'",
                (self.sesion_id,),
            ).fetchone()[0]
            if not previos:
                return
            insert_event_and_enqueue_sync(conn, {
                'usuario_id': self.usuario_id,
                'sesion_id': self.sesion_id,
                'timestamp': datetime.utcnow().isoformat(),
                'tipo_accion': 'ATRIBUCION_SESION',
                'contexto_ejecucion': (
                    f"{previos} evento(s) previos de esta sesión quedaron como DESCONOCIDO "
                    f"y se atribuyen a {self.usuario_id} tras login()"
                ),
                'nivel_alerta': 'ADVERTENCIA',
                'motivo_alerta': f"Identificación tardía: {previos} evento(s) sin usuario en la sesión",
            })
        finally:
            conn.close()
        _schedule_sync()

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

        HU-5.1: si la sesión ya tenía eventos como DESCONOCIDO, se registra
        un evento ATRIBUCION_SESION que los liga al usuario identificado.

        Args:
            email: Email del usuario (camino HU-2.5).
            password: Contraseña del usuario (camino HU-2.5).
            api_url: Base URL del servidor central (camino HU-5.7). Si se
                omite, se usa la variable de entorno AUDIT_TRACER_API_URL.
            cache_dir: Carpeta donde cachear el token (camino HU-5.7).

        Returns:
            Dict: resultado de autenticación (success, message, ...).
        """
        anterior = self.usuario_id

        if email and password:
            conn = self.conn or get_connection()
            try:
                result = _auth_login(conn, email, password, self.sesion_id)
            finally:
                if conn is not self.conn:
                    conn.close()

            if result.get('success'):
                self.usuario_id = result['usuario_id']
                if anterior == 'DESCONOCIDO':
                    guard(self._registrar_atribucion, _contexto="Registro de ATRIBUCION_SESION")

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
            except Exception as exc:
                # la identidad local ya quedó establecida aunque falle configurar el sync
                log_internal_error("No se pudo configurar la sincronización tras login()", exc)
            if anterior == 'DESCONOCIDO':
                guard(self._registrar_atribucion, _contexto="Registro de ATRIBUCION_SESION")

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

            insert_event_and_enqueue_sync(self.conn, {
                'usuario_id': self.usuario_id,
                'sesion_id': self.sesion_id,
                'timestamp': now.isoformat(),
                'tipo_accion': tipo,
                'contexto_ejecucion': f"Duración: {duration}s",
                'nivel_alerta': 'NORMAL' if not abrupt else 'ADVERTENCIA'
            })
            self.conn.close()
            self._active = False
        except Exception as exc:
            log_internal_error("No se pudo registrar el cierre de sesión", exc)

        # HU-5.1 CA4: último intento de sincronizar (incluido el cierre),
        # acotado en tiempo; lo que no alcance se envía en la próxima sesión.
        try:
            from .sync_client import flush_pending
            flush_pending()
        except Exception as exc:
            log_internal_error("Sincronización final al cerrar la sesión", exc)


def _schedule_sync() -> None:
    try:
        from .sync_client import schedule_sync
        schedule_sync()
    except Exception as exc:
        log_internal_error("No se pudo programar la sincronización", exc)


def _avisar(mensaje: str) -> None:
    try:
        sys.stderr.write(mensaje + "\n")
    except Exception:
        pass


def init_tracker():
    """
    Inicializa el tracker global.

    HU-5.1: antes de registrar INICIO_SESION intenta identificar al usuario
    con el token cacheado (sin red). Si no hay token, la captura sigue igual
    (DESCONOCIDO) y se muestra un aviso para ejecutar audit_tracer.login().
    """
    tracker = SessionTracker.get_instance()
    if not tracker._active:
        guard(tracker.identify_from_cache, _contexto="Identificación desde el token cacheado")
    tracker.start_session()
    if tracker.usuario_id == 'DESCONOCIDO':
        # Aviso al importar; remind_if_unidentified() lo repite una sola vez
        # en el primer evento de datos, que en un notebook suele ser otra celda.
        _avisar(_AVISO_SIN_USUARIO)


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
