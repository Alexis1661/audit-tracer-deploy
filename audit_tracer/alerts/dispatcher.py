"""
dispatcher.py — HU-7.2 CA2/CA4 / Sub-tarea 3: disparo de notificaciones
desacoplado del registro del evento.

Flujo:

  insert_event()/insert_event_if_new()          (hilo de la petición)
      └─ _execute_insert(): INSERT + COMMIT      ← el evento YA quedó persistido
           └─ hooks post-inserción
                └─ DespachadorAlertas.hook_post_insercion()
                     └─ cola.put_nowait(event_id)   ← O(1), nunca bloquea, nunca lanza

  hilo daemon "audit-alertas"                    (fuera del hilo de la petición)
      └─ procesar_evento(event_id)
           ├─ abre SU PROPIA conexión a la base central
           ├─ relee el evento, lo clasifica (catalogo.clasificar_evento)
           ├─ resuelve destinatarios (alertas_destinatarios)
           ├─ envía el correo con reintentos y backoff
           └─ deja el resultado en alertas_notificaciones

CA4 se garantiza por construcción:
  1. El hook corre DESPUÉS del COMMIT: si todo lo demás falla, el evento
     ya está en audit_log.
  2. Lo único que hace el hilo de la petición es un put_nowait() en una
     cola en memoria; la clasificación (que consulta la base), el SMTP y
     los reintentos ocurren en otro hilo.
  3. Cualquier excepción del hook se atrapa en models/audit_log.py y va al
     log interno; nunca llega al INSERT ni a la respuesta HTTP.
  4. Si la cola está llena (ráfaga anómala), el evento se descarta de las
     notificaciones — no del registro — y queda en el log interno.
"""

import os
import queue
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from ..models import alertas as modelo
from ..models.audit_log import (
    eliminar_hook_post_insercion,
    get_event_by_id,
    registrar_hook_post_insercion,
)
from ..utils.error_log import log_internal_error
from .catalogo import CATALOGO_EVENTOS_CRITICOS, clasificar_evento
from .email_service import (
    ErrorEnvioCorreo,
    ServicioCorreo,
    construir_mensaje,
    construir_mensaje_prueba,
)

URL_DASHBOARD_POR_DEFECTO = "http://localhost:5000"


def _ruta_archivo_conexion(conn: sqlite3.Connection) -> Optional[str]:
    """Ruta absoluta del archivo de la base 'main' de `conn` (None si es en memoria)."""
    for fila in conn.execute("PRAGMA database_list").fetchall():
        if fila[1] == "main":
            return os.path.normcase(os.path.abspath(fila[2])) if fila[2] else None
    return None


class DespachadorAlertas:
    """
    Recibe event_ids recién insertados en la base central y, en un hilo
    aparte, decide si son críticos y notifica por correo.
    """

    def __init__(
        self,
        db_path: str,
        servicio_correo: Optional[ServicioCorreo] = None,
        url_base: Optional[str] = None,
        max_intentos: int = 3,
        backoff_base_segundos: float = 2.0,
        tamano_cola: int = 10_000,
        conexion_factory: Optional[Callable[[], sqlite3.Connection]] = None,
    ):
        self.db_path = db_path
        self._db_path_norm = os.path.normcase(os.path.abspath(db_path))
        self.servicio_correo = servicio_correo
        self._url_base = url_base
        self.max_intentos = max(1, max_intentos)
        self.backoff_base_segundos = backoff_base_segundos
        self._cola: "queue.Queue[Optional[int]]" = queue.Queue(maxsize=tamano_cola)
        self._hilo: Optional[threading.Thread] = None
        self._detener = threading.Event()
        self._conexion_factory = conexion_factory
        self.descartados = 0

    # ── Configuración ────────────────────────────────────────────
    @property
    def url_base(self) -> str:
        return (
            os.environ.get("AUDIT_DASHBOARD_URL")
            or self._url_base
            or URL_DASHBOARD_POR_DEFECTO
        ).rstrip("/")

    def recordar_url_base(self, url: str) -> None:
        """La app la fija con la URL real de la primera petición, si no hay AUDIT_DASHBOARD_URL."""
        if not self._url_base and url:
            self._url_base = url.rstrip("/")

    def url_detalle(self, event_id) -> str:
        """CA3 — Enlace directo al detalle del evento (HU-4.3)."""
        return f"{self.url_base}/eventos/{event_id}"

    def _conectar(self) -> sqlite3.Connection:
        if self._conexion_factory is not None:
            return self._conexion_factory()
        from ..db import get_central_connection
        return get_central_connection(self.db_path)

    # ── Hilo de la petición: solo encolar ────────────────────────
    def hook_post_insercion(self, conn: sqlite3.Connection, event_id: int, evento: Dict) -> None:
        """
        Registrado en models/audit_log.py. Corre en el hilo que insertó, justo
        después del COMMIT — por eso no hace nada más que encolar el id.
        Ignora inserciones en otras bases (p. ej. la base local de la librería).
        """
        if _ruta_archivo_conexion(conn) != self._db_path_norm:
            return
        self.encolar(event_id)

    def encolar(self, event_id: int) -> bool:
        try:
            self._cola.put_nowait(event_id)
            return True
        except queue.Full:
            self.descartados += 1
            log_internal_error(
                f"HU-7.2: cola de alertas llena; no se notificará event_id={event_id} "
                "(el evento sí quedó registrado)"
            )
            return False

    # ── Hilo de alertas ──────────────────────────────────────────
    def iniciar(self) -> "DespachadorAlertas":
        if self._hilo is None or not self._hilo.is_alive():
            self._detener.clear()
            self._hilo = threading.Thread(target=self._bucle, name="audit-alertas", daemon=True)
            self._hilo.start()
        return self

    def detener(self, timeout: float = 5.0) -> None:
        self._detener.set()
        try:
            self._cola.put_nowait(None)
        except queue.Full:
            pass
        if self._hilo is not None:
            self._hilo.join(timeout)

    @property
    def activo(self) -> bool:
        return self._hilo is not None and self._hilo.is_alive()

    def esperar(self, timeout: float = 10.0) -> bool:
        """Espera a que la cola se vacíe (útil en pruebas). True si terminó a tiempo."""
        limite = time.monotonic() + timeout
        while self._cola.unfinished_tasks:
            if time.monotonic() > limite:
                return False
            time.sleep(0.01)
        return True

    def procesar_pendientes(self) -> List[Optional[Dict]]:
        """Procesa en el hilo actual todo lo encolado (modo síncrono, para pruebas/CLI)."""
        resultados = []
        while True:
            try:
                event_id = self._cola.get_nowait()
            except queue.Empty:
                return resultados
            try:
                if event_id is not None:
                    resultados.append(self.procesar_evento(event_id))
            finally:
                self._cola.task_done()

    def _bucle(self) -> None:
        while not self._detener.is_set():
            event_id = self._cola.get()
            try:
                if event_id is not None:
                    self.procesar_evento(event_id)
            except Exception as exc:  # el hilo nunca debe morir
                log_internal_error(f"HU-7.2: error procesando alerta de event_id={event_id}", exc)
            finally:
                self._cola.task_done()

    # ── Núcleo: clasificar → destinatarios → enviar → registrar ──
    def procesar_evento(self, event_id: int) -> Optional[Dict]:
        """
        Devuelve None si el evento no es crítico (o ya fue notificado); si no,
        la fila final de alertas_notificaciones.
        """
        conn = self._conectar()
        try:
            evento = get_event_by_id(conn, event_id)
            if evento is None:
                return None
            clasificacion = clasificar_evento(conn, evento)
            if clasificacion is None:
                return None

            # Ráfagas (accesos denegados repetidos): un correo por ventana y usuario.
            # Solo se agrupa si TODOS los tipos del evento son agrupables y ya
            # hubo una notificación reciente de cada uno.
            agrupar = all(
                CATALOGO_EVENTOS_CRITICOS[t].agrupable
                and modelo.existe_notificacion_reciente(
                    conn, evento.get("usuario_id"), t,
                    desde=datetime.utcnow() - timedelta(
                        minutes=CATALOGO_EVENTOS_CRITICOS[t].ventana_agrupacion_min),
                    excluir_event_id=event_id,
                )
                for t in clasificacion.tipos
            )
            if agrupar:
                nid = modelo.registrar_notificacion(
                    conn, evento, clasificacion.tipos, clasificacion.severidad,
                    estado=modelo.ESTADO_AGRUPADA,
                    error="Ya se notificó esta ráfaga en la ventana de agrupación",
                )
                return modelo.obtener_notificacion_por_evento(conn, event_id) if nid else None

            destinatarios = modelo.resolver_correos_destino(
                conn, clasificacion.severidad, clasificacion.tipos
            )
            nid = modelo.registrar_notificacion(
                conn, evento, clasificacion.tipos, clasificacion.severidad,
                estado=modelo.ESTADO_PENDIENTE, destinatarios=destinatarios,
            )
            if nid is None:
                return None  # ya notificado antes (idempotencia por event_id)

            if not destinatarios:
                modelo.actualizar_notificacion(
                    conn, nid, modelo.ESTADO_SIN_DESTINATARIOS, 0,
                    error="Ningún destinatario activo cubre esta severidad/tipo",
                )
            elif self.servicio_correo is None:
                modelo.actualizar_notificacion(
                    conn, nid, modelo.ESTADO_SIN_SERVICIO, 0,
                    error="No hay servicio de correo configurado (AUDIT_SMTP_HOST)",
                )
            else:
                estado, intentos, error = self._enviar_con_reintentos(
                    construir_mensaje(
                        evento, clasificacion, self.url_detalle(event_id),
                        destinatarios, self.servicio_correo.remitente,
                    )
                )
                modelo.actualizar_notificacion(conn, nid, estado, intentos, error=error)
            return modelo.obtener_notificacion_por_evento(conn, event_id)
        finally:
            conn.close()

    def _enviar_con_reintentos(self, mensaje):
        ultimo_error = None
        for intento in range(1, self.max_intentos + 1):
            try:
                self.servicio_correo.enviar(mensaje)
                return modelo.ESTADO_ENVIADA, intento, None
            except ErrorEnvioCorreo as exc:
                ultimo_error = str(exc)
            except Exception as exc:  # cualquier otro fallo del backend
                ultimo_error = f"{type(exc).__name__}: {exc}"
            if intento < self.max_intentos and self.backoff_base_segundos > 0:
                time.sleep(self.backoff_base_segundos * (2 ** (intento - 1)))
        log_internal_error(f"HU-7.2: no se pudo enviar la notificación: {ultimo_error}")
        return modelo.ESTADO_FALLIDA, self.max_intentos, ultimo_error

    def enviar_prueba(self, destinatario: str) -> None:
        """Envía un correo de prueba (síncrono). Lanza ErrorEnvioCorreo si falla."""
        if self.servicio_correo is None:
            raise ErrorEnvioCorreo("No hay servicio de correo configurado")
        self.servicio_correo.enviar(
            construir_mensaje_prueba(destinatario, self.servicio_correo.remitente, self.url_base)
        )


# ──────────────────────────────────────────────────────────────
# Instancia global del proceso
# ──────────────────────────────────────────────────────────────

_despachador: Optional[DespachadorAlertas] = None
_lock = threading.Lock()


def configurar_alertas(
    db_path: str,
    servicio_correo: Optional[ServicioCorreo] = None,
    iniciar_hilo: bool = True,
    **kwargs,
) -> DespachadorAlertas:
    """
    Crea el despachador del proceso, lo engancha a las inserciones de
    audit_log sobre `db_path` y arranca su hilo. Reemplaza uno anterior.
    """
    global _despachador
    with _lock:
        if _despachador is not None:
            desactivar_alertas()
        d = DespachadorAlertas(db_path, servicio_correo=servicio_correo, **kwargs)
        registrar_hook_post_insercion(d.hook_post_insercion)
        if iniciar_hilo:
            d.iniciar()
        _despachador = d
        return d


def desactivar_alertas() -> None:
    global _despachador
    d = _despachador
    if d is not None:
        eliminar_hook_post_insercion(d.hook_post_insercion)
        d.detener(timeout=1.0)
    _despachador = None


def obtener_despachador() -> Optional[DespachadorAlertas]:
    return _despachador
