"""
audit_tracer/data_capture.py
============================
HU-2.1 — Registrar eventos de acceso a datos clínicos
HU-2.4 — Registrar intentos fallidos de acceso a datos clínicos

Intercepta automáticamente operaciones de carga y consulta sobre
DataFrames de pandas, generando registros en audit_log sin intervención
manual del usuario.

Operaciones interceptadas:
  CARGA          → pd.read_csv(), pd.read_excel()
  CONSULTA       → df[columna/s], df.query()
  ACCESO_FALLIDO → FileNotFoundError, PermissionError, OSError, IsADirectoryError

HU-5.1: pd.read_csv()/pd.read_excel() devuelven un AuditedFrame (consulta +
transformación) con el nombre del dataset ya asignado, así que no hace
falta envolver nada a mano. Toda la lógica de auditoría corre dentro de
guard(): si falla, la operación de pandas sigue y el error queda en el log
de errores del sistema. Las excepciones propias del usuario (archivo
inexistente, columna inexistente, ...) le llegan intactas.

Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
"""

import os
import json
from datetime import datetime
from typing import Optional

import pandas as pd

from .db import get_connection
from .models.audit_log import insert_event_and_enqueue_sync
from .utils.contexto import build_contexto
from .utils.error_log import guard, log_internal_error, in_audit_scope, audit_scope
from .failed_access import log_failed_access, ACCESS_FAILURE_EXCEPTIONS   # HU-2.4
from .transform_capture import AuditedTransformDataFrame                 # HU-2.2
from .utils.horario import es_horario_laboral, HORA_INICIO_LABORAL, HORA_FIN_LABORAL  # HU-4.4
from .utils.zona_horaria import a_hora_colombia, ETIQUETA_ZONA


# ──────────────────────────────────────────────────────────────
# ESTADO GLOBAL DEL INTERCEPTOR
# ──────────────────────────────────────────────────────────────

_interceptor_active = False   # evita doble-parcheo si se llama init dos veces
_original_read_csv = None
_original_read_excel = None


# ──────────────────────────────────────────────────────────────
# HELPERS INTERNOS
# ──────────────────────────────────────────────────────────────

def _get_session() -> tuple[str, str]:
    """
    Obtiene (usuario_id, sesion_id) desde SessionTracker si está activo.
    Si no puede identificar al usuario devuelve 'DESCONOCIDO' (CA3).

    Returns:
        tuple[str, str]: (usuario_id, sesion_id)
    """
    try:
        from .session_tracker import SessionTracker
        tracker = SessionTracker.get_instance()
        usuario_id = tracker.usuario_id or "DESCONOCIDO"
        sesion_id = tracker.sesion_id
        if usuario_id == "DESCONOCIDO":
            tracker.remind_if_unidentified()
        return usuario_id, sesion_id
    except Exception:
        return "DESCONOCIDO", "SIN_SESION"


def _build_contexto() -> str:
    """
    Construye el campo contexto_ejecucion con script/notebook y entorno.
    """
    return build_contexto()


def _resolve_dataset_nombre(filepath, default: str = "dataset_desconocido") -> str:
    """
    Extrae el nombre del archivo desde una ruta (str o PathLike).

    Args:
        filepath: Ruta al archivo (puede ser None o un buffer).
        default:  Valor por defecto si no se puede extraer.

    Returns:
        str: Nombre del archivo (e.g. 'PATIENTS.csv').
    """
    if isinstance(filepath, os.PathLike):
        filepath = os.fspath(filepath)
    if filepath and isinstance(filepath, str):
        return os.path.basename(filepath)
    return default


def _determine_alert(usuario_id: str, ahora: datetime) -> tuple[str, Optional[str]]:
    """
    Determina el nivel de alerta y su motivo.

    CA3 (HU-2.1): si usuario_id == DESCONOCIDO → nivel_alerta = CRITICO.
    CA1-c (HU-4.4): acceso a datos fuera del horario laboral configurado
    → nivel_alerta = CRITICO.

    Returns:
        tuple[str, str | None]: (nivel_alerta, motivo_alerta)
    """
    if usuario_id == "DESCONOCIDO":
        return "CRITICO", "Operación ejecutada por usuario no identificado"
    if not es_horario_laboral(ahora):
        return "CRITICO", (
            f"Acceso fuera de horario laboral "
            f"({HORA_INICIO_LABORAL:02d}:00-{HORA_FIN_LABORAL:02d}:00 {ETIQUETA_ZONA}): "
            f"{a_hora_colombia(ahora).strftime('%H:%M')}"
        )
    return "NORMAL", None


def _log_event(
    tipo_accion: str,
    dataset_nombre: str,
    columnas_afectadas: Optional[str] = None,
) -> None:
    """
    Construye y persiste un registro en audit_log (CA1, CA2, CA4, CA5).

    Args:
        tipo_accion:        'CARGA' o 'CONSULTA'.
        dataset_nombre:     Nombre del dataset afectado.
        columnas_afectadas: Lista de columnas como JSON string (opcional).

    HU-5.1 CA4: nunca lanza; cualquier fallo va al log de errores del sistema.
    """
    try:
        usuario_id, sesion_id = _get_session()
        ahora = datetime.utcnow()
        nivel_alerta, motivo_alerta = _determine_alert(usuario_id, ahora)

        event = {
            "usuario_id": usuario_id,                       # CA1, CA3
            "sesion_id": sesion_id,                          # CA5
            "timestamp": ahora.isoformat(),                  # CA1
            "tipo_accion": tipo_accion,                      # CA1
            "dataset_nombre": dataset_nombre,                # CA1
            "columnas_afectadas": columnas_afectadas,
            "contexto_ejecucion": _build_contexto(),
            "nivel_alerta": nivel_alerta,                    # CA3
            "motivo_alerta": motivo_alerta,                  # CA3
        }

        conn = get_connection()
        # CA4: persistencia inmediata. HU-5.8 CA1: se encola para
        # sincronización en la misma operación — el envío HTTP, si se
        # intenta, siempre sucede DESPUÉS de este insert, nunca antes.
        try:
            insert_event_and_enqueue_sync(conn, event)
        finally:
            conn.close()
        # HU-5.1 CA4: el envío ocurre en el hilo de fondo, nunca aquí.
        from .sync_client import schedule_sync
        schedule_sync()
    except Exception as exc:
        # No interrumpir la operación del usuario si falla la auditoría
        log_internal_error(f"No se pudo registrar evento {tipo_accion}", exc)


# ──────────────────────────────────────────────────────────────
# INTERCEPTORES DE CARGA  (PDGTRAZDSA-50)
# ──────────────────────────────────────────────────────────────

def _registrar_carga(resultado, dataset_nombre: str):
    """
    Registra CARGA y devuelve el resultado envuelto en AuditedFrame
    (HU-5.1). read_csv puede devolver un iterador (chunksize/iterator) y
    read_excel un dict por hoja (sheet_name=None): se respetan tal cual.
    """
    if isinstance(resultado, pd.DataFrame):
        _log_event(
            tipo_accion="CARGA",
            dataset_nombre=dataset_nombre,
            columnas_afectadas=json.dumps([str(c) for c in resultado.columns]),
        )
        return wrap_audited(resultado, dataset_nombre)
    if isinstance(resultado, dict):
        envueltos = {}
        for hoja, df in resultado.items():
            nombre = f"{dataset_nombre}[{hoja}]"
            _log_event(
                tipo_accion="CARGA",
                dataset_nombre=nombre,
                columnas_afectadas=json.dumps([str(c) for c in df.columns]),
            )
            envueltos[hoja] = wrap_audited(df, nombre)
        return envueltos
    _log_event(tipo_accion="CARGA", dataset_nombre=dataset_nombre)
    return resultado


def _audited_read(original, fuente, default_nombre: str, args, kwargs):
    """
    Núcleo común de read_csv/read_excel auditados.

    La llamada original va FUERA de guard(): sus excepciones son del
    usuario y le llegan intactas (HU-5.1 CA4). Solo la auditoría va
    dentro de guard().
    """
    if in_audit_scope():
        return original(fuente, *args, **kwargs)

    dataset_nombre = guard(
        _resolve_dataset_nombre, fuente, default=default_nombre,
        _default=default_nombre,
    )
    try:
        with audit_scope():
            resultado = original(fuente, *args, **kwargs)
    except ACCESS_FAILURE_EXCEPTIONS as exc:
        # HU-2.4 CA1: registrar fallo y relanzar la excepción
        guard(log_failed_access, dataset_nombre=dataset_nombre, exc=exc,
              _contexto="Registro de ACCESO_FALLIDO")
        raise

    return guard(_registrar_carga, resultado, dataset_nombre,
                 _contexto="Registro de CARGA", _default=resultado)


def _audited_read_csv(filepath_or_buffer=None, *args, **kwargs) -> pd.DataFrame:
    """
    Reemplazo auditado de pd.read_csv().
    Registra tipo_accion = 'CARGA' en caso de éxito.
    Registra tipo_accion = 'ACCESO_FALLIDO' si ocurre un error de acceso (HU-2.4).
    """
    return _audited_read(_original_read_csv, filepath_or_buffer, "buffer_csv", args, kwargs)


def _audited_read_excel(io=None, *args, **kwargs) -> pd.DataFrame:
    """
    Reemplazo auditado de pd.read_excel().
    Registra tipo_accion = 'CARGA' en caso de éxito.
    Registra tipo_accion = 'ACCESO_FALLIDO' si ocurre un error de acceso (HU-2.4).
    """
    return _audited_read(_original_read_excel, io, "buffer_excel", args, kwargs)


# ──────────────────────────────────────────────────────────────
# INTERCEPTORES DE CONSULTA  (PDGTRAZDSA-51)
# ──────────────────────────────────────────────────────────────

class AuditedDataFrame(pd.DataFrame):
    """
    Subclase de DataFrame que intercepta operaciones de consulta.

    Se utiliza para registrar:
      - df[columna]     → __getitem__
      - df.query(expr)  → query()

    El nombre del dataset se almacena en el atributo `_dataset_nombre`.
    """

    # HU-5.1: _metadata hace que pandas propague _dataset_nombre a los
    # DataFrames derivados (copias, filtros, resultados de transformaciones).
    _metadata = ["_dataset_nombre"]

    # Necesario para que pandas conserve la subclase al hacer operaciones
    @property
    def _constructor(self):
        return AuditedDataFrame

    # ── df[key] ──────────────────────────────────────────────
    def __getitem__(self, key):
        if in_audit_scope():
            return super().__getitem__(key)
        with audit_scope():
            result = super().__getitem__(key)
        guard(self._registrar_getitem, key, _contexto="Registro de CONSULTA df[...]")
        return result

    def _registrar_getitem(self, key) -> None:
        dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")

        # Determinar columnas accedidas
        if isinstance(key, str):
            cols = [key]
        elif isinstance(key, (list, pd.Index)):
            cols = [c for c in key if isinstance(c, str)]
        else:
            cols = []

        if cols:                        # solo auditar accesos a columnas concretas
            _log_event(
                tipo_accion="CONSULTA",
                dataset_nombre=dataset_nombre,
                columnas_afectadas=json.dumps(cols),
            )

    # ── df.query() ────────────────────────────────────────────
    def query(self, expr, **kwargs):
        if in_audit_scope():
            return super().query(expr, **kwargs)
        with audit_scope():
            result = super().query(expr, **kwargs)
        guard(self._registrar_query, expr, _contexto="Registro de CONSULTA df.query()")
        return result

    def _registrar_query(self, expr) -> None:
        dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")

        # Intentar extraer columnas referenciadas en la expresión
        cols = _extract_columns_from_expr(expr, self.columns)

        _log_event(
            tipo_accion="CONSULTA",
            dataset_nombre=dataset_nombre,
            columnas_afectadas=json.dumps(cols) if cols else expr,
        )


class AuditedFrame(AuditedDataFrame, AuditedTransformDataFrame):
    """
    HU-5.1 — DataFrame auditado completo: consultas (HU-2.1) y
    transformaciones (HU-2.2) en el mismo objeto. Es lo que devuelven
    pd.read_csv()/pd.read_excel() con audit_tracer importado, y se conserva
    en los DataFrames derivados (copias, filtros, resultados de fillna, ...).
    """

    _metadata = ["_dataset_nombre"]

    @property
    def _constructor(self):
        return AuditedFrame


def wrap_audited(df: pd.DataFrame, dataset_nombre: str) -> AuditedFrame:
    """Envuelve `df` en AuditedFrame con el nombre de dataset indicado."""
    audited = AuditedFrame(df)
    audited._dataset_nombre = dataset_nombre
    return audited


def _extract_columns_from_expr(expr: str, df_columns) -> list:
    """
    Extrae nombres de columnas del DataFrame que aparecen en una expresión query.

    Args:
        expr:       Expresión de pandas query (e.g. 'age > 30 and diagnosis == "sepsis"').
        df_columns: Columnas disponibles en el DataFrame.

    Returns:
        list: Columnas encontradas en la expresión.
    """
    found = []
    for col in df_columns:
        if str(col) in expr:
            found.append(str(col))
    return found


def wrap_dataframe(df: pd.DataFrame, dataset_nombre: str) -> AuditedDataFrame:
    """
    Convierte un DataFrame ordinario en AuditedDataFrame, preservando datos y nombre.

    Uso manual (opcional, para DataFrames no cargados con read_csv/read_excel):

        from audit_tracer.data_capture import wrap_dataframe
        df = wrap_dataframe(df, "mi_dataset.csv")

    HU-5.1: ya no hace falta para DataFrames cargados con read_csv/read_excel
    (vienen auditados). Si `df` ya es un AuditedFrame, solo cambia el nombre
    y conserva también la auditoría de transformaciones.

    Args:
        df:              DataFrame a envolver.
        dataset_nombre:  Nombre descriptivo del dataset.

    Returns:
        AuditedDataFrame listo para auditar consultas.
    """
    if isinstance(df, AuditedFrame):
        return wrap_audited(df, dataset_nombre)
    audited = AuditedDataFrame(df)
    audited._dataset_nombre = dataset_nombre
    return audited


# ──────────────────────────────────────────────────────────────
# ACTIVACIÓN / DESACTIVACIÓN DEL INTERCEPTOR
# ──────────────────────────────────────────────────────────────

def _unwrap(fn):
    """Función original de pandas detrás de un parche de audit_tracer (o `fn`)."""
    return getattr(fn, "_audit_tracer_original", fn)


def activate() -> None:
    """
    Activa el interceptor: reemplaza pd.read_csv y pd.read_excel con
    versiones auditadas.

    Idempotente: llamadas adicionales no tienen efecto. HU-5.1: también
    tras importlib.reload() / %autoreload — el original se recupera desde
    la marca que deja cada parche, así nunca se parchea encima de un parche.
    """
    global _interceptor_active, _original_read_csv, _original_read_excel

    # Guardar referencias originales (PDGTRAZDSA-50)
    _original_read_csv = _unwrap(pd.read_csv)
    _original_read_excel = _unwrap(pd.read_excel)
    _audited_read_csv._audit_tracer_original = _original_read_csv
    _audited_read_excel._audit_tracer_original = _original_read_excel

    # Parchear las funciones globales de pandas
    pd.read_csv = _audited_read_csv
    pd.read_excel = _audited_read_excel

    # Parchear también en el namespace del módulo pandas (para imports previos)
    import pandas.io.parsers as _parsers          # noqa: F401
    pd.io.parsers.readers.read_csv = _audited_read_csv

    _interceptor_active = True


def deactivate() -> None:
    """
    Desactiva el interceptor y restaura las funciones originales de pandas.
    Útil principalmente en tests.

    HU-5.1: desactivar queda registrado como evento CRITICO
    AUDITORIA_DESACTIVADA — apagar la captura no puede pasar sin rastro.
    """
    global _interceptor_active

    if not _interceptor_active:
        return

    pd.read_csv = _unwrap(pd.read_csv)
    pd.read_excel = _unwrap(pd.read_excel)
    pd.io.parsers.readers.read_csv = _unwrap(pd.io.parsers.readers.read_csv)

    _interceptor_active = False
    log_deactivation("data_capture (read_csv, read_excel)", get_connection)


def log_deactivation(interceptor: str, conn_factory) -> None:
    """Registra AUDITORIA_DESACTIVADA (nivel CRITICO). Nunca lanza."""
    try:
        usuario_id, sesion_id = _get_session()
        conn = conn_factory()
        try:
            insert_event_and_enqueue_sync(conn, {
                "usuario_id": usuario_id,
                "sesion_id": sesion_id,
                "timestamp": datetime.utcnow().isoformat(),
                "tipo_accion": "AUDITORIA_DESACTIVADA",
                "contexto_ejecucion": _build_contexto(),
                "nivel_alerta": "CRITICO",
                "motivo_alerta": f"Se desactivó el interceptor {interceptor}",
            })
        finally:
            conn.close()
    except Exception as exc:
        log_internal_error(f"No se pudo registrar AUDITORIA_DESACTIVADA ({interceptor})", exc)
