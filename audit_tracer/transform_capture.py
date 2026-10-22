"""
audit_tracer/transform_capture.py
==================================
HU-2.2 — Registrar eventos de modificación y transformación de datos

Intercepta automáticamente operaciones de transformación sobre DataFrames
de pandas, generando registros en audit_log con tipo_accion = TRANSFORMACION
sin intervención manual del usuario.

Catálogo de tipos de transformación interceptados (PDGTRAZDSA-58):
  ┌─────────────────────┬──────────────────────────────────────────────┐
  │ tipo_transformacion │ Operaciones pandas                           │
  ├─────────────────────┼──────────────────────────────────────────────┤
  │ FILTRADO            │ df.query(), df[mask_booleana]                │
  │ IMPUTACION          │ df.fillna()                                  │
  │ ELIMINACION_FILAS   │ df.dropna()                                  │
  │ ELIMINACION_COLS    │ df.drop(columns=...)                         │
  │ RENOMBRE            │ df.rename()                                  │
  │ APLICACION          │ df.apply()                                   │
  │ MERGE               │ df.merge() / pd.merge()                      │
  │ NORMALIZACION       │ df.apply() con funciones min-max / z-score   │
  └─────────────────────┴──────────────────────────────────────────────┘

tipo_accion siempre = TRANSFORMACION  (PDGTRAZDSA-61)

HU-5.1: los métodos interceptados aceptan exactamente la misma firma que
pandas (*args/**kwargs pasados tal cual) y la auditoría corre dentro de
guard(): un fallo interno nunca cambia ni interrumpe la operación del
usuario, y sus propios errores (columna inexistente, ...) le llegan
intactos. Los DataFrames cargados con pd.read_csv()/pd.read_excel() ya
traen esta auditoría (ver data_capture.AuditedFrame).

Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
"""

import json
from datetime import datetime
from typing import Optional

import pandas as pd

from .db import get_connection
from .models.audit_log import insert_event_and_enqueue_sync
from .utils.contexto import build_contexto
from .utils.error_log import guard, log_internal_error, in_audit_scope, audit_scope

# ──────────────────────────────────────────────────────────────
# CATÁLOGO DE TIPOS DE TRANSFORMACIÓN  (PDGTRAZDSA-58)
# ──────────────────────────────────────────────────────────────

TIPO_FILTRADO           = "FILTRADO"
TIPO_IMPUTACION         = "IMPUTACION"
TIPO_ELIMINACION_FILAS  = "ELIMINACION_FILAS"
TIPO_ELIMINACION_COLS   = "ELIMINACION_COLS"
TIPO_RENOMBRE           = "RENOMBRE"
TIPO_APLICACION         = "APLICACION"
TIPO_MERGE              = "MERGE"
TIPO_NORMALIZACION      = "NORMALIZACION"

TIPOS_VALIDOS = {
    TIPO_FILTRADO, TIPO_IMPUTACION, TIPO_ELIMINACION_FILAS,
    TIPO_ELIMINACION_COLS, TIPO_RENOMBRE, TIPO_APLICACION,
    TIPO_MERGE, TIPO_NORMALIZACION,
}

# ──────────────────────────────────────────────────────────────
# ESTADO GLOBAL DEL INTERCEPTOR
# ──────────────────────────────────────────────────────────────

_transform_interceptor_active = False


# ──────────────────────────────────────────────────────────────
# HELPERS INTERNOS
# ──────────────────────────────────────────────────────────────

def _get_session() -> tuple[str, str]:
    """
    Obtiene (usuario_id, sesion_id) desde SessionTracker.
    Retorna 'DESCONOCIDO' si no hay sesión activa.
    """
    try:
        from .session_tracker import SessionTracker
        tracker = SessionTracker.get_instance()
        usuario_id = tracker.usuario_id or "DESCONOCIDO"
        sesion_id  = tracker.sesion_id
        if usuario_id == "DESCONOCIDO":
            tracker.remind_if_unidentified()
        return usuario_id, sesion_id
    except Exception:
        return "DESCONOCIDO", "SIN_SESION"


def _build_contexto() -> str:
    """Construye contexto de ejecución: script, entorno y host."""
    return build_contexto()


def _determine_alert(usuario_id: str) -> tuple[str, Optional[str]]:
    if usuario_id == "DESCONOCIDO":
        return "CRITICO", "Transformación ejecutada por usuario no identificado"
    return "NORMAL", None


def _log_transform(
    tipo_transformacion: str,
    dataset_nombre: str,
    columnas_afectadas: Optional[list],
    descripcion: str,
) -> None:
    """
    Persiste un registro de transformación en audit_log.

    CA1: incluye tipo_transformacion, columnas_afectadas, origen_ejecucion.
    CA2: timestamp generado en el momento exacto de la operación.
    CA3: solo las columnas involucradas, no el dataset completo.
    CA4: un registro por transformación.
    CA5: incluye usuario_id y sesion_id.

    HU-5.1 CA4: nunca lanza; cualquier fallo va al log de errores del sistema.

    Args:
        tipo_transformacion: Valor del catálogo (e.g. 'IMPUTACION').
        dataset_nombre:      Nombre del dataset afectado.
        columnas_afectadas:  Lista de columnas impactadas (puede ser vacía).
        descripcion:         Texto descriptivo de la operación concreta.
    """
    try:
        usuario_id, sesion_id = _get_session()
        nivel_alerta, motivo_alerta = _determine_alert(usuario_id)

        cols_json = json.dumps(columnas_afectadas, default=str) if columnas_afectadas is not None else None

        event = {
            "usuario_id":          usuario_id,                       # CA5
            "sesion_id":           sesion_id,                        # CA5
            "timestamp":           datetime.utcnow().isoformat(),    # CA2
            "tipo_accion":         "TRANSFORMACION",                  # PDGTRAZDSA-61
            "dataset_nombre":      dataset_nombre,
            "columnas_afectadas":  cols_json,                        # CA3
            "contexto_ejecucion":  _build_contexto(),                # CA1 origen_ejecucion
            "nivel_alerta":        nivel_alerta,
            "motivo_alerta":       motivo_alerta,
        }

        # Inyectar tipo_transformacion en la descripcion para trazabilidad completa
        event["motivo_fallo"] = f"[{tipo_transformacion}] {descripcion}"

        conn = get_connection()
        # CA4: persistencia inmediata e independiente. HU-5.8: se encola
        # para sincronización en la misma operación, igual que data_capture.
        try:
            insert_event_and_enqueue_sync(conn, event)
        finally:
            conn.close()
        # HU-5.1 CA4: el envío ocurre en el hilo de fondo, nunca aquí.
        from .sync_client import schedule_sync
        schedule_sync()
    except Exception as exc:
        log_internal_error(f"No se pudo registrar transformación {tipo_transformacion}", exc)


def _arg(args: tuple, kwargs: dict, pos: int, name: str, default=None):
    """Valor de un parámetro de pandas pasado por posición o por nombre."""
    if name in kwargs:
        return kwargs[name]
    if pos is not None and len(args) > pos:
        return args[pos]
    return default


def _as_list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    try:
        return list(value)
    except TypeError:
        return [value]


def _nombre(df) -> str:
    return getattr(df, "_dataset_nombre", "dataset_desconocido")


# ── Descripciones por operación (solo lectura de argumentos) ───────────

def _describe_fillna(df, args, kwargs):
    value = _arg(args, kwargs, 0, "value")
    if isinstance(value, dict):
        cols = list(value.keys())
        val_repr = f"dict({list(value.keys())})"
    else:
        cols = list(df.columns)   # fillna sin dict afecta todas
        val_repr = str(value)
    return TIPO_IMPUTACION, cols, f"fillna(value={val_repr})"


def _describe_dropna(df, args, kwargs):
    axis = kwargs.get("axis", 0)
    how = kwargs.get("how", "any")
    subset = kwargs.get("subset")
    # CA3: solo registrar columnas del subset si se especifica
    cols = _as_list(subset) if subset is not None else list(df.columns)
    return TIPO_ELIMINACION_FILAS, cols, f"dropna(axis={axis}, how='{how}', subset={subset})"


def _describe_drop(df, args, kwargs):
    labels = _arg(args, kwargs, 0, "labels")
    axis = kwargs.get("axis", 0)
    columns = kwargs.get("columns")
    # Determinar si es eliminación de columnas o de filas
    if columns is not None or axis in (1, "columns"):
        cols = _as_list(columns) if columns is not None else _as_list(labels)
        return TIPO_ELIMINACION_COLS, cols, f"drop(columns={cols})"
    return TIPO_ELIMINACION_FILAS, list(df.columns), f"drop(labels={labels}, axis={axis})"


def _describe_rename(df, args, kwargs):
    mapper = _arg(args, kwargs, 0, "mapper")
    columns = kwargs.get("columns")
    axis = kwargs.get("axis")
    # CA3: columnas originales y nuevas nombres
    if isinstance(columns, dict):
        cols_orig, cols_new = list(columns.keys()), list(columns.values())
        desc = f"rename(columns={columns})"
    elif columns is not None or (mapper is not None and axis in (1, "columns")):
        cols_orig, cols_new = list(df.columns), []
        desc = "rename(mapper=<fn>, axis='columns')"
    else:
        cols_orig, cols_new = list(df.index[:5]), []
        desc = "rename(index=...)"
    return TIPO_RENOMBRE, cols_orig + [f"→{c}" for c in cols_new], desc


_NORMALIZ_KEYWORDS = {"normalize", "norm", "scale", "minmax", "zscore", "standard"}


def _describe_apply(df, args, kwargs):
    func = _arg(args, kwargs, 0, "func")
    axis = _arg(args, kwargs, 1, "axis", 0)
    func_name = getattr(func, "__name__", str(func))
    tipo = (
        TIPO_NORMALIZACION
        if any(kw in func_name.lower() for kw in _NORMALIZ_KEYWORDS)
        else TIPO_APLICACION
    )
    return tipo, list(df.columns), f"apply(func={func_name}, axis={axis})"


def _merge_keys(left, on, left_on) -> list:
    # CA3: columnas clave del join
    if on is not None:
        return _as_list(on)
    if left_on is not None:
        return _as_list(left_on)
    return list(left.columns) if hasattr(left, "columns") else []


def _describe_merge(df, args, kwargs):
    right = _arg(args, kwargs, 0, "right")
    how = _arg(args, kwargs, 1, "how", "inner")
    cols = _merge_keys(df, _arg(args, kwargs, 2, "on"), _arg(args, kwargs, 3, "left_on"))
    right_name = getattr(right, "_dataset_nombre", "dataset_externo")
    return TIPO_MERGE, cols, f"merge({_nombre(df)} ⟕ {right_name}, how='{how}', on={cols})"


# ──────────────────────────────────────────────────────────────
# CLASE AuditedTransformDataFrame
# Subclase que intercepta todas las transformaciones (PDGTRAZDSA-59)
# ──────────────────────────────────────────────────────────────

class AuditedTransformDataFrame(pd.DataFrame):
    """
    Subclase de pd.DataFrame que intercepta operaciones de transformación
    y las registra automáticamente en audit_log.

    Atributos internos:
        _dataset_nombre (str): Nombre del dataset para los registros.
    """

    # HU-5.1: pandas propaga _dataset_nombre a los DataFrames resultantes.
    _metadata = ["_dataset_nombre"]

    @property
    def _constructor(self):
        return AuditedTransformDataFrame

    def _audited_call(self, operacion, describe, args, kwargs):
        """
        Ejecuta la operación original de pandas (fuera de guard: sus
        errores son del usuario) y registra la transformación (dentro de
        guard: los errores de auditoría nunca llegan al usuario).
        """
        # pd.DataFrame directo (no super(Clase, self)): tras importlib.reload
        # el nombre de la clase apunta a la clase nueva y super() fallaría
        # sobre objetos creados con la anterior.
        original = getattr(pd.DataFrame, operacion)
        if in_audit_scope():
            return original(self, *args, **kwargs)
        info = guard(describe, self, args, kwargs, _contexto=f"Descripción de {operacion}()")
        nombre = _nombre(self)
        with audit_scope():
            result = original(self, *args, **kwargs)
        if info is not None:
            tipo, cols, desc = info
            guard(_log_transform, tipo_transformacion=tipo, dataset_nombre=nombre,
                  columnas_afectadas=cols, descripcion=desc,
                  _contexto=f"Registro de TRANSFORMACION {operacion}()")
        return result

    # ── IMPUTACION: fillna() ──────────────────────────────────
    def fillna(self, *args, **kwargs):
        """Intercepta fillna() → tipo_transformacion = IMPUTACION."""
        return self._audited_call("fillna", _describe_fillna, args, kwargs)

    # ── ELIMINACION_FILAS: dropna() ───────────────────────────
    def dropna(self, *args, **kwargs):
        """Intercepta dropna() → tipo_transformacion = ELIMINACION_FILAS."""
        return self._audited_call("dropna", _describe_dropna, args, kwargs)

    # ── ELIMINACION_COLS: drop() ──────────────────────────────
    def drop(self, *args, **kwargs):
        """Intercepta drop(columns=...) → tipo_transformacion = ELIMINACION_COLS."""
        return self._audited_call("drop", _describe_drop, args, kwargs)

    # ── RENOMBRE: rename() ────────────────────────────────────
    def rename(self, *args, **kwargs):
        """Intercepta rename() → tipo_transformacion = RENOMBRE."""
        return self._audited_call("rename", _describe_rename, args, kwargs)

    # ── APLICACION / NORMALIZACION: apply() ───────────────────
    def apply(self, *args, **kwargs):
        """
        Intercepta apply().
        - Si func lleva nombre que sugiere normalización → NORMALIZACION
        - En otro caso → APLICACION
        """
        return self._audited_call("apply", _describe_apply, args, kwargs)

    # ── MERGE: merge() ────────────────────────────────────────
    def merge(self, *args, **kwargs):
        """Intercepta merge() → tipo_transformacion = MERGE."""
        right = _arg(args, kwargs, 0, "right")
        result = self._audited_call("merge", _describe_merge, args, kwargs)
        if isinstance(result, pd.DataFrame):
            right_name = getattr(right, "_dataset_nombre", "dataset_externo")
            guard(object.__setattr__, result, "_dataset_nombre",
                  f"merge({_nombre(self)},{right_name})")
        return result


# ──────────────────────────────────────────────────────────────
# INTERCEPTOR GLOBAL: pd.merge()  (PDGTRAZDSA-59)
# ──────────────────────────────────────────────────────────────

_original_pd_merge = None


def _audited_pd_merge(left, right, *args, **kwargs):
    """Versión auditada de pd.merge() para merges entre DataFrames externos."""
    original = _original_pd_merge
    if in_audit_scope():
        return original(left, right, *args, **kwargs)

    def _describe():
        how = _arg(args, kwargs, 0, "how", "inner")
        cols = _merge_keys(left, _arg(args, kwargs, 1, "on"), _arg(args, kwargs, 2, "left_on"))
        left_name = getattr(left, "_dataset_nombre", "left_dataset")
        right_name = getattr(right, "_dataset_nombre", "right_dataset")
        desc = f"pd.merge({left_name} ⟕ {right_name}, how='{how}', on={cols})"
        return left_name, right_name, cols, desc

    info = guard(_describe, _contexto="Descripción de pd.merge()")
    with audit_scope():
        result = original(left, right, *args, **kwargs)

    if info is not None:
        left_name, right_name, cols, desc = info
        guard(_log_transform, tipo_transformacion=TIPO_MERGE, dataset_nombre=left_name,
              columnas_afectadas=cols, descripcion=desc,
              _contexto="Registro de TRANSFORMACION pd.merge()")
        if isinstance(result, pd.DataFrame):
            guard(object.__setattr__, result, "_dataset_nombre",
                  f"merge({left_name},{right_name})")
    return result


# ──────────────────────────────────────────────────────────────
# FUNCIÓN PÚBLICA: wrap_for_transforms
# ──────────────────────────────────────────────────────────────

def wrap_for_transforms(df: pd.DataFrame, dataset_nombre: str) -> AuditedTransformDataFrame:
    """
    Envuelve un DataFrame en AuditedTransformDataFrame para auditar
    todas las transformaciones que se le apliquen.

    HU-5.1: ya no es necesario para DataFrames cargados con
    read_csv/read_excel (vienen auditados). Se mantiene por compatibilidad
    y para DataFrames construidos a mano. Si `df` ya es un AuditedFrame,
    solo le cambia el nombre (no pierde la auditoría de consultas).

    Uso:
        df = pd.read_csv("PATIENTS.csv")
        df = wrap_for_transforms(df, "PATIENTS.csv")
        df.fillna(0)        # → genera evento TRANSFORMACION / IMPUTACION
        df.dropna()         # → genera evento TRANSFORMACION / ELIMINACION_FILAS

    Args:
        df:              DataFrame original.
        dataset_nombre:  Nombre descriptivo del dataset (e.g. 'PATIENTS.csv').

    Returns:
        AuditedTransformDataFrame con auditoría de transformaciones activa.
    """
    from .data_capture import AuditedFrame, wrap_audited
    if isinstance(df, AuditedFrame):
        return wrap_audited(df, dataset_nombre)
    audited = AuditedTransformDataFrame(df)
    audited._dataset_nombre = dataset_nombre
    return audited


# ──────────────────────────────────────────────────────────────
# ACTIVACIÓN / DESACTIVACIÓN
# ──────────────────────────────────────────────────────────────

def activate() -> None:
    """
    Activa el interceptor de transformaciones.
    - Parchea pd.merge() globalmente.
    - Las transformaciones sobre DataFrames cargados con read_csv/read_excel
      se auditan solas (HU-5.1); para DataFrames construidos a mano,
      wrap_for_transforms().
    Idempotente, también tras importlib.reload() (HU-5.1).
    """
    global _transform_interceptor_active, _original_pd_merge

    _original_pd_merge = getattr(pd.merge, "_audit_tracer_original", pd.merge)
    _audited_pd_merge._audit_tracer_original = _original_pd_merge
    pd.merge = _audited_pd_merge

    _transform_interceptor_active = True


def deactivate() -> None:
    """
    Desactiva el interceptor y restaura pd.merge(). Útil en tests.
    HU-5.1: queda registrado como evento CRITICO AUDITORIA_DESACTIVADA.
    """
    global _transform_interceptor_active

    if not _transform_interceptor_active:
        return

    pd.merge = getattr(pd.merge, "_audit_tracer_original", pd.merge)

    _transform_interceptor_active = False
    from .data_capture import log_deactivation
    log_deactivation("transform_capture (pd.merge)", get_connection)
