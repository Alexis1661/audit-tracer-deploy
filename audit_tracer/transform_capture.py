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

Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
"""

import json
import os
import inspect
from datetime import datetime
from typing import Optional

import pandas as pd

from .db import get_connection
from .models.audit_log import insert_event_and_enqueue_sync
from .utils.session import detect_environment, get_hostname

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
        return usuario_id, sesion_id
    except Exception:
        return "DESCONOCIDO", "SIN_SESION"


def _build_contexto() -> str:
    """Construye contexto de ejecución: script, entorno y host."""
    env  = detect_environment()
    host = get_hostname()

    caller_file = "desconocido"
    for frame_info in inspect.stack():
        fname = frame_info.filename
        if (
            fname != __file__
            and "audit_tracer"  not in fname
            and "pandas"        not in fname
            and "<frozen"       not in fname
            and "<string>"      not in fname
        ):
            caller_file = os.path.basename(fname)
            break

    return f"Script: {caller_file} | Env: {env} | Host: {host}"


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

    Args:
        tipo_transformacion: Valor del catálogo (e.g. 'IMPUTACION').
        dataset_nombre:      Nombre del dataset afectado.
        columnas_afectadas:  Lista de columnas impactadas (puede ser vacía).
        descripcion:         Texto descriptivo de la operación concreta.
    """
    usuario_id, sesion_id = _get_session()
    nivel_alerta, motivo_alerta = _determine_alert(usuario_id)

    cols_json = json.dumps(columnas_afectadas) if columnas_afectadas is not None else None

    event = {
        "usuario_id":          usuario_id,                       # CA5
        "sesion_id":           sesion_id,                        # CA5
        "timestamp":           datetime.utcnow().isoformat(),    # CA2
        "tipo_accion":         "TRANSFORMACION",                  # PDGTRAZDSA-61
        "dataset_nombre":      dataset_nombre,
        "columnas_afectadas":  cols_json,                        # CA3
        "contexto_ejecucion":  _build_contexto(),                # CA1 origen_ejecucion
        "motivo_fallo":        descripcion,                      # descripcion_transformacion
        "nivel_alerta":        nivel_alerta,
        "motivo_alerta":       motivo_alerta,
    }

    # Inyectar tipo_transformacion en la descripcion para trazabilidad completa
    desc_completa = f"[{tipo_transformacion}] {descripcion}"
    event["motivo_fallo"] = desc_completa

    try:
        conn = get_connection()
        # CA4: persistencia inmediata e independiente. HU-5.8: se encola
        # para sincronización en la misma operación, igual que data_capture.
        resultado = insert_event_and_enqueue_sync(conn, event)
        try:
            from .sync_client import try_sync_event
            try_sync_event(conn, resultado["event_id"])  # best-effort, nunca lanza
        except Exception:
            pass
        conn.close()
    except Exception as exc:
        print(f"[AuditTracer] Advertencia: no se pudo registrar transformación — {exc}")


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

    @property
    def _constructor(self):
        return AuditedTransformDataFrame

    # ── IMPUTACION: fillna() ──────────────────────────────────
    def fillna(self, value=None, axis=None, inplace=False, limit=None, **kwargs):
        """Intercepta fillna() → tipo_transformacion = IMPUTACION."""

        # Determinar columnas afectadas ANTES de la operación (CA3)
        if isinstance(value, dict):
            cols = list(value.keys())
        else:
            cols = list(self.columns)   # fillna sin dict afecta todas

        result = super().fillna(
            value=value, axis=axis, inplace=inplace, limit=limit, **kwargs
        )

        val_repr = str(value) if not isinstance(value, dict) else f"dict({list(value.keys())})"
        _log_transform(
            tipo_transformacion=TIPO_IMPUTACION,
            dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
            columnas_afectadas=cols,
            descripcion=f"fillna(value={val_repr})",
        )

        if inplace:
            self._dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")
            return None
        if result is not None:
            result._dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")
        return result

    # ── ELIMINACION_FILAS: dropna() ───────────────────────────
    def dropna(self, *, axis=0, how="any", thresh=None,
               subset=None, inplace=False):
        """Intercepta dropna() → tipo_transformacion = ELIMINACION_FILAS."""

        # CA3: solo registrar columnas del subset si se especifica
        cols = list(subset) if subset is not None else list(self.columns)

        # pandas 2.x: how and thresh are mutually exclusive
        kw = dict(axis=axis, subset=subset, inplace=inplace)
        if thresh is not None:
            kw["thresh"] = thresh
        else:
            kw["how"] = how
        result = super().dropna(**kw)

        _log_transform(
            tipo_transformacion=TIPO_ELIMINACION_FILAS,
            dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
            columnas_afectadas=cols,
            descripcion=f"dropna(axis={axis}, how='{how}', subset={subset})",
        )

        if inplace:
            return None
        if result is not None:
            result._dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")
        return result

    # ── ELIMINACION_COLS: drop() ──────────────────────────────
    def drop(self, labels=None, axis=0, index=None, columns=None,
             level=None, inplace=False, errors="raise"):
        """Intercepta drop(columns=...) → tipo_transformacion = ELIMINACION_COLS."""

        # Determinar si es eliminación de columnas o de filas
        is_col_drop = (
            columns is not None
            or (axis == 1)
            or (axis == "columns")
        )

        if is_col_drop:
            cols = list(columns) if columns is not None else (
                [labels] if isinstance(labels, str) else list(labels or [])
            )
            tipo = TIPO_ELIMINACION_COLS
            desc = f"drop(columns={cols})"
        else:
            cols = list(self.columns)
            tipo = TIPO_ELIMINACION_FILAS
            desc = f"drop(labels={labels}, axis={axis})"

        result = super().drop(
            labels=labels, axis=axis, index=index, columns=columns,
            level=level, inplace=inplace, errors=errors
        )

        _log_transform(
            tipo_transformacion=tipo,
            dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
            columnas_afectadas=cols,
            descripcion=desc,
        )

        if inplace:
            return None
        if result is not None:
            result._dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")
        return result

    # ── RENOMBRE: rename() ────────────────────────────────────
    def rename(self, mapper=None, index=None, columns=None,
               axis=None, copy=True, inplace=False,
               level=None, errors="ignore"):
        """Intercepta rename() → tipo_transformacion = RENOMBRE."""

        # CA3: columnas originales y nuevas nombres
        if columns is not None:
            cols_orig = list(columns.keys())
            cols_new  = list(columns.values())
            desc = f"rename(columns={columns})"
        elif mapper is not None and (axis == 1 or axis == "columns"):
            cols_orig = list(self.columns)
            cols_new  = []
            desc = f"rename(mapper=<fn>, axis='columns')"
        else:
            cols_orig = list(self.index[:5]) if self.index is not None else []
            cols_new  = []
            desc = f"rename(index=...)"

        result = super().rename(
            mapper=mapper, index=index, columns=columns,
            axis=axis, copy=copy, inplace=inplace,
            level=level, errors=errors
        )

        afectadas = cols_orig + [f"→{c}" for c in cols_new]

        _log_transform(
            tipo_transformacion=TIPO_RENOMBRE,
            dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
            columnas_afectadas=afectadas,
            descripcion=desc,
        )

        if inplace:
            return None
        if result is not None:
            result._dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")
        return result

    # ── APLICACION / NORMALIZACION: apply() ───────────────────
    def apply(self, func, axis=0, raw=False,
              result_type=None, args=(), **kwargs):
        """
        Intercepta apply().
        - Si func lleva nombre que sugiere normalización → NORMALIZACION
        - En otro caso → APLICACION
        """
        func_name = getattr(func, "__name__", str(func))
        normaliz_keywords = {"normalize", "norm", "scale", "minmax", "zscore", "standard"}
        tipo = (
            TIPO_NORMALIZACION
            if any(kw in func_name.lower() for kw in normaliz_keywords)
            else TIPO_APLICACION
        )

        # CA3: columnas afectadas dependen del eje
        if axis == 1 or axis == "columns":
            cols = list(self.columns)
        else:
            cols = list(self.columns)   # axis=0 aplica función a cada columna

        result = super().apply(func, axis=axis, raw=raw,
                               result_type=result_type, args=args, **kwargs)

        _log_transform(
            tipo_transformacion=tipo,
            dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
            columnas_afectadas=cols,
            descripcion=f"apply(func={func_name}, axis={axis})",
        )

        if isinstance(result, pd.DataFrame):
            result._dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")
        return result

    # ── MERGE: merge() ────────────────────────────────────────
    def merge(self, right, how="inner", on=None, left_on=None,
              right_on=None, left_index=False, right_index=False,
              sort=False, suffixes=("_x", "_y"), copy=True,
              indicator=False, validate=None):
        """Intercepta merge() → tipo_transformacion = MERGE."""

        # CA3: columnas clave del join
        if on is not None:
            cols = [on] if isinstance(on, str) else list(on)
        elif left_on is not None:
            cols = [left_on] if isinstance(left_on, str) else list(left_on)
        else:
            cols = list(self.columns)

        right_name = getattr(right, "_dataset_nombre", "dataset_externo")
        dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")

        result = super().merge(
            right, how=how, on=on, left_on=left_on,
            right_on=right_on, left_index=left_index, right_index=right_index,
            sort=sort, suffixes=suffixes, copy=copy,
            indicator=indicator, validate=validate
        )

        _log_transform(
            tipo_transformacion=TIPO_MERGE,
            dataset_nombre=dataset_nombre,
            columnas_afectadas=cols,
            descripcion=f"merge({dataset_nombre} ⟕ {right_name}, how='{how}', on={cols})",
        )

        result._dataset_nombre = f"merge({dataset_nombre},{right_name})"
        return result


# ──────────────────────────────────────────────────────────────
# INTERCEPTOR GLOBAL: pd.merge()  (PDGTRAZDSA-59)
# ──────────────────────────────────────────────────────────────

_original_pd_merge = None


def _audited_pd_merge(left, right, how="inner", on=None, left_on=None,
                      right_on=None, **kwargs):
    """Versión auditada de pd.merge() para merges entre DataFrames externos."""
    if on is not None:
        cols = [on] if isinstance(on, str) else list(on)
    elif left_on is not None:
        cols = [left_on] if isinstance(left_on, str) else list(left_on)
    else:
        cols = list(left.columns) if hasattr(left, "columns") else []

    left_name  = getattr(left,  "_dataset_nombre", "left_dataset")
    right_name = getattr(right, "_dataset_nombre", "right_dataset")

    result = _original_pd_merge(left, right, how=how, on=on,
                                left_on=left_on, right_on=right_on, **kwargs)

    _log_transform(
        tipo_transformacion=TIPO_MERGE,
        dataset_nombre=left_name,
        columnas_afectadas=cols,
        descripcion=f"pd.merge({left_name} ⟕ {right_name}, how='{how}', on={cols})",
    )

    if isinstance(result, pd.DataFrame):
        result._dataset_nombre = f"merge({left_name},{right_name})"
    return result


# ──────────────────────────────────────────────────────────────
# FUNCIÓN PÚBLICA: wrap_for_transforms
# ──────────────────────────────────────────────────────────────

def wrap_for_transforms(df: pd.DataFrame, dataset_nombre: str) -> AuditedTransformDataFrame:
    """
    Envuelve un DataFrame en AuditedTransformDataFrame para auditar
    todas las transformaciones que se le apliquen.

    Compatible con wrap_dataframe() de HU-2.1: se puede encadenar.

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
    - Las transformaciones sobre DataFrames requieren wrap_for_transforms().
    Idempotente.
    """
    global _transform_interceptor_active, _original_pd_merge

    if _transform_interceptor_active:
        return

    _original_pd_merge = pd.merge
    pd.merge = _audited_pd_merge

    _transform_interceptor_active = True


def deactivate() -> None:
    """Desactiva el interceptor y restaura pd.merge(). Útil en tests."""
    global _transform_interceptor_active, _original_pd_merge

    if not _transform_interceptor_active:
        return

    if _original_pd_merge is not None:
        pd.merge = _original_pd_merge

    _transform_interceptor_active = False
