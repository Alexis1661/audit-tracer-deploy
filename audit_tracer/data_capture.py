"""
audit_tracer/data_capture.py
============================
HU-2.1 — Registrar eventos de acceso a datos clínicos

Intercepta automáticamente operaciones de carga y consulta sobre
DataFrames de pandas, generando registros en audit_log sin intervención
manual del usuario.

Operaciones interceptadas:
  CARGA    → pd.read_csv(), pd.read_excel()
  CONSULTA → df[columna/s], df.query()

Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
"""

import os
import json
import inspect
import functools
from datetime import datetime
from typing import Optional

import pandas as pd

from .db import get_connection
from .models.audit_log import insert_event
from .utils.session import detect_environment, get_hostname


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
        return usuario_id, sesion_id
    except Exception:
        return "DESCONOCIDO", "SIN_SESION"


def _build_contexto() -> str:
    """
    Construye el campo contexto_ejecucion con script/notebook y entorno.
    """
    env = detect_environment()
    host = get_hostname()

    # Intentar identificar el script o notebook que llamó la función
    caller_file = "desconocido"
    stack = inspect.stack()
    for frame_info in stack:
        filename = frame_info.filename
        # Saltar frames internos de este módulo, pandas y stdlib
        if (
            filename != __file__
            and "audit_tracer" not in filename
            and "pandas" not in filename
            and "<frozen" not in filename
        ):
            caller_file = os.path.basename(filename)
            break

    return f"Script: {caller_file} | Env: {env} | Host: {host}"


def _resolve_dataset_nombre(filepath: Optional[str], default: str = "dataset_desconocido") -> str:
    """
    Extrae el nombre del archivo desde una ruta.

    Args:
        filepath: Ruta al archivo (puede ser None).
        default:  Valor por defecto si no se puede extraer.

    Returns:
        str: Nombre del archivo (e.g. 'PATIENTS.csv').
    """
    if filepath and isinstance(filepath, str):
        return os.path.basename(filepath)
    return default


def _determine_alert(usuario_id: str) -> tuple[str, Optional[str]]:
    """
    Determina el nivel de alerta y su motivo.

    CA3: si usuario_id == DESCONOCIDO → nivel_alerta = CRITICO, flag_alerta = True.

    Returns:
        tuple[str, str | None]: (nivel_alerta, motivo_alerta)
    """
    if usuario_id == "DESCONOCIDO":
        return "CRITICO", "Operación ejecutada por usuario no identificado"
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
    """
    usuario_id, sesion_id = _get_session()
    nivel_alerta, motivo_alerta = _determine_alert(usuario_id)

    event = {
        "usuario_id": usuario_id,                       # CA1, CA3
        "sesion_id": sesion_id,                          # CA5
        "timestamp": datetime.utcnow().isoformat(),      # CA1
        "tipo_accion": tipo_accion,                      # CA1
        "dataset_nombre": dataset_nombre,                # CA1
        "columnas_afectadas": columnas_afectadas,
        "contexto_ejecucion": _build_contexto(),
        "nivel_alerta": nivel_alerta,                    # CA3
        "motivo_alerta": motivo_alerta,                  # CA3
    }

    try:
        conn = get_connection()
        insert_event(conn, event)           # CA4: persistencia inmediata
        conn.close()
    except Exception as exc:
        # No interrumpir la operación del usuario si falla la auditoría
        print(f"[AuditTracer] Advertencia: no se pudo registrar evento — {exc}")


# ──────────────────────────────────────────────────────────────
# INTERCEPTORES DE CARGA  (PDGTRAZDSA-50)
# ──────────────────────────────────────────────────────────────

def _audited_read_csv(filepath_or_buffer=None, *args, **kwargs) -> pd.DataFrame:
    """
    Reemplazo auditado de pd.read_csv().
    Registra tipo_accion = 'CARGA' antes de devolver el DataFrame.
    """
    dataset_nombre = _resolve_dataset_nombre(
        filepath_or_buffer, default="buffer_csv"
    )

    df = _original_read_csv(filepath_or_buffer, *args, **kwargs)

    _log_event(
        tipo_accion="CARGA",
        dataset_nombre=dataset_nombre,
        columnas_afectadas=json.dumps(list(df.columns)),
    )
    return df


def _audited_read_excel(io=None, *args, **kwargs) -> pd.DataFrame:
    """
    Reemplazo auditado de pd.read_excel().
    Registra tipo_accion = 'CARGA' antes de devolver el DataFrame.
    """
    dataset_nombre = _resolve_dataset_nombre(io, default="buffer_excel")

    df = _original_read_excel(io, *args, **kwargs)

    _log_event(
        tipo_accion="CARGA",
        dataset_nombre=dataset_nombre,
        columnas_afectadas=json.dumps(list(df.columns)),
    )
    return df


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

    # Necesario para que pandas conserve la subclase al hacer operaciones
    @property
    def _constructor(self):
        return AuditedDataFrame

    # ── df[key] ──────────────────────────────────────────────
    def __getitem__(self, key):
        result = super().__getitem__(key)

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

        return result

    # ── df.query() ────────────────────────────────────────────
    def query(self, expr, **kwargs):
        result = super().query(expr, **kwargs)

        dataset_nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")

        # Intentar extraer columnas referenciadas en la expresión
        cols = _extract_columns_from_expr(expr, self.columns)

        _log_event(
            tipo_accion="CONSULTA",
            dataset_nombre=dataset_nombre,
            columnas_afectadas=json.dumps(cols) if cols else expr,
        )

        return result


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

    Args:
        df:              DataFrame a envolver.
        dataset_nombre:  Nombre descriptivo del dataset.

    Returns:
        AuditedDataFrame listo para auditar consultas.
    """
    audited = AuditedDataFrame(df)
    audited._dataset_nombre = dataset_nombre
    return audited


# ──────────────────────────────────────────────────────────────
# ACTIVACIÓN / DESACTIVACIÓN DEL INTERCEPTOR
# ──────────────────────────────────────────────────────────────

def activate() -> None:
    """
    Activa el interceptor: reemplaza pd.read_csv y pd.read_excel con
    versiones auditadas.

    Idempotente: llamadas adicionales no tienen efecto.
    """
    global _interceptor_active, _original_read_csv, _original_read_excel

    if _interceptor_active:
        return

    # Guardar referencias originales (PDGTRAZDSA-50)
    _original_read_csv = pd.read_csv
    _original_read_excel = pd.read_excel

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
    """
    global _interceptor_active, _original_read_csv, _original_read_excel

    if not _interceptor_active:
        return

    if _original_read_csv is not None:
        pd.read_csv = _original_read_csv
    if _original_read_excel is not None:
        pd.read_excel = _original_read_excel

    _interceptor_active = False
