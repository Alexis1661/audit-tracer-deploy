"""
audit_tracer/export_capture.py
===============================
HU-2.3 — Registrar eventos de exportación de datos

Intercepta automáticamente operaciones de exportación sobre DataFrames
de pandas, generando registros en audit_log con tipo_accion = EXPORTACION
sin intervención manual del usuario.

Operaciones interceptadas (PDGTRAZDSA-54):
  EXPORTACION → df.to_csv(), df.to_excel(), df.to_json(), df.to_parquet()

CA4 — métodos alternativos de exportación (ej. escritura con open()):
  No se parchea builtins.open() de forma global: pandas y el resto del
  intérprete dependen de open() internamente, y reemplazarlo a nivel de
  proceso generaría auditoría duplicada/recursiva e inestabilidad.
  En su lugar se expone `audited_open()`, un reemplazo drop-in de open()
  que el usuario invoca explícitamente para exportar datos por fuera de
  pandas y que queda registrado igual que las demás exportaciones. Esta
  es la forma "técnicamente detectable" contemplada por el CA4.

Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
"""

import os
import contextlib
import inspect
from datetime import datetime
from typing import Optional

import pandas as pd

from .db import get_connection
from .models.audit_log import insert_event
from .utils.session import detect_environment, get_hostname


# ──────────────────────────────────────────────────────────────
# UMBRAL DE EXPORTACIÓN MASIVA
# ──────────────────────────────────────────────────────────────

UMBRAL_EXPORTACION_MASIVA = 1000
# Coherente con el comentario de nivel_alerta en schema/audit_log.sql:
# "CRITICO: ... exportaciones masivas >1000 filas"


# ──────────────────────────────────────────────────────────────
# ESTADO GLOBAL DEL INTERCEPTOR
# ──────────────────────────────────────────────────────────────

_export_interceptor_active = False
_original_to_csv = None
_original_to_excel = None
_original_to_json = None
_original_to_parquet = None


# ──────────────────────────────────────────────────────────────
# HELPERS INTERNOS
# ──────────────────────────────────────────────────────────────

def _get_session() -> tuple[str, str]:
    """
    Obtiene (usuario_id, sesion_id) desde SessionTracker si está activo.
    Si no puede identificar al usuario devuelve 'DESCONOCIDO' (CA1/CA2).
    """
    try:
        from .session_tracker import SessionTracker
        tracker = SessionTracker.get_instance()
        usuario_id = tracker.usuario_id or "DESCONOCIDO"
        sesion_id = tracker.sesion_id
        return usuario_id, sesion_id
    except Exception:
        return "DESCONOCIDO", "SIN_SESION"


def _build_contexto(formato: str) -> str:
    """Construye contexto_ejecucion: script, entorno, host y formato exportado."""
    env = detect_environment()
    host = get_hostname()

    caller_file = "desconocido"
    for frame_info in inspect.stack():
        fname = frame_info.filename
        if (
            fname != __file__
            and "audit_tracer" not in fname
            and "pandas" not in fname
            and "<frozen" not in fname
            and "<string>" not in fname
        ):
            caller_file = os.path.basename(fname)
            break

    return f"Script: {caller_file} | Env: {env} | Host: {host} | Formato: {formato}"


def _determine_alert(usuario_id: str, filas_exportadas: Optional[int]) -> tuple[str, Optional[str]]:
    """
    CA1/CA2: usuario no identificado siempre es CRITICO.
    Exportaciones masivas (> UMBRAL_EXPORTACION_MASIVA filas) también son CRITICO,
    para poder controlar posibles fugas de información.
    """
    if usuario_id == "DESCONOCIDO":
        return "CRITICO", "Exportación ejecutada por usuario no identificado"
    if filas_exportadas is not None and filas_exportadas > UMBRAL_EXPORTACION_MASIVA:
        return "CRITICO", f"Exportación masiva: {filas_exportadas} filas (> {UMBRAL_EXPORTACION_MASIVA})"
    return "NORMAL", None


def _resolve_export_path(target) -> Optional[str]:
    """
    Extrae una ruta de archivo legible del destino de exportación.
    Soporta str/PathLike y objetos tipo ExcelWriter (atributo path/filename/name).
    """
    if target is None:
        return None
    if isinstance(target, (str, os.PathLike)):
        return str(target)
    for attr in ("path", "filename", "name"):
        val = getattr(target, attr, None)
        if isinstance(val, (str, os.PathLike)):
            return str(val)
    return None


def _path_exists(path: Optional[str]) -> bool:
    return bool(path) and os.path.exists(path)


def _log_export(
    dataset_nombre: str,
    ruta_destino: str,
    filas_exportadas: int,
    formato: str,
    sobrescritura: bool,
) -> None:
    """
    Construye y persiste un registro EXPORTACION en audit_log (CA1, CA2, CA3).
    """
    usuario_id, sesion_id = _get_session()
    nivel_alerta, motivo_alerta = _determine_alert(usuario_id, filas_exportadas)

    event = {
        "usuario_id": usuario_id,                          # CA2
        "sesion_id": sesion_id,
        "timestamp": datetime.utcnow().isoformat(),         # CA2
        "tipo_accion": "EXPORTACION",                       # CA1
        "dataset_nombre": dataset_nombre,                   # CA2
        "ruta_destino": ruta_destino,                       # CA2
        "filas_exportadas": filas_exportadas,                # CA2
        "sobrescritura": 1 if sobrescritura else 0,          # CA3
        "contexto_ejecucion": _build_contexto(formato),
        "nivel_alerta": nivel_alerta,
        "motivo_alerta": motivo_alerta,
    }

    try:
        conn = get_connection()
        insert_event(conn, event)
        conn.close()
    except Exception as exc:
        print(f"[AuditTracer] Advertencia: no se pudo registrar exportación — {exc}")


def wrap_for_export(df: pd.DataFrame, dataset_nombre: str) -> pd.DataFrame:
    """
    Etiqueta un DataFrame con el nombre de dataset a usar en los registros
    de exportación. Compatible con DataFrames ya envueltos por HU-2.1/HU-2.2.

    Uso:
        df = wrap_for_export(df, "PATIENTS.csv")
        df.to_csv("outputs/resultados.csv")   # → evento EXPORTACION
    """
    df._dataset_nombre = dataset_nombre
    return df


# ──────────────────────────────────────────────────────────────
# INTERCEPTORES DE EXPORTACIÓN  (PDGTRAZDSA-54, PDGTRAZDSA-55)
# ──────────────────────────────────────────────────────────────

def _audited_to_csv(self, path_or_buf=None, *args, **kwargs):
    """Reemplazo auditado de DataFrame.to_csv()."""
    ruta = _resolve_export_path(path_or_buf)
    existed_before = _path_exists(ruta)

    result = _original_to_csv(self, path_or_buf, *args, **kwargs)

    _log_export(
        dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
        ruta_destino=ruta or "buffer_csv",
        filas_exportadas=len(self),
        formato="CSV",
        sobrescritura=existed_before,
    )
    return result


def _audited_to_excel(self, excel_writer=None, *args, **kwargs):
    """Reemplazo auditado de DataFrame.to_excel()."""
    ruta = _resolve_export_path(excel_writer)
    existed_before = _path_exists(ruta)

    result = _original_to_excel(self, excel_writer, *args, **kwargs)

    _log_export(
        dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
        ruta_destino=ruta or "buffer_excel",
        filas_exportadas=len(self),
        formato="EXCEL",
        sobrescritura=existed_before,
    )
    return result


def _audited_to_json(self, path_or_buf=None, *args, **kwargs):
    """Reemplazo auditado de DataFrame.to_json()."""
    ruta = _resolve_export_path(path_or_buf)
    existed_before = _path_exists(ruta)

    result = _original_to_json(self, path_or_buf, *args, **kwargs)

    _log_export(
        dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
        ruta_destino=ruta or "buffer_json",
        filas_exportadas=len(self),
        formato="JSON",
        sobrescritura=existed_before,
    )
    return result


def _audited_to_parquet(self, path=None, *args, **kwargs):
    """Reemplazo auditado de DataFrame.to_parquet()."""
    ruta = _resolve_export_path(path)
    existed_before = _path_exists(ruta)

    result = _original_to_parquet(self, path, *args, **kwargs)

    _log_export(
        dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
        ruta_destino=ruta or "buffer_parquet",
        filas_exportadas=len(self),
        formato="PARQUET",
        sobrescritura=existed_before,
    )
    return result


# ──────────────────────────────────────────────────────────────
# CA4: EXPORTACIÓN POR MÉTODOS ALTERNATIVOS (open())
# ──────────────────────────────────────────────────────────────

class _CountingFileWrapper:
    """Envuelve un archivo abierto en modo escritura y cuenta líneas escritas."""

    def __init__(self, fileobj):
        self._fileobj = fileobj
        self.lines_written = 0

    def write(self, data):
        if isinstance(data, str):
            self.lines_written += data.count("\n")
        return self._fileobj.write(data)

    def __getattr__(self, name):
        return getattr(self._fileobj, name)

    def __iter__(self):
        return iter(self._fileobj)


@contextlib.contextmanager
def audited_open(path, mode: str = "w", dataset_nombre: Optional[str] = None, **kwargs):
    """
    Reemplazo drop-in de open() para exportaciones manuales fuera de pandas (CA4).

    Uso:
        with audited_open("outputs/resultado.csv", "w", dataset_nombre="resultado.csv") as f:
            f.write("col1,col2\\n1,2\\n")
        # → genera un evento EXPORTACION con filas_exportadas = líneas escritas

    Solo registra evento para modos de escritura ('w', 'x', 'a'); en modo
    lectura se comporta como open() normal sin auditar.
    """
    existed_before = _path_exists(str(path)) if isinstance(path, (str, os.PathLike)) else False
    is_write_mode = any(flag in mode for flag in ("w", "x", "a"))

    f = open(path, mode, **kwargs)
    wrapper = _CountingFileWrapper(f)
    try:
        yield wrapper
    finally:
        f.close()
        if is_write_mode:
            _log_export(
                dataset_nombre=dataset_nombre or os.path.basename(str(path)),
                ruta_destino=str(path),
                filas_exportadas=wrapper.lines_written,
                formato="OPEN",
                sobrescritura=existed_before,
            )


# ──────────────────────────────────────────────────────────────
# ACTIVACIÓN / DESACTIVACIÓN DEL INTERCEPTOR
# ──────────────────────────────────────────────────────────────

def activate() -> None:
    """
    Activa el interceptor: reemplaza to_csv/to_excel/to_json/to_parquet
    de pd.DataFrame con versiones auditadas. Idempotente.
    """
    global _export_interceptor_active
    global _original_to_csv, _original_to_excel, _original_to_json, _original_to_parquet

    if _export_interceptor_active:
        return

    _original_to_csv = pd.DataFrame.to_csv
    _original_to_excel = pd.DataFrame.to_excel
    _original_to_json = pd.DataFrame.to_json
    _original_to_parquet = pd.DataFrame.to_parquet

    pd.DataFrame.to_csv = _audited_to_csv
    pd.DataFrame.to_excel = _audited_to_excel
    pd.DataFrame.to_json = _audited_to_json
    pd.DataFrame.to_parquet = _audited_to_parquet

    _export_interceptor_active = True


def deactivate() -> None:
    """Desactiva el interceptor y restaura los métodos originales de pandas."""
    global _export_interceptor_active

    if not _export_interceptor_active:
        return

    if _original_to_csv is not None:
        pd.DataFrame.to_csv = _original_to_csv
    if _original_to_excel is not None:
        pd.DataFrame.to_excel = _original_to_excel
    if _original_to_json is not None:
        pd.DataFrame.to_json = _original_to_json
    if _original_to_parquet is not None:
        pd.DataFrame.to_parquet = _original_to_parquet

    _export_interceptor_active = False
