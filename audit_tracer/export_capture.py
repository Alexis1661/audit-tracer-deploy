"""
audit_tracer/export_capture.py
===============================
HU-2.3 — Registrar eventos de exportación de datos

Intercepta automáticamente operaciones de exportación sobre DataFrames
de pandas, generando registros en audit_log con tipo_accion = EXPORTACION
sin intervención manual del usuario.

Operaciones interceptadas (PDGTRAZDSA-54):
  EXPORTACION → df.to_csv(), df.to_excel(), df.to_json(), df.to_parquet() y,
                desde el 21/11/2026 (LIB-R2), to_feather, to_orc, to_pickle,
                to_xml, to_stata, to_hdf, to_sql (a una base de datos),
                to_clipboard (portapapeles), to_html/to_markdown/to_latex
                cuando escriben a un archivo, y np.save/savez/savez_compressed/savetxt

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
from datetime import datetime
from typing import Optional

import pandas as pd

from .db import get_connection
from .models.audit_log import insert_event_and_enqueue_sync
from .utils.contexto import build_contexto
from .utils.error_log import guard, log_internal_error, in_audit_scope, audit_scope


# ──────────────────────────────────────────────────────────────
# UMBRAL DE EXPORTACIÓN MASIVA
# ──────────────────────────────────────────────────────────────

UMBRAL_EXPORTACION_MASIVA = 1000
# Coherente con el comentario de nivel_alerta en audit_tracer/schema/audit_log.sql:
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
        if usuario_id == "DESCONOCIDO":
            tracker.remind_if_unidentified()
        return usuario_id, sesion_id
    except Exception:
        return "DESCONOCIDO", "SIN_SESION"


def _build_contexto(formato: str) -> str:
    """Construye contexto_ejecucion: script, entorno, host y formato exportado."""
    return build_contexto(f"Formato: {formato}")


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

    HU-5.1 CA4: nunca lanza; cualquier fallo va al log de errores del sistema.
    """
    try:
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

        conn = get_connection()
        # HU-5.8 CA1: persistencia local + encolado antes de cualquier envío.
        try:
            insert_event_and_enqueue_sync(conn, event)
        finally:
            conn.close()
        # HU-5.1 CA4: el envío ocurre en el hilo de fondo, nunca aquí.
        from .sync_client import schedule_sync
        schedule_sync()
    except Exception as exc:
        log_internal_error("No se pudo registrar exportación", exc)


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

def _audited_export(self, original, destino, formato, buffer_label, args, kwargs):
    """
    Núcleo común de to_csv/to_excel/to_json/to_parquet auditados.

    HU-5.1 CA4: la escritura original va FUERA de guard() (sus errores son
    del usuario y le llegan intactos); solo la auditoría va dentro.
    """
    if in_audit_scope():
        return original(self, destino, *args, **kwargs)

    ruta = guard(_resolve_export_path, destino, _contexto="Ruta de exportación")
    existed_before = guard(_path_exists, ruta, _default=False)

    with audit_scope():
        result = original(self, destino, *args, **kwargs)

    guard(
        _log_export,
        dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
        ruta_destino=ruta or buffer_label,
        filas_exportadas=len(self),
        formato=formato,
        sobrescritura=existed_before,
        _contexto=f"Registro de EXPORTACION {formato}",
    )
    return result


def _audited_to_csv(self, path_or_buf=None, *args, **kwargs):
    """Reemplazo auditado de DataFrame.to_csv()."""
    return _audited_export(self, _original_to_csv, path_or_buf, "CSV", "buffer_csv", args, kwargs)


def _audited_to_excel(self, excel_writer=None, *args, **kwargs):
    """Reemplazo auditado de DataFrame.to_excel()."""
    return _audited_export(self, _original_to_excel, excel_writer, "EXCEL", "buffer_excel", args, kwargs)


def _audited_to_json(self, path_or_buf=None, *args, **kwargs):
    """Reemplazo auditado de DataFrame.to_json()."""
    return _audited_export(self, _original_to_json, path_or_buf, "JSON", "buffer_json", args, kwargs)


def _audited_to_parquet(self, path=None, *args, **kwargs):
    """Reemplazo auditado de DataFrame.to_parquet()."""
    return _audited_export(self, _original_to_parquet, path, "PARQUET", "buffer_parquet", args, kwargs)


# ── Exportaciones adicionales (LIB-R2, 21/11/2026) ────────────────────────────
# Cada entrada: método, formato, etiqueta cuando no hay ruta, y si solo se
# registra cuando hay destino (to_html/to_markdown/to_latex sin archivo solo
# devuelven texto para mostrar; Jupyter los usa al pintar una tabla).
_EXPORTADORES_ADICIONALES = (
    ("to_feather", "FEATHER", "buffer_feather", False),
    ("to_orc", "ORC", "buffer_orc", False),
    ("to_pickle", "PICKLE", "buffer_pickle", False),
    ("to_xml", "XML", "buffer_xml", False),
    ("to_stata", "STATA", "buffer_stata", False),
    ("to_hdf", "HDF5", "buffer_hdf", False),
    ("to_html", "HTML", "buffer_html", True),
    ("to_markdown", "MARKDOWN", "buffer_markdown", True),
    ("to_latex", "LATEX", "buffer_latex", True),
)
_originales_adicionales: dict = {}


def _exportador_factory(metodo: str, formato: str, etiqueta: str, solo_con_destino: bool):
    def _auditado(self, *args, **kwargs):
        original = _originales_adicionales[metodo]
        destino = args[0] if args else next(
            (kwargs[n] for n in ("path", "path_or_buf", "path_or_buffer", "buf", "excel_writer") if n in kwargs), None)
        if solo_con_destino and destino is None:
            # Solo devuelve texto para mostrar (Jupyter lo usa al pintar la tabla):
            # no es exportación ni debe registrar las lecturas internas del formateador.
            with audit_scope():
                return original(self, *args, **kwargs)
        if args:
            return _audited_export(self, lambda df, _d, *a, **k: original(df, *args, **kwargs),
                                   destino, formato, etiqueta, (), {})
        return _audited_export(self, lambda df, _d, *a, **k: original(df, **kwargs),
                               destino, formato, etiqueta, (), {})
    _auditado.__name__ = f"_audited_{metodo}"
    return _auditado


def _audited_to_sql(self, name=None, con=None, *args, **kwargs):
    """to_sql: los datos salen hacia una tabla de una base de datos; la ruta es sql:<tabla>."""
    original = _originales_adicionales["to_sql"]
    destino = f"sql:{name}" if isinstance(name, str) else "sql:tabla"
    return _audited_export(self, lambda df, _d, *a, **k: original(df, name, con, *args, **kwargs),
                           destino, "SQL", "sql:tabla", (), {})


def _audited_to_clipboard(self, *args, **kwargs):
    """to_clipboard: copiar al portapapeles también saca los datos del entorno auditado."""
    original = _originales_adicionales["to_clipboard"]
    return _audited_export(self, lambda df, _d, *a, **k: original(df, *args, **kwargs),
                           "portapapeles", "PORTAPAPELES", "portapapeles", (), {})


# ── NumPy ─────────────────────────────────────────────────────────────────────
_ESCRITORES_NUMPY = ("save", "savez", "savez_compressed", "savetxt")
_originales_numpy: dict = {}


def _filas_de(valor) -> Optional[int]:
    try:
        return int(len(valor))
    except Exception:
        return None


def _numpy_factory(nombre: str):
    def _auditado(*args, **kwargs):
        original = _originales_numpy[nombre]
        if in_audit_scope():
            return original(*args, **kwargs)
        destino = args[0] if args else kwargs.get("file", kwargs.get("fname"))
        datos = args[1] if len(args) > 1 else kwargs.get("arr", kwargs.get("X"))
        ruta = guard(_resolve_export_path, destino, _contexto="Ruta de exportación")
        existia = guard(_path_exists, ruta, _default=False)
        with audit_scope():
            resultado = original(*args, **kwargs)
        guard(_log_export, dataset_nombre="numpy_array", ruta_destino=ruta or f"buffer_numpy_{nombre}",
              filas_exportadas=_filas_de(datos), formato=f"NUMPY_{nombre.upper()}", sobrescritura=existia,
              _contexto=f"Registro de EXPORTACION np.{nombre}")
        return resultado
    _auditado.__name__ = f"_audited_np_{nombre}"
    return _auditado


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

_PATCHES = (
    ("to_csv", "_audited_to_csv", "_original_to_csv"),
    ("to_excel", "_audited_to_excel", "_original_to_excel"),
    ("to_json", "_audited_to_json", "_original_to_json"),
    ("to_parquet", "_audited_to_parquet", "_original_to_parquet"),
)


def activate() -> None:
    """
    Activa el interceptor: reemplaza to_csv/to_excel/to_json/to_parquet
    de pd.DataFrame con versiones auditadas. Idempotente, también tras
    importlib.reload() (HU-5.1): el original se recupera desde la marca
    que deja cada parche, así nunca se parchea encima de un parche.
    """
    global _export_interceptor_active

    g = globals()
    for metodo, auditada, original in _PATCHES:
        actual = getattr(pd.DataFrame, metodo)
        g[original] = getattr(actual, "_audit_tracer_original", actual)
        g[auditada]._audit_tracer_original = g[original]
        setattr(pd.DataFrame, metodo, g[auditada])

    # LIB-R2: exportadores adicionales de pandas y NumPy.
    adicionales = [(m, _exportador_factory(m, f, e, d)) for m, f, e, d in _EXPORTADORES_ADICIONALES]
    adicionales += [("to_sql", _audited_to_sql), ("to_clipboard", _audited_to_clipboard)]
    for metodo, parche in adicionales:
        actual = getattr(pd.DataFrame, metodo, None)
        if actual is None:
            continue
        original = getattr(actual, "_audit_tracer_original", actual)
        _originales_adicionales[metodo] = original
        parche._audit_tracer_original = original
        setattr(pd.DataFrame, metodo, parche)
    import numpy as _np
    for nombre in _ESCRITORES_NUMPY:
        actual = getattr(_np, nombre, None)
        if actual is None:
            continue
        original = getattr(actual, "_audit_tracer_original", actual)
        _originales_numpy[nombre] = original
        parche = _numpy_factory(nombre)
        parche._audit_tracer_original = original
        setattr(_np, nombre, parche)

    _export_interceptor_active = True


def deactivate() -> None:
    """
    Desactiva el interceptor y restaura los métodos originales de pandas.
    HU-5.1: queda registrado como evento CRITICO AUDITORIA_DESACTIVADA.
    """
    global _export_interceptor_active

    if not _export_interceptor_active:
        return

    for metodo, _, _ in _PATCHES:
        actual = getattr(pd.DataFrame, metodo)
        setattr(pd.DataFrame, metodo, getattr(actual, "_audit_tracer_original", actual))
    for metodo in list(_originales_adicionales):
        actual = getattr(pd.DataFrame, metodo, None)
        if actual is not None:
            setattr(pd.DataFrame, metodo, getattr(actual, "_audit_tracer_original", actual))
    import numpy as _np
    for nombre in _ESCRITORES_NUMPY:
        actual = getattr(_np, nombre, None)
        if actual is not None:
            setattr(_np, nombre, getattr(actual, "_audit_tracer_original", actual))

    _export_interceptor_active = False
    from .data_capture import log_deactivation
    log_deactivation("export_capture (to_csv, to_excel, to_json, to_parquet)", get_connection)
