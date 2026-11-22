"""
audit_tracer/data_capture.py
============================
HU-2.1 — Registrar eventos de acceso a datos clínicos
HU-2.4 — Registrar intentos fallidos de acceso a datos clínicos

Intercepta automáticamente operaciones de carga y consulta sobre
DataFrames de pandas, generando registros en audit_log sin intervención
manual del usuario.

Operaciones interceptadas:
  CARGA          → pd.read_csv(), pd.read_excel(), pd.read_sql*(), y desde el
                   21/11/2026 también read_table, read_fwf, read_json,
                   read_parquet, read_feather, read_orc, read_pickle,
                   read_xml, read_stata, read_sas, read_spss, read_hdf;
                   np.load/loadtxt/genfromtxt/fromfile; polars.read_* y
                   scan_* si polars está instalado (LIB-R2)
  CONSULTA       → df[columna/s], df.query(), df.loc/iloc y, desde el
                   21/11/2026, head, tail, sample, nlargest, nsmallest,
                   describe, value_counts, filter, groupby, at, iat, y la
                   lectura con open() de un archivo ya cargado como dataset
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
import re
import time
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

def _registrar_ruta_dataset(fuente) -> None:
    """LIB-R2: recuerda la ruta de cada archivo cargado para auditar lecturas directas con open()."""
    if isinstance(fuente, os.PathLike):
        fuente = os.fspath(fuente)
    if isinstance(fuente, str) and fuente and "://" not in fuente:
        _rutas_datasets.add(os.path.normcase(os.path.abspath(fuente)))
        _nombres_datasets.add(os.path.basename(fuente).lower())


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

    guard(_registrar_ruta_dataset, fuente, _contexto="Ruta del dataset")
    return guard(_registrar_carga, resultado, dataset_nombre,
                 _contexto="Registro de CARGA", _default=resultado)


# ── Lectores adicionales de pandas (LIB-R2, 21/11/2026) ──────────────────────
# Antes, read_parquet, read_json o read_feather leían un dataset sin dejar
# rastro. Todos comparten el mismo núcleo que read_csv: CARGA con el nombre
# del archivo y sus columnas, y ACCESO_FALLIDO si el archivo no se puede abrir.
_LECTORES_ADICIONALES = (
    "read_table", "read_fwf", "read_json", "read_parquet", "read_feather", "read_orc",
    "read_pickle", "read_xml", "read_stata", "read_sas", "read_spss", "read_hdf",
)
_PARAMETROS_FUENTE = ("filepath_or_buffer", "path_or_buf", "path", "io", "filepath")
_originales_lectores: dict = {}


def _fuente_de(args, kwargs):
    if args:
        return args[0]
    for nombre in _PARAMETROS_FUENTE:
        if nombre in kwargs:
            return kwargs[nombre]
    return None


def _audited_reader_factory(nombre_original: str):
    def _audited(*args, **kwargs):
        original = _originales_lectores[nombre_original]
        if in_audit_scope():
            return original(*args, **kwargs)
        fuente = _fuente_de(args, kwargs)
        default = f"buffer_{nombre_original.replace('read_', '')}"
        dataset_nombre = guard(_resolve_dataset_nombre, fuente, default=default, _default=default)
        try:
            with audit_scope():
                resultado = original(*args, **kwargs)
        except ACCESS_FAILURE_EXCEPTIONS as exc:
            guard(log_failed_access, dataset_nombre=dataset_nombre, exc=exc, _contexto="Registro de ACCESO_FALLIDO")
            raise
        guard(_registrar_ruta_dataset, fuente, _contexto="Ruta del dataset")
        return guard(_registrar_carga, resultado, dataset_nombre,
                     _contexto=f"Registro de CARGA ({nombre_original})", _default=resultado)
    _audited.__name__ = f"_audited_{nombre_original}"
    return _audited


# ── NumPy (LIB-R2) ────────────────────────────────────────────────────────────
_LECTORES_NUMPY = ("load", "loadtxt", "genfromtxt", "fromfile")
_originales_numpy: dict = {}


def _audited_numpy_factory(nombre_original: str):
    def _audited(*args, **kwargs):
        original = _originales_numpy[nombre_original]
        if in_audit_scope():
            return original(*args, **kwargs)
        fuente = args[0] if args else kwargs.get("file", kwargs.get("fname"))
        defecto = f"numpy_{nombre_original}"
        dataset_nombre = guard(_resolve_dataset_nombre, fuente, default=defecto, _default=defecto)
        try:
            with audit_scope():
                resultado = original(*args, **kwargs)
        except ACCESS_FAILURE_EXCEPTIONS as exc:
            guard(log_failed_access, dataset_nombre=dataset_nombre, exc=exc, _contexto="Registro de ACCESO_FALLIDO")
            raise
        guard(_registrar_ruta_dataset, fuente, _contexto="Ruta del dataset")
        guard(_log_event, tipo_accion="CARGA", dataset_nombre=dataset_nombre,
              _contexto=f"Registro de CARGA (np.{nombre_original})")
        return resultado
    _audited.__name__ = f"_audited_np_{nombre_original}"
    return _audited


# ── polars, si está instalado (LIB-R2) ────────────────────────────────────────
_LECTORES_POLARS = ("read_csv", "read_parquet", "read_json", "read_ndjson", "read_excel", "read_ipc",
                    "read_database", "scan_csv", "scan_parquet", "scan_ndjson", "scan_ipc")
_originales_polars: dict = {}


def _columnas_de(resultado):
    try:
        return [str(c) for c in resultado.columns]
    except Exception:
        return None


def _audited_polars_factory(nombre_original: str):
    def _audited(*args, **kwargs):
        original = _originales_polars[nombre_original]
        if in_audit_scope():
            return original(*args, **kwargs)
        fuente = args[0] if args else kwargs.get("source", kwargs.get("query"))
        if nombre_original == "read_database":
            dataset_nombre = guard(_nombre_dataset_sql, fuente, "sql:consulta", _default="sql:consulta")
        else:
            dataset_nombre = guard(_resolve_dataset_nombre, fuente, default="buffer_polars", _default="buffer_polars")
        try:
            with audit_scope():
                resultado = original(*args, **kwargs)
        except ACCESS_FAILURE_EXCEPTIONS as exc:
            guard(log_failed_access, dataset_nombre=dataset_nombre, exc=exc, _contexto="Registro de ACCESO_FALLIDO")
            raise
        if nombre_original != "read_database":
            guard(_registrar_ruta_dataset, fuente, _contexto="Ruta del dataset")
        columnas = _columnas_de(resultado)
        guard(_log_event, tipo_accion="CARGA", dataset_nombre=dataset_nombre,
              columnas_afectadas=json.dumps(columnas) if columnas else None,
              _contexto=f"Registro de CARGA (polars.{nombre_original})")
        return resultado
    _audited.__name__ = f"_audited_polars_{nombre_original}"
    return _audited


def _activar_polars() -> None:
    import sys
    polars = sys.modules.get("polars")
    if polars is None:
        import importlib.util
        if importlib.util.find_spec("polars") is None:
            return
        import polars
    for nombre in _LECTORES_POLARS:
        actual = getattr(polars, nombre, None)
        if actual is None:
            continue
        original = _unwrap(actual)
        _originales_polars[nombre] = original
        parche = _audited_polars_factory(nombre)
        parche._audit_tracer_original = original
        setattr(polars, nombre, parche)


# ── open() sobre archivos ya cargados como dataset (LIB-R2) ───────────────────
# No se audita todo open() (pandas, el intérprete y las demás librerías abren
# miles de archivos): solo la lectura directa de un archivo que ya se cargó
# como dataset, que es la forma de saltarse la captura con el módulo csv o
# leyendo el archivo a mano.
_rutas_datasets: set = set()
_nombres_datasets: set = set()
_open_original = None


def _es_dataset_conocido(file) -> bool:
    try:
        ruta = os.fspath(file)
    except TypeError:
        return False
    if not isinstance(ruta, str) or os.path.basename(ruta).lower() not in _nombres_datasets:
        return False
    return os.path.normcase(os.path.abspath(ruta)) in _rutas_datasets


def _audited_open_builtin(file, mode="r", *args, **kwargs):
    original = _open_original
    if (_nombres_datasets and isinstance(file, (str, os.PathLike)) and isinstance(mode, str)
            and "r" in mode and not in_audit_scope() and _es_dataset_conocido(file)):
        with audit_scope():
            manejador = original(file, mode, *args, **kwargs)
        guard(_log_event, tipo_accion="CONSULTA", dataset_nombre=os.path.basename(os.fspath(file)),
              columnas_afectadas=json.dumps(["lectura directa con open()"]),
              _contexto="Registro de lectura directa con open()")
        return manejador
    return original(file, mode, *args, **kwargs)


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


_RE_TABLA_SQL = re.compile(r"\bfrom\s+([A-Za-z_][\w.]*)", re.I)


def _nombre_dataset_sql(consulta, default: str) -> str:
    """
    Nombre de dataset de una consulta SQL: solo la tabla (sql:tabla). El texto de
    la consulta no se guarda: puede llevar valores o identificadores de pacientes.
    """
    if isinstance(consulta, str):
        m = _RE_TABLA_SQL.search(consulta)
        if m:
            return f"sql:{m.group(1)}"
        if re.fullmatch(r"[A-Za-z_][\w.]*", consulta.strip()):   # read_sql_table("tabla")
            return f"sql:{consulta.strip()}"
    return default


def _audited_read_sql_factory(nombre_original: str):
    def _audited(sql=None, *args, **kwargs):
        original = _originales_sql[nombre_original]
        if in_audit_scope():
            return original(sql, *args, **kwargs)
        dataset = guard(_nombre_dataset_sql, sql, "sql:consulta", _default="sql:consulta")
        with audit_scope():
            resultado = original(sql, *args, **kwargs)
        return guard(_registrar_carga, resultado, dataset, _contexto="Registro de CARGA (SQL)",
                     _default=resultado)
    _audited.__name__ = f"_audited_{nombre_original}"
    return _audited


_FUNCIONES_SQL = ("read_sql", "read_sql_query", "read_sql_table")
_originales_sql: dict = {}


# ──────────────────────────────────────────────────────────────
# INTERCEPTORES DE CONSULTA  (PDGTRAZDSA-51)
# ──────────────────────────────────────────────────────────────

def _es_mascara_booleana(key) -> bool:
    """True si `key` es una Series/array/lista de booleanos (seleccion de filas)."""
    try:
        if hasattr(key, "dtype"):
            return pd.api.types.is_bool_dtype(key.dtype) and getattr(key, "ndim", 1) == 1
        return isinstance(key, list) and bool(key) and all(isinstance(k, bool) or type(k).__name__ == "bool_"
                                                          for k in key)
    except Exception:
        return False


# Las lecturas por celda dentro de un bucle (df.loc[i, "x"]) generarian miles de
# eventos identicos: un mismo (dataset, operacion, columnas) se registra una vez por segundo.
_VENTANA_REPETIDOS_S = 1.0
_ultimos_loc: dict = {}


class _IndexerAuditado:
    """Envoltura de df.loc / df.iloc: registra la lectura y delega todo lo demas."""

    def __init__(self, df, indexador, nombre: str):
        object.__setattr__(self, "_df", df)
        object.__setattr__(self, "_indexador", indexador)
        object.__setattr__(self, "_nombre", nombre)

    def __getitem__(self, key):
        if in_audit_scope():
            return self._indexador[key]
        with audit_scope():
            result = self._indexador[key]
        guard(self._registrar, key, result, _contexto=f"Registro de df.{self._nombre}[...]")
        return result

    def _registrar(self, key, result) -> None:
        df = self._df
        filas = key[0] if isinstance(key, tuple) and key else key
        if _es_mascara_booleana(filas):
            df._registrar_filtrado(filas, result, f"df.{self._nombre}[mascara]")
            return
        cols = []
        if isinstance(key, tuple) and len(key) > 1:
            seleccion = key[1]
            if self._nombre in ("loc", "at"):
                cols = [c for c in (seleccion if isinstance(seleccion, (list, pd.Index)) else [seleccion])
                        if isinstance(c, str)]
            elif isinstance(seleccion, (int, list, slice)):
                try:
                    pos = [seleccion] if isinstance(seleccion, int) else seleccion
                    cols = [str(c) for c in df.columns[pos]]
                except Exception:
                    cols = []
        elif isinstance(result, pd.DataFrame):
            cols = [str(c) for c in result.columns]
        nombre = getattr(df, "_dataset_nombre", "dataset_desconocido")
        firma = (nombre, self._nombre, tuple(cols))
        ahora = time.monotonic()
        if ahora - _ultimos_loc.get(firma, -1e9) < _VENTANA_REPETIDOS_S:
            return
        _ultimos_loc[firma] = ahora
        if len(_ultimos_loc) > 1000:
            _ultimos_loc.clear()
        _log_event(tipo_accion="CONSULTA", dataset_nombre=nombre,
                   columnas_afectadas=json.dumps(cols) if cols else None)

    def __setitem__(self, key, value):
        self._indexador[key] = value

    def __call__(self, *args, **kwargs):  # df.loc(axis=...)[...]
        return _IndexerAuditado(self._df, self._indexador(*args, **kwargs), self._nombre)

    def __getattr__(self, nombre):
        return getattr(self._indexador, nombre)


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
        if _es_mascara_booleana(key):
            guard(self._registrar_filtrado, key, result, "df[mascara]", _contexto="Registro de FILTRADO df[mascara]")
        else:
            guard(self._registrar_getitem, key, _contexto="Registro de CONSULTA df[...]")
        return result

    # ── df[mascara booleana] / df.loc[...] / df.iloc[...] ─────
    def _registrar_filtrado(self, mascara, resultado, origen: str) -> None:
        """Seleccion de filas por mascara booleana: TRANSFORMACION con subtipo FILTRADO."""
        from .transform_capture import _log_transform, TIPO_FILTRADO, _comparar_estructura
        total = len(self)
        if isinstance(resultado, pd.DataFrame):
            conservadas = len(resultado)
            comparacion = _comparar_estructura((self.shape, self.columns), resultado)
            columnas = [str(c) for c in resultado.columns]
        else:
            conservadas, comparacion, columnas = None, None, []
        detalle = f"{origen}: {conservadas} de {total} filas" if conservadas is not None else origen
        _log_transform(
            tipo_transformacion=TIPO_FILTRADO,
            dataset_nombre=getattr(self, "_dataset_nombre", "dataset_desconocido"),
            columnas_afectadas=columnas,
            descripcion=detalle, comparacion=comparacion,
        )

    # ── df.loc / df.iloc ──────────────────────────────────────
    @property
    def loc(self):
        return _IndexerAuditado(self, pd.DataFrame.loc.fget(self), "loc")

    @property
    def iloc(self):
        return _IndexerAuditado(self, pd.DataFrame.iloc.fget(self), "iloc")

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

    # ── head, tail, sample, describe, groupby, filter, at, iat (LIB-R2) ──
    def _registrar_consulta_metodo(self, metodo: str, resultado=None, columnas=None) -> None:
        nombre = getattr(self, "_dataset_nombre", "dataset_desconocido")
        if columnas is None:
            fuente = resultado if isinstance(resultado, pd.DataFrame) else self
            columnas = [str(c) for c in getattr(fuente, "columns", [])]
        firma = (nombre, metodo, tuple(columnas))
        ahora = time.monotonic()
        if ahora - _ultimos_loc.get(firma, -1e9) < _VENTANA_REPETIDOS_S:
            return
        _ultimos_loc[firma] = ahora
        if len(_ultimos_loc) > 1000:
            _ultimos_loc.clear()
        _log_event(tipo_accion="CONSULTA", dataset_nombre=nombre,
                   columnas_afectadas=json.dumps(columnas) if columnas else json.dumps([f"df.{metodo}()"]))

    def _consulta(self, metodo: str, args, kwargs, columnas_de=None):
        funcion = getattr(pd.DataFrame, metodo)
        if in_audit_scope():
            return funcion(self, *args, **kwargs)
        with audit_scope():
            resultado = funcion(self, *args, **kwargs)
        columnas = guard(columnas_de, args, kwargs, _default=None) if columnas_de else None
        guard(self._registrar_consulta_metodo, metodo, resultado, columnas,
              _contexto=f"Registro de CONSULTA df.{metodo}()")
        return resultado

    def head(self, *args, **kwargs):
        return self._consulta("head", args, kwargs)

    def tail(self, *args, **kwargs):
        return self._consulta("tail", args, kwargs)

    def sample(self, *args, **kwargs):
        return self._consulta("sample", args, kwargs)

    def nlargest(self, *args, **kwargs):
        return self._consulta("nlargest", args, kwargs)

    def nsmallest(self, *args, **kwargs):
        return self._consulta("nsmallest", args, kwargs)

    def describe(self, *args, **kwargs):
        return self._consulta("describe", args, kwargs)

    def value_counts(self, *args, **kwargs):
        return self._consulta("value_counts", args, kwargs,
                              columnas_de=lambda a, k: _como_columnas(a[0] if a else k.get("subset")) or None)

    def filter(self, *args, **kwargs):
        return self._consulta("filter", args, kwargs)

    def groupby(self, *args, **kwargs):
        return self._consulta("groupby", args, kwargs,
                              columnas_de=lambda a, k: _como_columnas(a[0] if a else k.get("by")))

    @property
    def at(self):
        return _IndexerAuditado(self, pd.DataFrame.at.fget(self), "at")

    @property
    def iat(self):
        return _IndexerAuditado(self, pd.DataFrame.iat.fget(self), "iat")

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


def _como_columnas(valor) -> list:
    """Nombres de columna de un argumento by/subset (str, lista o Index); [] si no son nombres."""
    if isinstance(valor, str):
        return [valor]
    if isinstance(valor, (list, tuple, pd.Index)):
        return [str(c) for c in valor if isinstance(c, str)]
    return []


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

    # Lecturas desde bases de datos -> CARGA (21/11/2026)
    for nombre in _FUNCIONES_SQL:
        original = _unwrap(getattr(pd, nombre))
        _originales_sql[nombre] = original
        parche = _audited_read_sql_factory(nombre)
        parche._audit_tracer_original = original
        setattr(pd, nombre, parche)

    # Parchear también en el namespace del módulo pandas (para imports previos)
    import pandas.io.parsers as _parsers          # noqa: F401
    pd.io.parsers.readers.read_csv = _audited_read_csv

    # LIB-R2 (21/11/2026): lectores adicionales de pandas, NumPy y polars.
    for nombre in _LECTORES_ADICIONALES:
        actual = getattr(pd, nombre, None)
        if actual is None:
            continue
        original = _unwrap(actual)
        _originales_lectores[nombre] = original
        parche = _audited_reader_factory(nombre)
        parche._audit_tracer_original = original
        setattr(pd, nombre, parche)
    import numpy as _np
    for nombre in _LECTORES_NUMPY:
        actual = getattr(_np, nombre, None)
        if actual is None:
            continue
        original = _unwrap(actual)
        _originales_numpy[nombre] = original
        parche = _audited_numpy_factory(nombre)
        parche._audit_tracer_original = original
        setattr(_np, nombre, parche)
    guard(_activar_polars, _contexto="Captura de lecturas con polars")

    # LIB-R2: lecturas directas con open() de archivos ya cargados.
    import builtins
    global _open_original
    _open_original = _unwrap(builtins.open)
    _audited_open_builtin._audit_tracer_original = _open_original
    builtins.open = _audited_open_builtin

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
    for nombre in _FUNCIONES_SQL:
        setattr(pd, nombre, _unwrap(getattr(pd, nombre)))
    pd.io.parsers.readers.read_csv = _unwrap(pd.io.parsers.readers.read_csv)
    for nombre in _LECTORES_ADICIONALES:
        if hasattr(pd, nombre):
            setattr(pd, nombre, _unwrap(getattr(pd, nombre)))
    import numpy as _np
    for nombre in _LECTORES_NUMPY:
        if hasattr(_np, nombre):
            setattr(_np, nombre, _unwrap(getattr(_np, nombre)))
    import sys
    polars = sys.modules.get("polars")
    if polars is not None:
        for nombre in _LECTORES_POLARS:
            if hasattr(polars, nombre):
                setattr(polars, nombre, _unwrap(getattr(polars, nombre)))
    import builtins
    builtins.open = _unwrap(builtins.open)

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
