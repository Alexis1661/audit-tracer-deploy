"""
audit_tracer/model_capture.py
=============================
HU-03 «Registrar eventos de modelado» (21/11/2026) — Captura automática del
entrenamiento y la predicción de modelos de scikit-learn.

Eventos:
  MODELADO          [ENTRENAMIENTO] fit / fit_transform / fit_predict
                    [PREDICCION]    predict / predict_proba
                    [VALIDACION]    cross_val_score / cross_validate /
                                    cross_val_predict / learning_curve /
                                    validation_curve / permutation_test_score
  MODELADO_FALLIDO  la misma operación terminó con una excepción (que le
                    llega intacta al usuario)

Por qué así (la versión anterior descartó interceptar fit/predict):
  * Cada estimador define su propio fit: en lugar de un gancho por clase se
    envuelven los métodos de todas las subclases de BaseEstimator, las que ya
    existen y las que se definan después (__init_subclass__).
  * GridSearchCV, Pipeline o cross_val_score llaman fit cientos de veces: solo
    se registra la operación más externa (contador de anidamiento por hilo), así
    una búsqueda de hiperparámetros es UN evento, no una avalancha.
  * Las predicciones repetidas en un bucle (mismo modelo, misma operación,
    mismo dataset) se registran una vez por segundo, igual que df.loc.
  * scikit-learn no es dependencia del proyecto: si no está instalado no se
    hace nada; si se importa después de audit_tracer, un gancho de importación
    aplica la captura en cuanto se carga.
  * Nunca se guardan valores: solo el nombre del modelo, la operación, el
    dataset de origen (si viene de un DataFrame auditado), las columnas y el
    número de filas.

AUDIT_TRACER_MODELADO=0 desactiva esta captura.
"""

import contextvars
import functools
import importlib.abc
import importlib.machinery
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional

from .db import get_connection
from .models.audit_log import insert_event_and_enqueue_sync
from .utils.contexto import build_contexto
from .utils.error_log import guard, log_internal_error

METODOS_ENTRENAMIENTO = ("fit", "fit_transform", "fit_predict")
METODOS_PREDICCION = ("predict", "predict_proba")
FUNCIONES_VALIDACION = (
    "cross_val_score", "cross_validate", "cross_val_predict",
    "learning_curve", "validation_curve", "permutation_test_score",
)
_MODULOS_VALIDACION = ("sklearn.model_selection", "sklearn.model_selection._validation")
_VENTANA_REPETIDOS_S = 1.0

_profundidad = contextvars.ContextVar("audit_tracer_modelado_profundidad", default=0)
_ultimos: dict = {}
_activo = False
_gancho = None


def habilitado() -> bool:
    return os.environ.get("AUDIT_TRACER_MODELADO", "1") != "0"


# ──────────────────────────────────────────────────────────────
# REGISTRO DEL EVENTO
# ──────────────────────────────────────────────────────────────

def _get_session():
    try:
        from .session_tracker import SessionTracker
        tracker = SessionTracker.get_instance()
        return tracker.usuario_id or "DESCONOCIDO", tracker.sesion_id
    except Exception:
        return "DESCONOCIDO", "SIN_SESION"


def _describir_datos(X):
    """(dataset_nombre, columnas, filas) de la matriz de entrada, sin leer sus valores."""
    dataset = getattr(X, "_dataset_nombre", None) or "datos_en_memoria"
    columnas = None
    cols = getattr(X, "columns", None)
    if cols is not None:
        try:
            columnas = [str(c) for c in list(cols)[:200]]
        except Exception:
            columnas = None
    filas = None
    try:
        filas = int(X.shape[0])
    except Exception:
        try:
            filas = len(X)
        except Exception:
            filas = None
    return dataset, columnas, filas


def _registrar(tipo_accion: str, subtipo: str, modelo: str, operacion: str, X, error: Optional[BaseException] = None):
    usuario_id, sesion_id = _get_session()
    dataset, columnas, filas = _describir_datos(X)
    detalle = f"Modelo: {modelo} | Operación: {operacion}"
    if filas is not None:
        detalle += f" | Filas: {filas}"
    evento = {
        "usuario_id": usuario_id,
        "sesion_id": sesion_id,
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": tipo_accion,
        "dataset_nombre": dataset,
        "columnas_afectadas": json.dumps(columnas) if columnas else None,
        "contexto_ejecucion": build_contexto(detalle),
        "motivo_fallo": (f"[{subtipo}] {modelo}.{operacion}()" if error is None
                         else f"[{subtipo}] {modelo}.{operacion}(): {type(error).__name__}: {str(error)[:300]}"),
        "nivel_alerta": "CRITICO" if usuario_id == "DESCONOCIDO" else "NORMAL",
        "motivo_alerta": "Operación ejecutada por usuario no identificado" if usuario_id == "DESCONOCIDO" else None,
    }
    conn = get_connection()
    try:
        insert_event_and_enqueue_sync(conn, evento)
    finally:
        conn.close()
    from .sync_client import schedule_sync
    schedule_sync()


def _repetido(firma) -> bool:
    ahora = time.monotonic()
    if ahora - _ultimos.get(firma, -1e9) < _VENTANA_REPETIDOS_S:
        return True
    if len(_ultimos) > 1000:
        _ultimos.clear()
    _ultimos[firma] = ahora
    return False


def _envolver(original, subtipo: str, operacion: str, es_funcion: bool = False):
    if getattr(original, "_audit_tracer_original", None) is not None:
        return original

    @functools.wraps(original)
    def envoltura(*args, **kwargs):
        if not _activo or _profundidad.get() > 0:
            return original(*args, **kwargs)
        if es_funcion:
            modelo = type(args[0]).__name__ if args else "estimador"
            X = args[1] if len(args) > 1 else kwargs.get("X")
        else:
            modelo = type(args[0]).__name__
            X = args[1] if len(args) > 1 else kwargs.get("X")
        token = _profundidad.set(_profundidad.get() + 1)
        try:
            resultado = original(*args, **kwargs)
        except Exception as exc:
            guard(_registrar, "MODELADO_FALLIDO", subtipo, modelo, operacion, X, exc,
                  _contexto=f"Registro de MODELADO_FALLIDO {modelo}.{operacion}")
            raise
        finally:
            _profundidad.reset(token)
        if subtipo == "PREDICCION" and _repetido((id(args[0]), operacion, getattr(X, "_dataset_nombre", None))):
            return resultado
        guard(_registrar, "MODELADO", subtipo, modelo, operacion, X,
              _contexto=f"Registro de MODELADO {modelo}.{operacion}")
        return resultado

    envoltura._audit_tracer_original = original
    return envoltura


# ──────────────────────────────────────────────────────────────
# APLICACIÓN SOBRE SCIKIT-LEARN
# ──────────────────────────────────────────────────────────────

def _envolver_metodos_propios(cls) -> None:
    for nombre in METODOS_ENTRENAMIENTO + METODOS_PREDICCION:
        metodo = cls.__dict__.get(nombre)
        if metodo is None or not callable(metodo) or getattr(metodo, "_audit_tracer_original", None):
            continue
        subtipo = "ENTRENAMIENTO" if nombre in METODOS_ENTRENAMIENTO else "PREDICCION"
        try:
            setattr(cls, nombre, _envolver(metodo, subtipo, nombre))
        except (TypeError, AttributeError):
            continue


def _envolver_clase(cls) -> None:
    """
    Envuelve fit/predict de la clase y de toda su jerarquía: muchos métodos
    viven en mixins que no heredan de BaseEstimator (p. ej. predict de
    LogisticRegression está en LinearClassifierMixin).
    """
    for clase in getattr(cls, "__mro__", (cls,)):
        if clase is object:
            continue
        _envolver_metodos_propios(clase)


def _todas_las_subclases(cls):
    pendientes, vistas = [cls], set()
    while pendientes:
        actual = pendientes.pop()
        for sub in actual.__subclasses__():
            if sub not in vistas:
                vistas.add(sub)
                pendientes.append(sub)
    return vistas


def _parchear_base(modulo_base) -> None:
    """Envuelve los estimadores ya definidos y los que se definan después."""
    base = modulo_base.BaseEstimator
    for mixin in ("TransformerMixin", "ClusterMixin", "OutlierMixin"):
        clase = getattr(modulo_base, mixin, None)
        if clase is not None:
            _envolver_clase(clase)
    for sub in _todas_las_subclases(base):
        _envolver_clase(sub)
    if getattr(base.__init_subclass__, "_audit_tracer_original", None) is None:
        original = base.__dict__.get("__init_subclass__")
        original_func = original.__func__ if isinstance(original, classmethod) else None

        def __init_subclass__(cls, **kwargs):
            if original_func is not None:
                original_func(cls, **kwargs)
            else:
                super(base, cls).__init_subclass__(**kwargs)
            guard(_envolver_clase, cls, _contexto="Captura de modelado en una subclase nueva")

        __init_subclass__._audit_tracer_original = original or True
        base.__init_subclass__ = classmethod(__init_subclass__)


def _parchear_validacion(modulo) -> None:
    for nombre in FUNCIONES_VALIDACION:
        funcion = getattr(modulo, nombre, None)
        if callable(funcion):
            setattr(modulo, nombre, _envolver(funcion, "VALIDACION", nombre, es_funcion=True))


def _aplicar_si_cargado() -> None:
    if "sklearn.base" in sys.modules:
        guard(_parchear_base, sys.modules["sklearn.base"], _contexto="Captura de modelado (sklearn.base)")
    for nombre in _MODULOS_VALIDACION:
        if nombre in sys.modules:
            guard(_parchear_validacion, sys.modules[nombre], _contexto=f"Captura de modelado ({nombre})")


class _GanchoImportacion(importlib.abc.MetaPathFinder):
    """Aplica la captura apenas se importa sklearn.base o sklearn.model_selection."""

    _OBJETIVOS = ("sklearn.base",) + _MODULOS_VALIDACION

    def find_spec(self, nombre, ruta, objetivo=None):
        if nombre not in self._OBJETIVOS:
            return None
        spec = importlib.machinery.PathFinder.find_spec(nombre, ruta)
        if spec is None or spec.loader is None or not hasattr(spec.loader, "exec_module"):
            return spec
        cargador = spec.loader
        ejecutar_original = cargador.exec_module

        def exec_module(modulo):
            ejecutar_original(modulo)
            if nombre == "sklearn.base":
                guard(_parchear_base, modulo, _contexto="Captura de modelado (sklearn.base)")
            else:
                guard(_parchear_validacion, modulo, _contexto=f"Captura de modelado ({nombre})")

        cargador.exec_module = exec_module
        return spec


def activate() -> None:
    """Activa la captura de modelado. Idempotente; no hace nada sin scikit-learn instalado."""
    global _activo, _gancho
    if not habilitado():
        return
    _activo = True
    _aplicar_si_cargado()
    if _gancho is None and not all(n in sys.modules for n in _GanchoImportacion._OBJETIVOS):
        _gancho = _GanchoImportacion()
        sys.meta_path.insert(0, _gancho)


def deactivate() -> None:
    """
    Suspende la captura (los métodos envueltos pasan directo al original).
    Queda registrado como AUDITORIA_DESACTIVADA, igual que los demás interceptores.
    """
    global _activo
    if not _activo:
        return
    _activo = False
    try:
        from .data_capture import log_deactivation
        log_deactivation("model_capture (fit, predict, validación cruzada)", get_connection)
    except Exception as exc:
        log_internal_error("No se pudo registrar la desactivación de model_capture", exc)
