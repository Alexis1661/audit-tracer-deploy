"""
HU-7.3 — Mapeo normativo explícito de los eventos de auditoría.

Tabla tipo_accion → referencias normativas (HIPAA y Ley 1581 de 2012) que el
evento ayuda a demostrar. Se usa para anotar cada fila del reporte de
auditoría (HU-4.5) con su base normativa, de modo que un auditor externo
pueda usar el CSV exportado directamente como evidencia de cumplimiento.

Fuente: la matriz de trazabilidad normativa de HU-6.6
(docs/matriz_trazabilidad_normativa.csv). Para cada tipo_accion se toman
todos los controles (CT-xx) cuya columna `eventos_audit_log` lo menciona y
se unen sus cláusulas HIPAA y de la Ley 1581.

La tabla vive aquí, y no se lee del CSV en tiempo de ejecución, porque
docs/ no forma parte del paquete instalable (pyproject.toml solo empaqueta
audit_tracer*). tests/test_mapeo_normativo.py verifica que esta tabla sea
exactamente la que se deriva de la matriz: si la matriz cambia y la tabla
no, la suite falla.
"""

from typing import Dict, Optional, Tuple, TypedDict


class ReferenciaNormativa(TypedDict):
    hipaa: Tuple[str, ...]
    ley_1581: Tuple[str, ...]
    controles: Tuple[str, ...]


# CA3 — Texto explícito para los eventos sin referencia normativa asociada.
# Nunca se deja la celda vacía: un vacío es ambiguo para el auditor (¿falta
# el dato o no aplica?), este texto no lo es.
SIN_REFERENCIA_NORMATIVA = "Sin referencia normativa asociada"

# CA1 — Sub-tarea 1: tabla de mapeo tipo_evento → referencia normativa.
MAPEO_NORMATIVO: Dict[str, ReferenciaNormativa] = {
    # ── Acceso a datos clínicos ──────────────────────────────────
    "CARGA": {
        "hipaa": ("§164.312(b)",),
        "ley_1581": ("Art. 17 lit. m",),
        "controles": ("CT-12",),
    },
    "CONSULTA": {
        "hipaa": ("§164.312(b)",),
        "ley_1581": ("Art. 17 lit. m",),
        "controles": ("CT-12",),
    },
    # ── Transformación ───────────────────────────────────────────
    "TRANSFORMACION": {
        "hipaa": ("§164.312(b)", "§164.312(c)(1)"),
        "ley_1581": ("Art. 4 lit. d", "Art. 17 lit. m"),
        "controles": ("CT-13",),
    },
    # ── Exportación ──────────────────────────────────────────────
    "EXPORTACION": {
        "hipaa": ("§164.312(b)", "§164.308(a)(1)(ii)(D)", "§164.528 (apoyo)"),
        "ley_1581": ("Art. 4 lit. f", "Art. 17 lit. m"),
        "controles": ("CT-14",),
    },
    # ── Autenticación y control de acceso ────────────────────────
    "ACCESO_FALLIDO": {
        "hipaa": (
            "§164.312(d)", "§164.308(a)(5)(ii)(C)", "§164.312(a)(1)",
            "§164.308(a)(6)(ii)", "§164.308(a)(1)(ii)(D)", "§164.312(b)",
        ),
        "ley_1581": ("Art. 4 lit. g", "Art. 4 lit. h", "Art. 17 lit. d", "Art. 17 lit. n"),
        "controles": ("CT-03", "CT-04", "CT-05", "CT-15"),
    },
    "ACCESO_DENEGADO": {
        "hipaa": (
            "§164.312(a)(1)", "§164.308(a)(4)(ii)(B)", "§164.502(b)",
            "§164.312(b)", "§164.308(a)(1)(ii)(D)",
        ),
        "ley_1581": ("Art. 4 lit. f", "Art. 18 lit. j", "Art. 17 lit. d"),
        "controles": ("CT-09", "CT-11"),
    },
    "CREACION_USUARIO": {
        "hipaa": ("§164.312(a)(2)(i)", "§164.308(a)(4)(ii)(C)", "§164.308(a)(3)(ii)(B)"),
        "ley_1581": ("Art. 4 lit. g", "Art. 17 lit. d", "Art. 18 lit. j"),
        "controles": ("CT-02", "CT-10"),
    },
    "MODIFICACION_ROL": {
        "hipaa": ("§164.308(a)(4)(ii)(C)", "§164.308(a)(3)(ii)(B)"),
        "ley_1581": ("Art. 17 lit. d", "Art. 18 lit. j"),
        "controles": ("CT-10",),
    },
    "GENERACION_TOKEN": {
        "hipaa": ("§164.312(d)", "§164.312(a)(1)", "§164.308(a)(3)(ii)(C)"),
        "ley_1581": ("Art. 4 lit. g", "Art. 17 lit. d", "Art. 18 lit. j"),
        "controles": ("CT-06",),
    },
    "REVOCACION_TOKEN": {
        "hipaa": ("§164.312(d)", "§164.312(a)(1)", "§164.308(a)(3)(ii)(C)"),
        "ley_1581": ("Art. 4 lit. g", "Art. 17 lit. d", "Art. 18 lit. j"),
        "controles": ("CT-06",),
    },
    "CONFIRMACION_LOGIN_DISPOSITIVO": {
        "hipaa": ("§164.312(d)",),
        "ley_1581": ("Art. 4 lit. g", "Art. 17 lit. d"),
        "controles": ("CT-07",),
    },
    # ── Sesiones y atribución ────────────────────────────────────
    "ATRIBUCION_SESION": {
        "hipaa": ("§164.312(a)(2)(i)", "§164.312(b)"),
        "ley_1581": ("Art. 17 lit. m",),
        "controles": ("CT-16",),
    },
    "INICIO_SESION": {
        "hipaa": ("§164.312(b)",),
        "ley_1581": ("Art. 17 lit. m",),
        "controles": ("CT-17",),
    },
    "CIERRE_SESION": {
        "hipaa": ("§164.312(b)",),
        "ley_1581": ("Art. 17 lit. m",),
        "controles": ("CT-17",),
    },
    "SESION_INTERRUMPIDA": {
        "hipaa": ("§164.312(b)",),
        "ley_1581": ("Art. 17 lit. m",),
        "controles": ("CT-17",),
    },
    "AUDITORIA_DESACTIVADA": {
        "hipaa": ("§164.312(b)", "§164.308(a)(1)(ii)(D)"),
        "ley_1581": ("Art. 17 lit. d",),
        "controles": ("CT-18",),
    },
    # ── Integridad del registro y transmisión ────────────────────
    "INTENTO_MODIFICACION": {
        "hipaa": ("§164.312(c)(1)", "§164.312(b)"),
        "ley_1581": ("Art. 17 lit. d", "Art. 18 lit. b"),
        "controles": ("CT-21",),
    },
    "INTENTO_ELIMINACION": {
        "hipaa": ("§164.312(c)(1)", "§164.312(b)"),
        "ley_1581": ("Art. 17 lit. d", "Art. 18 lit. b"),
        "controles": ("CT-21",),
    },
    "FIRMA_INVALIDA": {
        "hipaa": ("§164.312(c)(2)", "§164.312(e)(2)(i)", "§164.312(d)"),
        "ley_1581": ("Art. 17 lit. d", "Art. 18 lit. b"),
        "controles": ("CT-22",),
    },
    "SINCRONIZACION_RECHAZADA": {
        "hipaa": ("§164.312(d)", "§164.312(e)(1)"),
        "ley_1581": ("Art. 4 lit. h", "Art. 17 lit. d"),
        "controles": ("CT-25",),
    },
}


def obtener_mapeo(tipo_accion: Optional[str]) -> Optional[ReferenciaNormativa]:
    """CA1 — Referencias estructuradas de un tipo_accion, o None si no tiene."""
    if not tipo_accion:
        return None
    return MAPEO_NORMATIVO.get(tipo_accion.strip().upper())


def referencia_normativa(tipo_accion: Optional[str]) -> str:
    """
    CA2/CA3 — Texto de la columna `referencia_normativa` del reporte.

    Formato (una sola celda, separadores ';' como en la matriz HU-6.6):
        HIPAA §164.312(b); §164.312(c)(1) | Ley 1581 Art. 4 lit. d; Art. 17 lit. m | Matriz CT-13

    Si el tipo_accion no tiene referencias (o viene vacío), devuelve
    SIN_REFERENCIA_NORMATIVA en lugar de una cadena vacía.
    """
    mapeo = obtener_mapeo(tipo_accion)
    if mapeo is None:
        return SIN_REFERENCIA_NORMATIVA

    partes = []
    if mapeo["hipaa"]:
        partes.append("HIPAA " + "; ".join(mapeo["hipaa"]))
    if mapeo["ley_1581"]:
        partes.append("Ley 1581 " + "; ".join(mapeo["ley_1581"]))
    if not partes:
        return SIN_REFERENCIA_NORMATIVA
    if mapeo["controles"]:
        partes.append("Matriz " + "; ".join(mapeo["controles"]))
    return " | ".join(partes)
