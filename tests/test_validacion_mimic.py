"""
tests/test_validacion_mimic.py
==============================
Sección 7.4 del documento final — validación con MIMIC-III Clinical Database
Demo v1.4 mediante tres casos de uso. Cada afirmación del documento es una
prueba.

Corre el sistema real: el servidor central (app.py) en su propio proceso,
la científica de datos autenticada con código de dispositivo y sus scripts de
pandas en procesos aparte, y el auditor y el administrador por HTTP sobre el
dashboard (ver validacion/casos_mimic.py).

Las afirmaciones que el sistema hoy NO cumple están marcadas xfail(strict=True)
con la causa: la suite sigue verde, el incumplimiento queda visible en cada
ejecución y, si alguien corrige el sistema, la prueba pasa a XPASS y obliga a
quitar la marca.

Requiere los CSV de MIMIC-III Demo (python validacion/descargar_mimic.py o
MIMIC_DEMO_DIR). Sin ellos, el módulo se omite.
"""

import os
from pathlib import Path

import pytest

from validacion.casos_mimic import ValidacionMIMIC, carpeta_mimic

DATOS = carpeta_mimic()
pytestmark = pytest.mark.skipif(
    DATOS is None, reason="Faltan los CSV de MIMIC-III Demo: python validacion/descargar_mimic.py")

NO_CUMPLE = {
    "1.4b": "lineage.py agrupa por (sesion_id, dataset_nombre) y el merge renombra el dataset: "
            "la cadena de la cohorte se parte en dos grafos sin arista",
    "2.1": "app.py:1126 solo aplica el detector a eventos sin firma y no CRITICO; la librería firma "
           "todo y marca CRITICO toda exportación > 1000 filas",
    "2.1b": "el horario habitual se calcula con todos los eventos previos del usuario, incluidos "
            "INICIO_SESION y CARGA de la misma sesión de las 03:10",
    "2.3": "como el detector no corre, motivo_alerta solo dice 'Exportación masiva'",
    "3.2b": "REPORT_CSV_COLUMNS no incluye sesion_id, contexto_ejecucion, hash_integridad, "
            "ruta_destino ni filas_exportadas",
}

IDS = ["1.1", "1.2", "1.3", "1.4a", "1.4b", "1.5",
       "2.1", "2.1b", "2.1c", "2.2", "2.3", "2.4a", "2.4b",
       "3.1", "3.2a", "3.2b", "3.3", "3.4a", "3.4b"]


@pytest.fixture(scope="module")
def resultados(tmp_path_factory):
    evidencia = Path(os.environ.get("VALIDACION_EVIDENCIA_DIR") or tmp_path_factory.mktemp("evidencia_mimic"))
    val = ValidacionMIMIC(evidencia, DATOS, base=tmp_path_factory.mktemp("sistema_mimic"))
    resumen = val.ejecutar()
    return {v["id"]: v for v in resumen["verificaciones"]}


def test_se_ejecutaron_todas_las_verificaciones(resultados):
    assert sorted(resultados) == sorted(IDS)


@pytest.mark.parametrize("vid", [
    pytest.param(i, marks=pytest.mark.xfail(strict=True, reason=NO_CUMPLE[i])) if i in NO_CUMPLE else i
    for i in IDS
])
def test_afirmacion_del_documento(resultados, vid):
    v = resultados[vid]
    assert v["cumple"], f"{v['id']} {v['afirmacion']}\n{v['detalle']}"
