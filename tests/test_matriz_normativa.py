"""
HU-6.6 — Matriz de trazabilidad normativa.

La matriz (docs/matriz_trazabilidad_normativa.csv) es la fuente que reutiliza
HU-7.3. Estas pruebas evitan que quede desactualizada: si se renombra un
archivo o una prueba citada como evidencia, la suite falla.
"""

import csv
import re
from pathlib import Path

import pytest

RAIZ = Path(__file__).resolve().parent.parent
MATRIZ_CSV = RAIZ / "docs" / "matriz_trazabilidad_normativa.csv"
MATRIZ_MD = RAIZ / "docs" / "matriz_trazabilidad_normativa.md"

COLUMNAS = [
    "id", "categoria", "control_tecnico", "componente",
    "hipaa", "ley_1581", "hu", "eventos_audit_log", "evidencia",
]

# Una ruta de archivo dentro de la celda "componente", p. ej. app.py o audit_tracer/merkle.py
_RUTA = re.compile(r"[\w./-]+\.(?:py|sql|md)")


def _filas():
    with open(MATRIZ_CSV, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _lista(celda):
    return [p.strip() for p in celda.split(";") if p.strip()]


FILAS = _filas()


def test_columnas_minimas_ca1():
    with open(MATRIZ_CSV, encoding="utf-8", newline="") as f:
        assert next(csv.reader(f)) == COLUMNAS


def test_ids_unicos_y_consecutivos():
    ids = [fila["id"] for fila in FILAS]
    assert ids == [f"CT-{i:02d}" for i in range(1, len(ids) + 1)]


@pytest.mark.parametrize("fila", FILAS, ids=lambda f: f["id"])
def test_cada_control_tiene_los_campos_de_ca1(fila):
    for campo in ("control_tecnico", "componente", "hu", "evidencia"):
        assert fila[campo].strip(), f"{fila['id']}: '{campo}' vacío"
    assert _lista(fila["hipaa"]), f"{fila['id']}: sin cláusula HIPAA"
    assert _lista(fila["ley_1581"]), f"{fila['id']}: sin cláusula de la Ley 1581"
    assert all(c.startswith("§164.") for c in _lista(fila["hipaa"]))
    assert all(c.startswith("Art. ") for c in _lista(fila["ley_1581"]))
    assert all(re.fullmatch(r"HU-\d+\.\d+", hu) for hu in _lista(fila["hu"]))


@pytest.mark.parametrize("fila", FILAS, ids=lambda f: f["id"])
def test_componentes_citados_existen(fila):
    rutas = _RUTA.findall(fila["componente"])
    assert rutas, f"{fila['id']}: el componente no cita ningún archivo"
    for ruta in rutas:
        assert (RAIZ / ruta).is_file(), f"{fila['id']}: no existe {ruta}"


@pytest.mark.parametrize("fila", FILAS, ids=lambda f: f["id"])
def test_pruebas_citadas_como_evidencia_existen(fila):
    for referencia in _lista(fila["evidencia"]):
        archivo, *nombres = referencia.split("::")
        ruta = RAIZ / archivo
        assert ruta.is_file(), f"{fila['id']}: no existe {archivo}"
        codigo = ruta.read_text(encoding="utf-8")
        *clases, funcion = nombres
        for clase in clases:
            assert re.search(rf"^class {clase}\b", codigo, re.M), f"{fila['id']}: falta {referencia}"
        assert re.search(rf"^\s*def {funcion}\(", codigo, re.M), f"{fila['id']}: falta {referencia}"


def test_cubre_los_controles_exigidos_por_ca2():
    texto = " ".join(f"{f['control_tecnico']} {f['componente']}".lower() for f in FILAS)
    for control in ("bcrypt", "rol", "bloqueo", "firma", "token", "sha-256",
                    "inmutabilidad", "merkle", "https"):
        assert control in texto, f"La matriz no cubre: {control}"


def test_documento_anexo_incluye_todos_los_controles_ca3():
    documento = MATRIZ_MD.read_text(encoding="utf-8")
    for fila in FILAS:
        assert f"| {fila['id']} |" in documento, f"{fila['id']} no aparece en el anexo"
