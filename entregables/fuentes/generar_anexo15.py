"""
Genera entregables/05_modelo_amenazas_stride.md y 06_matriz_trazabilidad_normativa.md
(Anexo 15) a partir de los anexos que ya existen en docs/, anteponiendo una
sección de verificación con los conteos recalculados desde los CSV.

    python entregables/fuentes/generar_anexo15.py
"""
import csv
import re
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
DOCS = RAIZ / "docs"
SALIDA = RAIZ / "entregables"
FECHA = "2026-11-21"
COMPONENTES = ["Librería", "Canal de transmisión", "Servidor central", "Dashboard"]
CATEGORIAS = ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service",
              "Elevation of Privilege"]


def _cuerpo(md: Path) -> str:
    """El anexo original sin su título H1 y con los niveles de encabezado intactos."""
    texto = md.read_text(encoding="utf-8")
    return re.sub(r"\A# [^\n]*\n", "", texto, count=1)


def stride() -> str:
    filas = list(csv.DictReader(open(DOCS / "modelo_amenazas_stride.csv", encoding="utf-8")))
    por_comp = Counter(f["componente"] for f in filas)
    por_cat = Counter(f["categoria"] for f in filas)
    por_estado = Counter(f["estado"] for f in filas)
    por_riesgo = Counter(f["riesgo_residual"] for f in filas)
    cruce = Counter((f["componente"], f["categoria"]) for f in filas)
    altos = [f for f in filas if f["riesgo_residual"] == "Alto"]
    abiertos = [f for f in filas if f["estado"] != "IMPLEMENTADA"]

    t_comp = "\n".join(
        f"| {c} | " + " | ".join(str(cruce[(c, k)]) for k in CATEGORIAS) + f" | **{por_comp[c]}** |"
        for c in COMPONENTES)
    t_altos = "\n".join(f"| {f['id']} | {f['componente']} | {f['categoria']} | {f['amenaza']} | {f['estado']} |"
                        for f in altos)
    return f"""---
titulo: Modelo de amenazas STRIDE
anexo: Anexo 15 · HU-6.4
fecha: {FECHA}
---

[TOC]

# 0. Verificación de los conteos ({FECHA})

Fuente: `docs/modelo_amenazas_stride.md` y `docs/modelo_amenazas_stride.csv` (commit `7d962a7`, 04/11/2026). Los conteos se recalcularon desde el CSV con `entregables/fuentes/generar_anexo15.py`.

| Medida | Documento final | Real |
|---|---|---|
| Total de amenazas | 54 | **{len(filas)}** |
| Por componente | cuatro componentes | {", ".join(f"{c}: {por_comp[c]}" for c in COMPONENTES)} |
| Por categoría STRIDE | — | {", ".join(f"{k}: {por_cat[k]}" for k in CATEGORIAS)} |
| Estado de la mitigación | — | IMPLEMENTADA: {por_estado['IMPLEMENTADA']}, PARCIAL: {por_estado['PARCIAL']}, PLANEADA: {por_estado['PLANEADA']} |
| Riesgo residual | — | Alto: {por_riesgo['Alto']}, Medio: {por_riesgo['Medio']}, Bajo: {por_riesgo['Bajo']} |
| Riesgos abiertos (mitigación PARCIAL o PLANEADA) | «documentadas como riesgos abiertos» | **{len(abiertos)}** amenazas |
| Riesgos abiertos reproducidos con una prueba (`TestRiesgosAbiertos`) | — | 11 pruebas `xfail(strict=True)` |

| Componente | S | T | R | I | D | E | Total |
|---|---|---|---|---|---|---|---|
{t_comp}
| **Total** | {" | ".join(str(por_cat[k]) for k in CATEGORIAS)} | **{len(filas)}** |

**Amenazas con riesgo residual alto ({len(altos)}):**

| ID | Componente | Categoría | Amenaza | Estado |
|---|---|---|---|---|
{t_altos}

**Estado de las pruebas del modelo (`tests/test_modelo_amenazas.py`, {FECHA}):** 165 pruebas: 153 aprobadas, 8 xfail (riesgos abiertos que siguen abiertos) y 4 fallidas. Las 4 fallas vienen del ayudante `_sesion()` de la prueba, que no crea el token de sesión que el dashboard exige desde el commit `3d7dc2b` (08/11/2026): la petición termina en `/login`. Por eso tres de los once riesgos abiertos (DSH-T1, DSH-I3 y el de fórmulas en CSV) y una mitigación verificada (escape de datos en listados) **no se están comprobando hoy**; no significa que se hayan mitigado. La «Ejecución registrada» de la sección 2 (03/11/2026: 154 superadas, 11 xfail) es anterior a ese cambio.

**Nota sobre el hallazgo funcional de la sección 7** («`POST /admin/usuarios/nuevo` responde HTTP 500»): ya no aplica: desde el commit `cfbdddd` (09/11/2026) la función termina con `redirect(url_for('lista_usuarios'))` (`app.py:465-466`).

{_cuerpo(DOCS / "modelo_amenazas_stride.md")}"""


def matriz() -> str:
    filas = list(csv.DictReader(open(DOCS / "matriz_trazabilidad_normativa.csv", encoding="utf-8")))
    ids = [f["id"] for f in filas]
    por_cat = Counter(f["categoria"] for f in filas)
    md = (DOCS / "matriz_trazabilidad_normativa.md").read_text(encoding="utf-8")
    brechas = re.findall(r"^\| (B\d+) \| ([^|]+) \| ([^|]+) \|", md, re.M)
    hipaa = sorted({c.strip() for f in filas for c in f["hipaa"].split(";") if c.strip()})
    ley = sorted({c.strip() for f in filas for c in f["ley_1581"].split(";") if c.strip()})
    t_brechas = "\n".join(f"| {b} | {d.strip()} | {c.strip()} |" for b, d, c in brechas)
    return f"""---
titulo: Matriz de trazabilidad normativa
anexo: Anexo 15 · HU-6.6
fecha: {FECHA}
---

[TOC]

# 0. Verificación de los conteos ({FECHA})

Fuente: `docs/matriz_trazabilidad_normativa.md` y `docs/matriz_trazabilidad_normativa.csv` (commit `16c34e0`, 01/11/2026).

| Medida | Documento final | Real |
|---|---|---|
| Controles técnicos | 32 | **{len(filas)}** ({ids[0]} a {ids[-1]}, consecutivos) |
| Por categoría | — | {", ".join(f"{k}: {v}" for k, v in por_cat.items())} |
| Brechas documentadas | 10 | **{len(brechas)}** |
| Cláusulas HIPAA distintas citadas | — | {len(hipaa)} |
| Artículos de la Ley 1581 distintos citados | — | {len(ley)} |
| Normas mapeadas | HIPAA y Ley 1581 de 2012 | HIPAA y Ley 1581 de 2012. ISO/IEC 27001/27701 no tienen columna en la matriz. |

**Las {len(brechas)} brechas:**

| ID | Brecha | Cláusula afectada |
|---|---|---|
{t_brechas}

**Vigencia de las brechas al {FECHA}.** B1 está desactualizada: desde el commit `3d7dc2b` (08/11/2026) la sesión web vence a la hora (`PERMANENT_SESSION_LIFETIME=timedelta(hours=1)`, `SESSION_REFRESH_EACH_REQUEST=False`, `app.py:107-109`); es un vencimiento absoluto, no por inactividad. B4 sigue vigente: `.audit_keys/private_key.pem` continúa versionada (`git ls-files .audit_keys`). Las demás se confirmaron en el código.

**Sincronización con la implementación.** `tests/test_matriz_normativa.py` (100 pruebas, todas aprobadas el {FECHA}) comprueba en cada ejecución que la matriz tenga las columnas exigidas e identificadores consecutivos, que los archivos citados como componente existan, que cada prueba citada como evidencia exista (archivo, clase y función) y que el anexo Markdown incluya todos los controles. `tests/test_mapeo_normativo.py::TestCA1TablaDeMapeo::test_tabla_coincide_exactamente_con_la_matriz_hu_6_6` verifica que la tabla de mapeo que usan los reportes sea la que se deriva de esta matriz.

{_cuerpo(DOCS / "matriz_trazabilidad_normativa.md")}"""


def main():
    (SALIDA / "05_modelo_amenazas_stride.md").write_text(stride(), encoding="utf-8")
    (SALIDA / "06_matriz_trazabilidad_normativa.md").write_text(matriz(), encoding="utf-8")
    print("05 y 06 generados")


if __name__ == "__main__":
    main()
