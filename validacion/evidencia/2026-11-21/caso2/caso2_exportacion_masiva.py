"""
Caso de uso 2 (comportamiento anómalo) — El mismo usuario, a las 3 de la
mañana, exporta la tabla completa de resultados de laboratorio de MIMIC-III
Demo: muchas más filas que su promedio histórico y fuera de su horario.

La única línea relacionada con la auditoría es `import audit_tracer`.

Uso: python caso2_exportacion_masiva.py <carpeta_mimic> <carpeta_salida>
"""
import audit_tracer  # noqa: F401  (única línea añadida al script del analista)

import os
import sys

import pandas as pd

datos, salida = sys.argv[1], sys.argv[2]
os.makedirs(salida, exist_ok=True)

laboratorio = pd.read_csv(os.path.join(datos, "LABEVENTS.csv"))
laboratorio.to_csv(os.path.join(salida, "extraccion_laboratorio_completa.csv"), index=False)

print(f"exportadas={len(laboratorio)}")
