"""
Caso de uso 2 (línea base) — Trabajo habitual de un científico de datos con
MIMIC-III Demo: carga las admisiones y exporta una muestra pequeña.

Se ejecuta varios días seguidos, en horario laboral, para construir el
promedio histórico del usuario. La única línea relacionada con la auditoría
es `import audit_tracer`.

Uso: python caso2_muestra_habitual.py <carpeta_mimic> <carpeta_salida> <filas>
"""
import audit_tracer  # noqa: F401  (única línea añadida al script del analista)

import os
import sys

import pandas as pd

datos, salida, filas = sys.argv[1], sys.argv[2], int(sys.argv[3])
os.makedirs(salida, exist_ok=True)

laboratorio = pd.read_csv(os.path.join(datos, "LABEVENTS.csv"))
muestra = laboratorio.sample(n=filas, random_state=filas)
muestra.to_csv(os.path.join(salida, f"muestra_laboratorio_{filas}.csv"), index=False)

print(f"muestra={len(muestra)}")
