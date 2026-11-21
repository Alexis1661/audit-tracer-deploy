"""
Caso de uso 1 — Flujo de análisis normal sobre MIMIC-III Clinical Database Demo v1.4.

Es el código que escribiría un científico de datos para preparar un reporte
clínico de la cohorte de admisiones. La única línea relacionada con la
auditoría es `import audit_tracer`: no hay llamadas a la librería, ni
envoltorios, ni nombres de dataset puestos a mano.

Uso: python caso1_analisis_cohorte.py <carpeta_mimic> <carpeta_salida>
"""
import audit_tracer  # noqa: F401  (única línea añadida al script del analista)

import os
import sys

import pandas as pd

datos, salida = sys.argv[1], sys.argv[2]
os.makedirs(salida, exist_ok=True)

# 1. Carga
pacientes = pd.read_csv(os.path.join(datos, "PATIENTS.csv"))
admisiones = pd.read_csv(os.path.join(datos, "ADMISSIONS.csv"))

# 2. Consulta de las columnas del estudio
admisiones = admisiones[[
    "subject_id", "hadm_id", "admittime", "dischtime", "deathtime",
    "admission_type", "insurance", "language", "diagnosis", "hospital_expire_flag",
]]

# 3. Limpieza y preparación
admisiones = admisiones.fillna({"language": "DESCONOCIDO", "deathtime": ""})
cohorte = admisiones.merge(pacientes, on="subject_id", how="left")
cohorte = cohorte.drop(columns=["row_id", "dod_ssn"])
cohorte = cohorte.dropna(subset=["dischtime"])
cohorte = cohorte.rename(columns={"hospital_expire_flag": "fallecio_en_hospital", "gender": "sexo"})

# 4. Exportación del reporte clínico de la cohorte
cohorte.to_csv(os.path.join(salida, "reporte_clinico_cohorte.csv"), index=False)

# 5. Anexo de laboratorio: creatinina sérica de toda la cohorte
laboratorio = pd.read_csv(os.path.join(datos, "LABEVENTS.csv"))
creatinina = laboratorio.query("itemid == 50912")
creatinina = creatinina.dropna(subset=["valuenum"])
creatinina.to_csv(os.path.join(salida, "anexo_creatinina.csv"), index=False)

print(f"cohorte={len(cohorte)} creatinina={len(creatinina)}")
