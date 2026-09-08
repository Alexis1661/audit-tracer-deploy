"""
scratch/seed_demo_data.py
==========================
Siembra datos de demo en audit_trail.db para probar en la UI:
  - HU-2.3: exportaciones (normales y masivas, con/sin sobrescritura)
  - HU-4.2: filtros combinados por usuario, fecha, dataset y tipo de acción
  - HU-4.4: eventos críticos (intentos fallidos en ventana, exportación
    masiva, acceso fuera de horario laboral) + exportación a CSV

No borra datos existentes; solo agrega. Ejecutar desde la raíz del repo:
    python scratch/seed_demo_data.py
"""

import os
import sys
sys.path.append(os.getcwd())

from audit_tracer.db import get_central_connection
from audit_tracer.models.audit_log import insert_event
from audit_tracer.auth.registro import register_user
from audit_tracer.models.usuarios import get_user_by_email

conn = get_central_connection()

# ── Usuarios de demo (además del admin ya sembrado) ──────────────────────
DEMO_USERS = [
    ("analista.garcia@audit.com", "Analista123*", "ANALISTA"),
    ("cientifico.lopez@audit.com", "Cientifico123*", "CIENTIFICO_DATOS"),
    ("auditor.perez@audit.com", "Auditor123*", "AUDITOR"),
]

admin = get_user_by_email(conn, "admin@audit.com")
if not admin:
    raise SystemExit("Primero ejecuta: python scratch/seed_admin.py")
admin_id = admin["usuario_id"]

user_ids = {}
for email, pwd, rol in DEMO_USERS:
    existing = get_user_by_email(conn, email)
    if existing:
        user_ids[email] = existing["usuario_id"]
        continue
    try:
        user_ids[email] = register_user(conn, email, pwd, rol, admin_id=admin_id)
        print(f"Usuario creado: {email} ({rol})")
    except ValueError as e:
        print(f"Aviso: {e}")

u_analista = user_ids.get("analista.garcia@audit.com")
u_cientifico = user_ids.get("cientifico.lopez@audit.com")
u_auditor = user_ids.get("auditor.perez@audit.com")


def ev(**kwargs):
    kwargs.setdefault("nivel_alerta", "NORMAL")
    insert_event(conn, kwargs)


# ── HU-2.1/2.3: accesos y exportaciones normales, repartidos en varios días ──
ev(usuario_id=admin_id, sesion_id="s-admin-1", tipo_accion="CARGA",
   dataset_nombre="PATIENTS.csv", timestamp="2026-08-10T09:15:00")
ev(usuario_id=u_analista, sesion_id="s-ana-1", tipo_accion="CARGA",
   dataset_nombre="PATIENTS.csv", timestamp="2026-08-11T10:00:00")
ev(usuario_id=u_analista, sesion_id="s-ana-1", tipo_accion="CONSULTA",
   dataset_nombre="PATIENTS.csv", timestamp="2026-08-11T10:05:00")
ev(usuario_id=u_cientifico, sesion_id="s-cie-1", tipo_accion="CARGA",
   dataset_nombre="admissions.xlsx", timestamp="2026-08-12T14:30:00")
ev(usuario_id=u_cientifico, sesion_id="s-cie-1", tipo_accion="TRANSFORMACION",
   dataset_nombre="admissions.xlsx", timestamp="2026-08-12T14:45:00")
ev(usuario_id=u_analista, sesion_id="s-ana-2", tipo_accion="EXPORTACION",
   dataset_nombre="PATIENTS.csv", ruta_destino="outputs/patients_clean.csv",
   filas_exportadas=180, sobrescritura=0, timestamp="2026-08-13T11:20:00")
ev(usuario_id=u_auditor, sesion_id="s-aud-1", tipo_accion="EXPORTACION",
   dataset_nombre="admissions.xlsx", ruta_destino="outputs/admissions_report.xlsx",
   filas_exportadas=320, sobrescritura=1, timestamp="2026-08-14T16:00:00",
   nivel_alerta="ADVERTENCIA", motivo_alerta="Archivo de destino sobrescrito")
ev(usuario_id=u_cientifico, sesion_id="s-cie-2", tipo_accion="CARGA",
   dataset_nombre="labs.csv", timestamp="2026-08-15T08:45:00")
ev(usuario_id=admin_id, sesion_id="s-admin-2", tipo_accion="CONSULTA",
   dataset_nombre="labs.csv", timestamp="2026-08-16T09:30:00")

# ── HU-4.4 CA1-b: exportación masiva (>1000 filas) → CRITICO ──────────────
ev(usuario_id=u_analista, sesion_id="s-ana-3", tipo_accion="EXPORTACION",
   dataset_nombre="admissions.xlsx", ruta_destino="outputs/admissions_full.xlsx",
   filas_exportadas=4200, sobrescritura=0, timestamp="2026-08-17T15:10:00",
   nivel_alerta="CRITICO", motivo_alerta="Exportación masiva: 4200 filas (> 1000)")

# ── HU-4.4 CA1-c: acceso fuera de horario laboral (madrugada) → CRITICO ───
ev(usuario_id=u_cientifico, sesion_id="s-cie-3", tipo_accion="CONSULTA",
   dataset_nombre="PATIENTS.csv", timestamp="2026-08-18T02:15:00",
   nivel_alerta="CRITICO",
   motivo_alerta="Acceso fuera de horario laboral (08:00-18:00 UTC): 02:15")
ev(usuario_id=u_auditor, sesion_id="s-aud-2", tipo_accion="CARGA",
   dataset_nombre="labs.csv", timestamp="2026-08-19T22:40:00",
   nivel_alerta="CRITICO",
   motivo_alerta="Acceso fuera de horario laboral (08:00-18:00 UTC): 22:40")

# ── HU-4.4 CA1-a: >3 intentos fallidos en <5 min del mismo usuario → CRITICO ──
base = "2026-08-19T09:0{}:00"
for i in range(3):
    ev(usuario_id=u_analista, sesion_id=f"s-fail-{i}", tipo_accion="ACCESO_FALLIDO",
       motivo_fallo="Credenciales inválidas", timestamp=base.format(i),
       nivel_alerta="ADVERTENCIA" if i == 2 else "NORMAL",
       motivo_alerta=f"{i + 1} intentos fallidos" if i == 2 else None)
ev(usuario_id=u_analista, sesion_id="s-fail-3", tipo_accion="ACCESO_FALLIDO",
   motivo_fallo="Credenciales inválidas", timestamp="2026-08-19T09:03:30",
   nivel_alerta="CRITICO", motivo_alerta="4 intentos fallidos en menos de 5 minutos")

# ── CA1 usuario no identificado → CRITICO (ya existente de HU-2.1) ────────
ev(usuario_id="DESCONOCIDO", sesion_id="s-anon-1", tipo_accion="CONSULTA",
   dataset_nombre="labs.csv", timestamp="2026-08-20T13:00:00",
   nivel_alerta="CRITICO", motivo_alerta="Operación ejecutada por usuario no identificado")

conn.close()

print("\nListo. Usuarios de prueba:")
for email, pwd, rol in DEMO_USERS:
    print(f"  {email} / {pwd}  ({rol})")
print("\nDatasets sembrados: PATIENTS.csv, admissions.xlsx, labs.csv")
print("Rango de fechas: 2026-08-10 a 2026-08-20")
