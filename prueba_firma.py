import time
from audit_tracer.sync_client import configure_sync
from audit_tracer.models.audit_log import insert_event_and_enqueue_sync
from audit_tracer.db import get_connection

# 1. Configura el cliente (esto genera tus llaves y envía la pública al servidor)
configure_sync("http://localhost:5000", "tk_4vBO7IaXXhQ-Ehqcf5NQ0DnXdd5SbJi_wOKZxtIP0Gg")

# 2. Creamos un evento falso como si hubieras consultado datos
evento = {
    "usuario_id": "8059f3ba-40e5-4ac5-a64d-2b45976584ac",
    "tipo_accion": "CONSULTA_CRITICA",
    "dataset_nombre": "PACIENTES_VIH",
    "columnas_afectadas": "['diagnostico', 'nombre']",
    "contexto_ejecucion": "prueba_firma.py"
}

# 3. Guardar el evento (aquí se firma automáticamente)
conn = get_connection("audit_trail.db")
insert_event_and_enqueue_sync(conn, evento)
conn.close()

print("Evento generado y firmado. Esperando 5 segundos a que se sincronice al servidor...")
time.sleep(5)
print("¡Listo! Ve a la sección de 'Eventos' en tu dashboard para verlo.")
from audit_tracer.sync_client import sync_now

print("Forzando sincronización inmediata...")
sync_now()
print("¡Listo! Ve a la sección de 'Eventos' en tu dashboard para verlo.")
