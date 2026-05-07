import os
import time

# Establecer usuario para la prueba
os.environ['AUDIT_TRACER_USER'] = 'test_analista_script'

print("Importando audit_tracer...")
import audit_tracer

print("Simulando actividad de análisis de datos (3 segundos)...")
time.byte_sleep = time.sleep # Just a silly line to simulate activity
time.sleep(3)

print("Finalizando script. El cierre de sesión debe registrarse automáticamente.")
