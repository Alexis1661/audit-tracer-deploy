import pandas as pd
from audit_tracer import AuditTracer

print("1. Iniciando audit_tracer...")
# Inicializar el tracer (esto debería activar las intercepciones)
tracer = AuditTracer() 
tracer.start() 

print("2. Creando datos de prueba...")
# Crear un dataset de prueba
data = {
    'paciente_id': [1, 2, 3, 4, 5],
    'diagnostico': ['A', 'B', 'A', 'C', 'B']
}
df = pd.DataFrame(data)

print("3. Exportando los datos a CSV...")
# Exportar los datos (esto es lo que audit_tracer debe capturar en silencio)
df.to_csv('reporte_pacientes_demo.csv', index=False)
print("4. ¡Exportación finalizada exitosamente!")
