---
titulo: Plan de pruebas
anexo: Anexo 5 · Plan de pruebas
fecha: 2026-11-22
---

[TOC]

# 1. Propósito y alcance

Este plan define cómo se validó el prototipo Audit Tracer frente al tercer y cuarto objetivos específicos: que el sistema capture automáticamente las operaciones sobre datos clínicos, preserve su integridad, controle el acceso y genere evidencia útil para una auditoría regulatoria, sin alterar el trabajo del científico de datos. Consolida la estrategia aplicada durante los seis sprints (6 de abril a 2 de noviembre de 2026), las pruebas de cierre del 20 y 21 de noviembre de 2026 y la segunda ronda de robustez del 21 y 22 de noviembre, que ejecutó el plan de mitigación del modelo STRIDE.

**Elementos bajo prueba:** la librería de captura local (`audit_tracer`), el canal de sincronización HTTPS, el servidor central (base SQLite en modo WAL) y el dashboard web con control de acceso por roles (ADMIN, ANALISTA, AUDITOR y CIENTIFICO_DATOS).

**Fuera de alcance:** pruebas de carga con usuarios concurrentes a escala institucional, pruebas de penetración por un tercero, el despliegue en plataformas distintas de Render y de un servidor Linux propio, y la validación con datos clínicos reales de una institución.

# 2. Estrategia: niveles y tipos de prueba

| Nivel o tipo | Qué se prueba | Cómo y cuándo | Evidencia |
|---|---|---|---|
| Unitarias y de componente | Captura de carga, consulta, transformación, exportación y modelado; modelo de eventos, hash y firmas; sesiones; linaje; Merkle; anomalías; alertas | pytest; se escriben con cada historia de usuario y forman parte de su definición de terminado (sprints 1 a 6 y segunda ronda) | `tests/test_*.py` (Anexo 6, sección 3) |
| Integración | Sincronización local–central y cola ante caídas de red; flujo de código de dispositivo (RFC 8628); dashboard por HTTP; correo por SMTP contra un servidor local | pytest con el servidor real en proceso propio | `test_sync_events`, `test_device_login`, `test_integracion_automatica`, `test_robustez` |
| Seguridad | 32 ataques simulados; mitigaciones y riesgos abiertos del modelo STRIDE (CSRF, suplantación en la API, llaves, sesión, límites de peticiones); RBAC y escalada de privilegios | pytest (HU-6.4 y HU-6.5); los riesgos abiertos se registran como fallos esperados estrictos | `test_ataques_simulados`, `test_modelo_amenazas`, `test_control_acceso`, `test_robustez` |
| Conformidad normativa | Coherencia entre la matriz de trazabilidad (46 controles), el mapeo normativo de los reportes y el código | pytest (HU-6.6 y HU-7.3) | `test_matriz_normativa`, `test_mapeo_normativo` |
| Casos de uso de extremo a extremo | Tres escenarios de uso real sobre MIMIC-III Demo v1.4 (19 verificaciones) | Servidor central real, analista autenticada por código de dispositivo, auditor en el dashboard; 21/11/2026 y de nuevo dentro de la suite del 22/11/2026 | `test_validacion_mimic`, `validacion/casos_mimic.ipynb` |
| Rendimiento | Sobrecarga de la auditoría con 50.000, 200.000 y 1.000.000 de filas | `benchmarks/overhead_referencia.py`, cinco corridas por modo (sin auditoría, con auditoría, con servidor caído); 21/11/2026 | `resultados_benchmark_2026-11-21.json` |
| Validación externa | 26 escenarios en cuatro bloques (A–D) y percepción de usabilidad (SUS) | Evaluador externo con guía paso a paso, notebook en Google Colab y dashboard desplegado; 20/11/2026 | Capítulo 8 y Anexo 13 |

# 3. Entorno y herramientas

- Python 3.12.6, pandas 3.0.2, scikit-learn 1.7.0 y pytest, con resultados exportados en JUnit XML; Windows 11.
- Hardware del benchmark: AMD Ryzen 5 7520U (4 núcleos, 8 hilos), 15,3 GB de RAM y SSD NVMe.
- Servidor central ejecutado como proceso independiente (`python app.py`) con cuentas creadas por `SEED_USUARIOS`; en producción se sirve con Gunicorn (`wsgi.py`).
- Correo de alertas entregado en una carpeta local (`AUDIT_ALERTAS_OUTBOX`) en los casos de uso y, en la suite, enviado por protocolo SMTP a un servidor SMTP local.
- Reloj controlado (`validacion/reloj.py`) para fijar la hora del día en los casos que dependen del horario.
- Validación externa: Google Colab como entorno del analista (tratado como hostil) y una instancia desplegada del servidor central y del dashboard.

# 4. Datos de prueba

- MIMIC-III Clinical Database Demo v1.4 (PhysioNet, licencia ODbL 1.0): 100 pacientes, 129 admisiones y 76.074 resultados de laboratorio. Sus SHA-256 se verifican contra el archivo oficial y el dataset no se versiona; la evidencia guarda metadatos de auditoría y huellas de los archivos exportados, no filas clínicas.
- Datos sintéticos reproducibles (semilla fija) en la validación externa y en el benchmark.
- Cuentas de prueba por rol, con contraseñas que cumplen la política de contraseñas, incluida una cuenta dedicada a las pruebas de bloqueo por fuerza bruta.

# 5. Criterios de aceptación

- Cada verificación se califica CUMPLE o NO CUMPLE contra un resultado esperado definido antes de ejecutarla.
- Suite automatizada: una prueba fallida impide cerrar la historia de usuario. Un comportamiento que el sistema aún no cumple se registra como fallo esperado estricto (xfail) con su causa; si el sistema se corrige, la prueba pasa a XPASS y obliga a retirar la marca. Así se cerraron, el 21/11/2026, los nueve riesgos abiertos del modelo STRIDE.
- Seguridad: los 32 ataques simulados deben ser rechazados o detectados, y cada mitigación declarada en el modelo STRIDE debe tener una prueba que la respalde.
- Casos de uso: el resultado se reporta como número de verificaciones cumplidas; cada incumplimiento se documenta como hallazgo y se refleja en el documento final.
- Rendimiento: el script del analista no requiere cambios y se reporta la sobrecarga del tiempo total y del cuerpo de pandas; no se fijó un umbral numérico.
- Validación externa: cada escenario se contrasta entre el veredicto del notebook y lo que muestra el servidor central; las propiedades de seguridad se califican de 1 a 5 y la usabilidad con la escala SUS (Bangor et al., 2009).
- Las pruebas no pueden depender de la hora a la que se ejecutan: desde el 21/11/2026 la clasificación por horario del servidor se fija en la suite y las pruebas que la evalúan usan horas explícitas.

# 6. Gestión de defectos

Los defectos se registran en el tablero del proyecto (Jira) asociados a su historia de usuario. Los que no se corrigen antes del cierre quedan documentados como fallos esperados en la suite, como riesgos abiertos del modelo STRIDE o como brechas de la matriz de trazabilidad normativa, y se reportan en el informe de validación (Anexo 13).

# 7. Responsables y calendario

| Actividad | Responsable | Fecha |
|---|---|---|
| Pruebas unitarias, de integración y de seguridad por historia de usuario | Equipo del proyecto | Sprints 1 a 6 (6/04–2/11/2026) |
| Validación externa con evaluador | Equipo y evaluador externo | 20/11/2026 |
| Casos de uso con MIMIC-III Demo, suite completa y benchmark de cierre | Equipo del proyecto | 21/11/2026 |
| Segunda ronda de robustez (plan de mitigación STRIDE) y suite completa | Equipo del proyecto | 21–22/11/2026 |

# 8. Entregables de prueba

- Casos de prueba con sus resultados (Anexo 6).
- Informe de validación (Anexo 13).
- Evidencia de los casos de uso: `validacion/evidencia/2026-11-21/` en el repositorio (Anexo 7).
- Resultados de la suite (JUnit XML) y del benchmark (`benchmarks/resultados_benchmark_2026-11-21.json`).
- Guía de pruebas y notebook de la validación externa (Anexo 13).
