---
titulo: Casos de prueba
anexo: Anexo 6 · Casos de prueba
fecha: 2026-11-22
---

[TOC]

# 1. Convenciones

Los casos siguen el Plan de pruebas (Anexo 5). Cada verificación se califica CUMPLE o NO CUMPLE frente a su resultado esperado. Los incumplimientos quedan en la suite como fallos esperados estrictos (xfail) con su causa. Las cifras de los casos de uso corresponden a la ejecución del 21 de noviembre de 2026 (commit `1dc8537`), que se repitió dentro de la suite final del 22 de noviembre con el mismo resultado; la validación externa se realizó el 20 de noviembre de 2026.

# 2. Casos de uso de extremo a extremo con MIMIC-III Demo v1.4

**Precondiciones comunes:** servidor central real en su propio proceso; una científica de datos (rol CIENTIFICO_DATOS) autenticada una vez con el código de dispositivo; scripts de pandas corrientes con `import audit_tracer` como única línea añadida; auditor y administrador en el dashboard; correo de alertas entregado en una carpeta local. **Datos de entrada:** MIMIC-III Demo v1.4 (100 pacientes, 129 admisiones, 76.074 resultados de laboratorio).

## CU-1. Flujo de análisis científico normal

**Pasos:** (1) a las 10:00 la analista carga ADMISSIONS, PATIENTS y LABEVENTS; (2) limpia y prepara los datos y une la cohorte con `merge`; (3) exporta un reporte clínico de 129 filas y un extracto de 2174 filas; (4) la librería sincroniza con el servidor; (5) el auditor revisa eventos, linaje y reporte en el dashboard.

| ID | Verificación | Resultado esperado | Resultado obtenido | Estado |
|---|---|---|---|---|
| 1.1 | Captura sin modificar el código | Se registran carga, transformación y exportación sin llamadas a la librería | 3 CARGA, 2 CONSULTA, 6 TRANSFORMACION y 2 EXPORTACION | CUMPLE |
| 1.2 | Identidad y sesión | Cada evento con el usuario autenticado y su sesión | 15 eventos con el mismo usuario y sesión, firmados e iguales en la base local y la central | CUMPLE |
| 1.3 | Nivel según filas exportadas | El nivel de alerta depende del número de filas | 129 filas → NORMAL; 2174 filas → CRITICO | CUMPLE |
| 1.4a | Linaje de una tabla | El grafo reconstruye la cadena del dataset | LABEVENTS: carga → limpieza → exportación | CUMPLE |
| 1.4b | Linaje de la cohorte unida | La cadena incluye la unión de tablas | Un solo grafo: la unión se conecta con sus tablas de entrada | CUMPLE |
| 1.5 | Referencias normativas | Referencia correcta por tipo de evento | Las 15 filas coinciden con el mapeo normativo | CUMPLE |

## CU-2. Detección de comportamiento anómalo

**Pasos:** (1) se construye una línea base de cinco días (16 al 20/11/2026, simulados) con actividad en horario de oficina; (2) a las 03:10 la analista exporta los 76.074 resultados de laboratorio; (3) se revisan el nivel y el motivo del evento, el detector de anomalías y el correo al oficial de cumplimiento.

| ID | Verificación | Resultado esperado | Resultado obtenido | Estado |
|---|---|---|---|---|
| 2.1 | Reglas de anomalía sobre el evento registrado | Se activan horario inusual y volumen anómalo | La exportación queda CRITICO «Exportación masiva: 76074 filas (> 1000)» y el servidor agrega un evento ANOMALIA_DETECTADA con las dos reglas | CUMPLE |
| 2.1b | Detector con el historial al llegar el evento | Ambas reglas | Ambas reglas; el historial excluye la sesión en curso | CUMPLE |
| 2.1c | Detector con el historial previo a la sesión | Ambas reglas | Se activan ambas reglas | CUMPLE |
| 2.2 | Nivel de alerta | Nivel alto | CRITICO | CUMPLE |
| 2.3 | Descripción del motivo | Menciona las reglas activadas | El evento de anomalía nombra las dos reglas | CUMPLE |
| 2.4a | Correo al oficial de cumplimiento | Notificación automática | Enviada, severidad ALTA | CUMPLE |
| 2.4b | Correo independiente del registro | Una falla del correo no afecta el registro | Registro en 0,009 s; correo FALLIDA tras 3 intentos en otro hilo | CUMPLE |

## CU-3. Generación de evidencia para auditoría regulatoria

**Pasos:** (1) el auditor filtra los eventos por período (16 al 21/11/2026), usuario y tipo de operación; (2) exporta el reporte CSV, también con un filtro sin resultados; (3) verifica la integridad de un evento por su hash y la de un lote histórico con la prueba de Merkle.

| ID | Verificación | Resultado esperado | Resultado obtenido | Estado |
|---|---|---|---|---|
| 3.1 | Filtros por fecha, usuario y tipo | Iguales a consultas SQL directas; desde el 22/11/2026, además, cada descarga queda registrada | Coinciden (período: 56 eventos; un día: 4; un usuario: 45). En la repetición del 22/11, las 6 descargas del caso quedaron como DESCARGA_REPORTE con el SHA-256 del archivo | CUMPLE |
| 3.2a | Campos mínimos del reporte | Usuario, fecha, acción, dataset, columnas, nivel y referencia normativa | Incluidos | CUMPLE |
| 3.2b | Sesión, origen y hash en el reporte | Incluidos en el CSV | El CSV y el PDF tienen 11 columnas, con sesión, origen y hash | CUMPLE |
| 3.3 | CSV sin resultados | CSV válido sin filas | Solo la cabecera; se lee sin errores | CUMPLE |
| 3.4a | Integridad por hash | Hash recalculado igual al almacenado | Coincide | CUMPLE |
| 3.4b | Prueba de Merkle | Prueba de inclusión y firma del ancla válidas | Válidas | CUMPLE |

**Resumen:** 19 de 19 verificaciones cumplidas. La primera ejecución del 21/11/2026 cumplió 14; los cinco hallazgos (linaje de uniones, detector sobre eventos firmados, motivo de la alerta y columnas del reporte) se corrigieron y se volvieron a ejecutar el mismo día.

# 3. Suite de pruebas automatizadas

Ejecución final del 22/11/2026: 38 archivos y 1183 pruebas; 1180 aprobadas, 0 fallidas, 1 fallo esperado y 2 omitidas. El fallo esperado reproduce el único riesgo residual que no se puede cerrar en el servidor (B9: alterar un evento en el equipo del analista antes de sincronizarlo). Las 2 omitidas comprueban permisos de archivo de Linux/macOS y no aplican en Windows.

Frente a la ejecución del 21/11/2026 (1059 pruebas, 1050 aprobadas y 9 fallos esperados), la segunda ronda cerró los nueve riesgos abiertos del modelo STRIDE, cuyas pruebas ahora pasan en `TestMitigacionesDelPlan`, y agregó `test_robustez.py` (tokens y códigos como hash, política de contraseñas, bloqueo temporal y desbloqueo, límites de peticiones, errores genéricos, sello de tiempo RFC 3161, retención, llave de firma cifrada, sesiones sin cierre y envío real por SMTP) y `test_captura_ampliada.py` (lectores y exportaciones adicionales, consultas como `head` y `groupby`, lectura con `open()` y modelado con scikit-learn). El detalle por archivo y componente está en el informe de validación (Anexo 13).

# 4. Ataques simulados

`tests/test_ataques_simulados.py` reúne 32 ataques contra la librería, el canal, el servidor y el dashboard (manipulación de registros, falsificación y reenvío de eventos, tokens inválidos o revocados, escalada de privilegios y sesiones forjadas, entre otros). **Resultado esperado:** cada ataque es rechazado o detectado. **Resultado obtenido:** 32 de 32 el 22/10/2026 (rama de HU-6.5), el 21/11/2026 y de nuevo el 22/11/2026. Además, `tests/test_modelo_amenazas.py` ataca los riesgos del modelo STRIDE: 166 de 167 pruebas aprobadas y 1 fallo esperado (B9).

# 5. Rendimiento

**Datos de entrada:** flujo de referencia en pandas (lectura de dos CSV, 9 transformaciones y 2 exportaciones) sobre datos sintéticos, cinco corridas por modo. **Resultado esperado:** el script no requiere cambios y la sobrecarga es manejable.

| Filas | Sobrecarga total | Solo pandas |
|---|---|---|
| 50.000 | +8,96 % | +4,56 % |
| 200.000 | +7,48 % | +2,04 % |
| 1.000.000 | +2,35 % | −0,64 % |

Con cinco corridas, la variación entre ejecuciones es del mismo orden que la sobrecarga medida. Las mediciones son del 21/11/2026, antes de la captura ampliada de la segunda ronda.

# 6. Escenarios de la validación externa (20/11/2026)

**Datos de entrada:** datos sintéticos generados por el notebook. Cada escenario se ejecuta en el notebook y se contrasta con el dashboard; el notebook imprime CUMPLE o NO CUMPLE.

| ID | Escenario | Resultado esperado |
|---|---|---|
| A1 | Actividad sin usuario identificado | La carga queda como DESCONOCIDO y CRITICO; el evento nunca se descarta |
| A2 | Login por código y atribución tardía | Login sin escribir la contraseña; evento ATRIBUCION_SESION; A1 sigue como DESCONOCIDO |
| A3 | Análisis sin cambios de código | CARGA, CONSULTA, TRANSFORMACION y EXPORTACION firmados; salidas idénticas byte a byte con y sin auditoría |
| A4 | Errores del usuario intactos | Llega el FileNotFoundError normal de pandas y queda un ACCESO_FALLIDO |
| A5 | Exportación masiva | CRITICO con el número de filas en el motivo |
| A6 | Servidor central caído | La operación no espera al servidor; el evento queda en cola y se envía al volver la conexión |
| B1 | UPDATE y DELETE directos sobre SQLite | Ambos fallan por inmutabilidad y quedan en audit_intentos_bloqueados |
| B2 | Alteración tras borrar los triggers | La verificación de integridad señala solo el registro alterado |
| B3 | Alteración con SHA-256 recalculado | El hash ya no delata el cambio (límite conocido); la firma Ed25519 sí |
| B4 | Atacante con la llave privada | La copia local pasa (límite conocido); el servidor conserva el hash original |
| B5 | Eventos manipulados en tránsito | 201 en el control, 200 en el reenvío y 422 en las ocho manipulaciones |
| B6 | Árbol de Merkle y ancla externa | La prueba de inclusión es válida y falla con la hoja alterada |
| C1 | Dos secretos del flujo de dispositivo | El código corto no sirve como credencial (404); segunda consulta 410 |
| C2 | Tokens inválidos y HTTPS obligatorio | 401 con token alterado, inventado o ausente; se rechaza http:// externo |
| C3 | Revocación inmediata de un token | 201 antes de revocar y 401 «Token revocado» después |
| C4 | Escalada de privilegios | 403 para CIENTIFICO_DATOS en /eventos y /merkle/publicar; ANALISTA no crea ADMIN |
| C5 | Cookie de sesión forjada | Tratada como sesión inexistente; redirección a /login |
| C6 | Fuerza bruta | La quinta contraseña errónea bloquea la cuenta (desde el 21/11/2026, durante 15 minutos) |
| C7 | Cookie reutilizada tras cerrar sesión | Funciona antes del cierre y después redirige a /login |
| D1 | Consulta forense de eventos | Los filtros se combinan; la prueba de Merkle es válida |
| D2 | Linaje del dato | Orden temporal; cada nodo abre su evento |
| D3 | Anomalías | Aparecen los tres casos sembrados (volumen, horario y correlación)* |
| D4 | Alertas y su seguimiento | Catálogo de cinco tipos e historial; cambio de estado por el analista; 403 para el auditor |
| D5 | Exploración y actividad en vivo | Búsqueda por hash, filtro guardado y relaciones del evento |
| D6 | Reportes para auditoría | El CSV coincide con la tabla y trae la referencia normativa; el de críticos incluye el hash |
| D7 | Verificación de integridad y anclas | Todos los registros íntegros; anclas con integridad y firma válidas |

**Resultado obtenido:** el evaluador calificó con 5 sobre 5 las doce propiedades de seguridad asociadas a estos escenarios y aprobó el sistema (capítulo 8). *En D3, los casos se siembran con eventos sin firma enviados por la API; desde el 21/11/2026 el servidor también evalúa los eventos firmados (CU-2). La validación externa se hizo antes de la segunda ronda: B3 y B4 siguen siendo límites conocidos (riesgo residual B9).
