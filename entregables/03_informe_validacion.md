---
titulo: Informe de validación del prototipo
anexo: Anexo 13 · Informe de validación
fecha: 2026-11-21
---

[TOC]

# 1. Resumen

Este informe se actualizó el 21/11/2026 después de cerrar los hallazgos de la primera ejecución del mismo día (la versión anterior reportaba 14 CUMPLE y 5 NO CUMPLE).

| Validación | Fecha de ejecución | Commit | Resultado |
|---|---|---|---|
| Tres casos de uso con MIMIC-III Clinical Database Demo v1.4 | 21/11/2026 18:10 (hora Colombia) | `1dc8537` | 19 afirmaciones verificadas: **19 CUMPLE, 0 NO CUMPLE** |
| Suite automatizada completa | 21/11/2026 18:04–18:10 | `1dc8537` | 1 059 pruebas en 36 archivos: **1 050 aprobadas, 0 fallidas, 9 xfail** (343,3 s) |
| Ataques simulados (HU-6.5) | 21/11/2026, dentro de la suite | `1dc8537` | **32 de 32** aprobadas |
| Benchmark de sobrecarga | 21/11/2026 (5 corridas por modo) | `1dc8537` | 1 000 000 de filas: **+2,35 %** en tiempo total; 50 000: +8,96 %; 200 000: +7,48 % |

**Entorno:** Windows 11, AMD Ryzen 5 7520U (4 núcleos, 8 hilos), 15,3 GB de RAM, SSD NVMe; Python 3.12.6, pandas 3.0.2, Flask 3.1.0, cryptography 44.0.2, reportlab 4.2.5, APScheduler 3.11.3.

**Qué se corrigió entre la primera ejecución y esta** (cada punto con su prueba):

| Hallazgo anterior | Corrección | Prueba |
|---|---|---|
| 1.4b: el linaje partía la cohorte con `merge` en dos grafos | Una unión conecta sus entradas con el resultado (`lineage.py`) | `tests/test_lineage.py::TestUniones` (8) |
| 2.1, 2.1b, 2.3: el detector no evaluaba eventos firmados ni CRITICO; el historial incluía la sesión en curso; el motivo no nombraba las reglas | El servidor evalúa todo evento; historial previo sin la sesión; evento `ANOMALIA_DETECTADA` con las reglas nombradas | `tests/test_anomalias_eventos_firmados.py` (12) |
| 3.2b: el reporte no traía sesión, origen ni hash | CSV y PDF con 11 columnas | `tests/test_audit_log.py`, `tests/test_reporte_pdf.py` |

# 2. Validación con MIMIC-III Demo

## 2.1 Diseño

| Aspecto | Detalle |
|---|---|
| Dataset | MIMIC-III Clinical Database Demo v1.4 (PhysioNet, ODbL 1.0, doi:10.13026/C2HM2Q): 100 pacientes, 129 admisiones, 76 074 resultados de laboratorio. Descargado el 21/11/2026 de `physionet.org`; SHA-256 de los CSV verificados contra el `SHA256SUMS.txt` oficial (`validacion/descargar_mimic.py`). |
| Sistema bajo prueba | El servidor central real (`python app.py`) en su propio proceso, con base central, cuentas creadas por `SEED_USUARIOS` y correo de alertas entregado en una carpeta (`AUDIT_ALERTAS_OUTBOX`). |
| Analista | Una científica de datos (`CIENTIFICO_DATOS`) que se autentica **una vez** con el código de dispositivo (la librería muestra el código y se confirma en el dashboard). Sus scripts son pandas puro con `import audit_tracer` como única línea añadida y corren en procesos de Python separados. |
| Auditor y administrador | Usan el dashboard por HTTP con una sesión de navegador, como un usuario real. |
| Reloj | Los procesos del analista corren con `validacion/reloj.py`, que fija la **hora del día** sobre la **fecha real** de ejecución: 10:00 (caso 1) y 03:10 (caso 2) hora Colombia. La línea base del caso 2 usa los cinco días anteriores (16 al 20/11/2026) a horas de oficina. Esas fechas son **simuladas**; todo lo demás (servidor, sincronización, correo, dashboard) corrió en tiempo real el 21/11/2026. |
| Reproducción | `python validacion/descargar_mimic.py` y luego `python -m pytest tests/test_validacion_mimic.py` (o el notebook `validacion/casos_mimic.ipynb`). |
| Evidencia | `validacion/evidencia/2026-11-21/` (eventos de la base local y la central, CSV del dashboard, correo `.eml`, anclas Merkle, `resultados.json`, `RESULTADOS.md`). Por la licencia y por minimización, la evidencia guarda metadatos de auditoría y huellas SHA-256 de los archivos exportados, no las filas clínicas. |

## 2.2 Caso de uso 1 — Flujo de análisis normal

| | |
|---|---|
| **Objetivo** | Verificar que un análisis habitual queda registrado completo, atribuido, clasificado, con linaje y con su base normativa, sin tocar el código del analista. |
| **Datos de entrada** | `PATIENTS.csv`, `ADMISSIONS.csv`, `LABEVENTS.csv` |
| **Pasos** | `validacion/scripts/caso1_analisis_cohorte.py`: 1) cargar pacientes y admisiones; 2) seleccionar 10 columnas; 3) `fillna`, `merge` con pacientes, `drop`, `dropna`, `rename`; 4) exportar `reporte_clinico_cohorte.csv`; 5) cargar laboratorio, `query("itemid == 50912")` (creatinina), `dropna`, exportar `anexo_creatinina.csv`. Luego el auditor consulta el linaje y descarga el reporte. |
| **Resultado esperado** | Sección 7.4.2 del documento (cinco puntos). |

| # | Afirmación | Resultado | Lo obtenido |
|---|---|---|---|
| 1.1 | Carga, transformación y exportación se capturan sin modificar el código | **CUMPLE** | El script solo tiene `import audit_tracer` (0 llamadas a la librería). En el servidor: 3 CARGA, 2 CONSULTA, 6 TRANSFORMACION (IMPUTACION, MERGE, ELIMINACION_COLS, ELIMINACION_FILAS ×2, RENOMBRE), 2 EXPORTACION. |
| 1.2 | Identidad correcta y sesión | **CUMPLE** | 15 eventos, todos con el `usuario_id` de la científica (identificada con el token cacheado, sin escribir credenciales) y el mismo `sesion_id` de `INICIO_SESION` a `CIERRE_SESION`. Los 15 `evento_uuid` están en la base local y en la central, los 15 firmados con Ed25519. |
| 1.3 | La exportación activa el nivel según las filas | **CUMPLE** | `reporte_clinico_cohorte.csv`: 129 filas → NORMAL. `anexo_creatinina.csv`: 2 174 filas → CRITICO, «Exportación masiva: 2174 filas (> 1000)». |
| 1.4a | Linaje de una tabla sin uniones | **CUMPLE** | LABEVENTS.csv: CARGA → TRANSFORMACION → EXPORTACION → archivo `anexo_creatinina.csv`. |
| 1.4b | Linaje completo de la cohorte (con `merge`) | **CUMPLE** | Un solo grafo (dataset merge(ADMISSIONS.csv,PATIENTS.csv)) con 9 nodos y 2 aristas de unión; desde las cargas de ADMISSIONS.csv, PATIENTS.csv se llega al archivo reporte_clinico_cohorte.csv. |
| 1.5 | Referencias normativas correctas por tipo | **CUMPLE** | Las 15 filas del CSV del dashboard coinciden con `MAPEO_NORMATIVO`; p. ej. CARGA = «HIPAA §164.312(b) \| Ley 1581 Art. 17 lit. m \| Matriz CT-12». |

**Evidencia:** `caso1/eventos_servidor_central.json`, `caso1/eventos_base_local.json`, `caso1/linaje_api.json`, `caso1/reporte_auditoria_sesion.csv`, `caso1/salidas_del_analista.json`.
**Observaciones:** la unión se detecta por el nombre `merge(A,B)` que la librería asigna al resultado; un DataFrame construido a mano sigue siendo una cadena nueva. La exportación de 2 174 filas sin antecedentes del usuario generó además un `ANOMALIA_DETECTADA` propio del servidor (regla de volumen sin antecedente), en `caso1/eventos_anomalia_detectada.json`.

## 2.3 Caso de uso 2 — Comportamiento anómalo

| | |
|---|---|
| **Objetivo** | Verificar que una exportación masiva fuera de horario activa las dos reglas de anomalía, queda marcada, se explica y se notifica por correo de forma independiente. |
| **Datos de entrada** | `LABEVENTS.csv` |
| **Pasos** | 1) Línea base: del 16 al 20/11 (simulados), entre 09:15 y 11:55, la misma científica exporta muestras de 120, 150, 180, 140 y 160 filas (`caso2_muestra_habitual.py`). 2) El 21/11 a las 03:10 exporta la tabla completa: 76 074 filas (`caso2_exportacion_masiva.py`). 3) El administrador había registrado a `oficial.cumplimiento@…` como destinatario de alertas (severidad mínima MEDIA). |
| **Resultado esperado** | Sección 7.4.3 del documento. |

| # | Afirmación | Resultado | Lo obtenido |
|---|---|---|---|
| 2.1 | Se activan las dos reglas sobre el evento registrado | **CUMPLE** | La sesión de las 03:10 tiene 1 evento(s) ANOMALIA_DETECTADA (una por conjunto de reglas y sesión). #54: «Anomalía (reglas: volumen anómalo, horario inusual): Volumen anómalo: 13 operaciones en el día supera significativamente el promedio diario histórico del usuario (2.0 ops/día) \| Horario inusual: acceso registrado a las 08:10 fuera del horario habitual del usuario (13:00 - 17:00)» — Evento origen: CARGA #53 (evento_uuid=a96d1b70-df97-4766-ba9f-5b9f6ab2db28). |
| 2.1b | El detector, con el historial que habría al recibir el evento, activa las dos reglas | **CUMPLE** | Volumen: Volumen anómalo: 76,074 filas supera significativamente el promedio histórico del usuario (150.0 filas). Horario: Horario inusual: acceso registrado a las 08:10 fuera del horario habitual del usuario (13:00 - 17:00) (horario habitual calculado = (7, 23) UTC; el historial excluye la sesión en curso). |
| 2.1c | El detector, con el historial previo a la sesión, activa las dos reglas | **CUMPLE** | Volumen y horario («08:10 fuera del horario habitual (13:00 - 19:00)»). |
| 2.2 | El evento queda con su nivel de alerta | **CUMPLE** | La exportación #55 conserva el nivel de la librería (nivel_alerta=CRITICO, motivo «Exportación masiva: 76074 filas (> 1000)») porque está firmada y su nivel y motivo forman parte de la firma; el evento #54 que la acompaña tiene nivel_alerta=ANOMALIA. |
| 2.3 | Se genera la descripción del motivo (reglas de anomalía) | **CUMPLE** | motivo_alerta del evento ANOMALIA_DETECTADA: «Anomalía (reglas: volumen anómalo, horario inusual): Volumen anómalo: 13 operaciones en el día supera significativamente el promedio diario histórico del usuario (2.0 ops/día) \| Horario inusual: acceso registrado a las 08:10 fuera del horario habitual del usuario (13:00 - 17:00)». |
| 2.4a | Correo automático al oficial de cumplimiento | **CUMPLE** | `alertas_notificaciones`: ENVIADA, tipo EXPORTACION_MASIVA, severidad ALTA, 1 intento; el `.eml` va (en copia oculta) a admin, auditor y `oficial.cumplimiento@…` con el enlace al evento. Lo dispara la exportación masiva, no una anomalía. Se usó la entrega en carpeta del sistema; no se probó un servidor SMTP real. |
| 2.4b | El correo es independiente del registro | **CUMPLE** | Con un servicio de correo que tarda 2 s y falla siempre: `insert_event` volvió en 0,009 s, el evento quedó guardado y la notificación terminó FALLIDA tras 3 intentos en otro hilo. |

**Evidencia:** `caso2/linea_base.json`, `caso2/eventos_servidor_central.json`, `caso2/evaluacion_detector_anomalias.json`, `caso2/notificacion.json`, `caso2/correo_oficial_cumplimiento.eml`, `caso2/independencia_correo.json`.
**Observaciones:** como los eventos están firmados y su nivel y motivo forman parte de la firma, el servidor deja la exportación intacta (CRITICO, «Exportación masiva…») y agrega un evento `ANOMALIA_DETECTADA` (nivel ANOMALIA) con las reglas nombradas. El detector agrupa una anomalía por sesión y conjunto de reglas: el primer evento de datos de la sesión de las 03:10 (la `CARGA`) ya activó ambas reglas, por eso las verificaciones 2.x ubican ese evento. Cuando se activan las dos reglas sobre la exportación quedan dos eventos y dos correos (EXPORTACION_MASIVA y ANOMALIA_DETECTADA).

## 2.4 Caso de uso 3 — Evidencia para auditoría regulatoria

| | |
|---|---|
| **Objetivo** | Verificar que un auditor obtiene, filtra, exporta y verifica la evidencia de accesos de un período. |
| **Datos de entrada** | Los eventos de los casos 1 y 2 (56 eventos entre el 16 y el 21/11/2026). |
| **Pasos** | El auditor descarga `/reportes/exportar` con seis combinaciones de filtros, pulsa «Verificar integridad», publica el ancla Merkle del lote de la exportación masiva y verifica la prueba de inclusión y el ancla. |
| **Resultado esperado** | Sección 7.4.4 del documento. |

| # | Afirmación | Resultado | Lo obtenido |
|---|---|---|---|
| 3.1 | Filtros por fecha, usuario y tipo de operación | **CUMPLE** | Período 16–21/11: 56 eventos; solo 20/11: 4; usuario: 45; usuario + CARGA: 9; usuario + EXPORTACION: 8. Cada conjunto es idéntico al de una consulta SQL directa con los mismos criterios. |
| 3.2a | Quién, qué, cuándo, sobre qué dataset y base normativa | **CUMPLE** | Columnas: `event_id, usuario_id, timestamp, tipo_accion, dataset_nombre, columnas_afectadas, nivel_alerta, referencia_normativa`. |
| 3.2b | También sesión, origen de la solicitud y huella del evento | **CUMPLE** | Columnas del CSV: event_id, usuario_id, timestamp, tipo_accion, dataset_nombre, columnas_afectadas, nivel_alerta, sesion_id, contexto_ejecucion, hash_integridad, referencia_normativa. |
| 3.3 | CSV válido aunque no haya resultados | **CUMPLE** | Solo la cabecera (8 columnas) y 0 filas; `csv.reader` lo lee sin errores. |
| 3.4a | Integridad de un evento por su hash | **CUMPLE** | Evento #53: SHA-256 recalculado sobre los 13 campos = almacenado; al cambiar `filas_exportadas` el hash cambia; «Verificar integridad» reporta todos los registros íntegros. |
| 3.4b | Prueba de Merkle para lotes históricos | **CUMPLE** | Lote `2026-11-21T08` (UTC): prueba de inclusión del evento #53 válida (2 pasos); raíz publicada = recalculada; firma Ed25519 del ancla válida. El ancla es un archivo JSON en el disco del servidor, no un servicio externo. |

**Evidencia:** `caso3/reporte_*.csv`, `caso3/consultas.json`, `caso3/integridad_hash.json`, `caso3/merkle.json`, `caso3/merkle_2026-11-21T08.json`.
**Observaciones:** el filtro de usuario del reporte compara `usuario_id` exacto; escribir el correo no devuelve resultados.

# 3. Suite automatizada

## 3.1 Resultado

Ejecución completa: `python -m pytest -q --junitxml=…` sobre el commit `1dc8537`, 21/11/2026 de 18:04:31 a 18:10:36 (343,3 s).

| Medida | Valor |
|---|---|
| Archivos de prueba (`tests/test_*.py`) | 36 |
| Pruebas recolectadas (`pytest --collect-only -q`) | 1 059 |
| Aprobadas | 1 050 |
| Fallidas | 0 |
| Fallos esperados (`xfail`, documentados) | 9 (riesgos abiertos del modelo STRIDE) |
| Omitidas | 0 |

Las 4 fallas de la primera ejecución del día (`test_modelo_amenazas.py`) venían de un ayudante de prueba sin token de sesión; se corrigió y se comprobó que dos de esos riesgos (DSH-I1 y DSH-I3) ya estaban mitigados (Anexo 15).

## 3.2 Pruebas por archivo y componente

| Archivo | Pruebas | Resultado | Componente |
|---|---|---|---|
| test_alertas_tiempo_real.py | 61 | 61 ✓ | Alertas por correo (HU-7.2) |
| test_anomalias_eventos_firmados.py | 12 | 12 ✓ | Detector sobre eventos firmados (HU-6.3) |
| test_anomaly_detector.py | 13 | 13 ✓ | Reglas de anomalía (HU-6.3) |
| test_ataques_simulados.py | 32 | 32 ✓ | Ataques simulados (HU-6.5) |
| test_audit_log.py | 45 | 45 ✓ | Modelo de eventos, hash, reportes |
| test_autenticacion.py | 5 | 5 ✓ | Login y bloqueo |
| test_benchmark_overhead.py | 10 | 10 ✓ | Benchmark (HU-6.7) |
| test_captura_consultas.py | 19 | 19 ✓ | loc, iloc, FILTRADO, read_sql |
| test_central_db.py | 23 | 23 ✓ | Base central, WAL, inmutabilidad (HU-5.4) |
| test_consulta_eventos.py | 5 | 5 ✓ | Consulta de eventos |
| test_control_acceso.py | 54 | 54 ✓ | RBAC (HU-1.4) |
| test_data_capture.py | 45 | 45 ✓ | Carga y consulta (HU-2.1) |
| test_db.py | 2 | 2 ✓ | Conexión y esquema |
| test_detalle_evento.py | 17 | 17 ✓ | Detalle y explicador (HU-7.4) |
| test_device_login.py | 34 | 34 ✓ | Device code, RFC 8628 (HU-5.7) |
| test_digital_signatures.py | 34 | 34 ✓ | Firmas Ed25519 (HU-6.1) |
| test_export_capture.py | 26 | 26 ✓ | Exportaciones (HU-2.3) |
| test_failed_access.py | 29 | 29 ✓ | Accesos fallidos (HU-2.4) |
| test_filtro_usuario_correo.py | 8 | 8 ✓ | Filtro de usuario por ID o correo |
| test_integracion_automatica.py | 26 | 26 ✓ | import audit_tracer (HU-5.1) |
| test_lineage.py | 32 | 32 ✓ | Linaje y uniones (HU-7.1) |
| test_mapeo_normativo.py | 54 | 54 ✓ | Mapeo normativo (HU-7.3) |
| test_matriz_normativa.py | 100 | 100 ✓ | Matriz normativa (HU-6.6) |
| test_merkle.py | 17 | 17 ✓ | Árbol de Merkle (HU-6.2) |
| test_merkle_scheduler.py | 5 | 5 ✓ | Job de Merkle con APScheduler |
| test_modelo_amenazas.py | 163 | 154 ✓ · 9 xfail | STRIDE (HU-6.4) |
| test_paginacion_eventos.py | 2 | 2 ✓ | Paginación y filtro de acción |
| test_registro.py | 6 | 6 ✓ | Registro de usuarios |
| test_reporte_pdf.py | 16 | 16 ✓ | Reporte en PDF |
| test_seed_usuarios.py | 6 | 6 ✓ | Cuentas por SEED_USUARIOS |
| test_session_tracker.py | 14 | 14 ✓ | Sesiones de la librería |
| test_sync_events.py | 33 | 33 ✓ | Sincronización y cola (HU-5.6/5.8) |
| test_tokens.py | 29 | 29 ✓ | Tokens personales (HU-5.5) |
| test_transform_capture.py | 46 | 46 ✓ | Transformaciones (HU-2.2) |
| test_validacion_mimic.py | 20 | 20 ✓ | Casos de uso MIMIC-III |
| test_zona_horaria.py | 16 | 16 ✓ | Hora de Colombia |
| **Total** | **1059** | 1050 ✓ · 9 xfail | |

Los componentes que enumera la sección 7.4.5 del documento tienen todos al menos un archivo de pruebas.

## 3.3 Ataques simulados (HU-6.5)

`tests/test_ataques_simulados.py`: **32 pruebas, 32 aprobadas** el 21/11/2026; forman parte del total. El archivo se agregó en el commit `bb1548d` (22/10/2026 15:54). La «ejecución registrada el 22 de octubre» consta solo en el texto de `docs/validacion_resultados.md` (commit `1ef9c97`: «32 de 32 casos superados; suite completa 491/491»); no hay CI ni log de esa ejecución. Al recolectar las pruebas del commit `a116a44` (punta de la rama de HU-6.5, 22/10/2026) se obtienen exactamente **491**, consistente con esa cifra. «28 grupos» equivale a los 28 archivos de prueba del commit `cfbdddd` (09/11/2026).

# 4. Sobrecarga de rendimiento

Script: `benchmarks/overhead_referencia.py` (HU-6.7). Un flujo de referencia en pandas (lectura de dos CSV, 9 transformaciones, 2 exportaciones) sobre **datos sintéticos** se ejecuta en procesos nuevos en tres modos intercalados: sin auditoría, con `import audit_tracer`, y con auditoría y servidor de sincronización caído.

Ejecución final del 21/11/2026 (commit `1dc8537`, después de ampliar la captura a `loc`, `iloc`, máscaras booleanas y `read_sql`), 5 corridas por modo, mismo hardware:

| Filas | Sin auditoría (s) | Con auditoría (s) | Sobrecarga total | Solo pandas | Con servidor caído (total) |
|---|---|---|---|---|---|
| 50 000 | 2 647 | 2 885 | +8 96 % | +4 56 % | +11 88 % |
| 200 000 | 3 829 | 4 116 | +7 48 % | +2 04 % | +13 37 % |
| 1 000 000 | 10 628 | 10 878 | +2 35 % | -0 64 % | +3 59 % |

«Total» incluye importar pandas y la librería; «solo pandas» es el cuerpo del análisis. Resultados: `benchmarks/resultados_benchmark_2026-11-21_ronda2.json`. La ejecución anterior del mismo día (antes de ampliar la captura) dio +2,56 %, +6,70 % y +1,67 % en total (`resultados_benchmark_2026-11-21.json`); la de la HU-6.7 del 03/11, +14,39 %, +18,67 % y +0,11 % (3 corridas). Con 3 a 5 corridas la variación entre ejecuciones es del orden de la sobrecarga medida, así que la ampliación de la captura no empeora de forma distinguible el resultado: el cuerpo pandas pasa de +1,48 / +1,31 / +1,05 % a +4,56 / +2,04 / −0,64 %. El 4,5 % del documento corresponde a la sobrecarga del cuerpo pandas con 50 000 filas del 03/11, no a la del tiempo total.

# 5. Archivos de evidencia

| Qué | Dónde |
|---|---|
| Casos de uso MIMIC | `validacion/evidencia/2026-11-21/` · `validacion/casos_mimic.ipynb` (ejecutado) |
| Suite completa | Resultado reproducible con `python -m pytest`; los conteos de esta sección vienen del JUnit XML de la ejecución del 21/11/2026 |
| Benchmark | `benchmarks/resultados_benchmark_2026-11-21_ronda2.json` (final) y `…2026-11-21.json` |
