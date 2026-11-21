---
titulo: Informe de validación del prototipo
anexo: Anexo 13 · Informe de validación
fecha: 2026-11-21
---

[TOC]

# 1. Resumen

| Validación | Fecha de ejecución | Commit | Resultado |
|---|---|---|---|
| Tres casos de uso con MIMIC-III Clinical Database Demo v1.4 | 21/11/2026 13:23 (hora Colombia) | `e4a656b` (código) · evidencia en `31361a3` | 19 afirmaciones verificadas: **14 CUMPLE, 5 NO CUMPLE** |
| Suite automatizada completa | 21/11/2026 13:24–13:30 | `31361a3` | 1 006 pruebas en 32 archivos: **989 aprobadas, 4 fallidas, 13 xfail, 0 omitidas** (338,6 s) |
| Ataques simulados (HU-6.5) | 21/11/2026, dentro de la suite | `31361a3` | **32 de 32** aprobadas |
| Benchmark de sobrecarga | 21/11/2026 13:31–13:37 | `31361a3` | 1 000 000 de filas: **+1,67 %** en tiempo total; 50 000: +2,56 %; 200 000: +6,70 % |

**Entorno de ejecución:** Windows 11 (10.0.26200), AMD Ryzen 5 7520U (4 núcleos, 8 hilos), 15,3 GB de RAM, SSD NVMe Samsung MZVL4512HBLU; Python 3.12.6, pandas 3.0.2, Flask 3.1.0, cryptography 44.0.2, reportlab 4.2.5.

**Las cinco afirmaciones que no se cumplen** (detalle en la sección 2):

1. El grafo de linaje no une en una sola cadena una cohorte construida con `merge`: la parte en dos grafos.
2. El detector de anomalías **no se aplica** a los eventos de la librería: el servidor solo lo ejecuta sobre eventos sin firma y sin nivel CRITICO, y la librería los firma todos (`app.py:1126`).
3. Aun aplicado al llegar el evento, la regla de horario no se activa, porque el horario habitual incluye los eventos de la propia sesión sospechosa.
4. Por lo anterior, el motivo de la alerta no describe las reglas de anomalía, solo «Exportación masiva».
5. El reporte CSV no incluye sesión, origen, hash, destino ni filas exportadas.

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
| 1.4b | Linaje completo de la cohorte (con `merge`) | **NO CUMPLE** | El grafo se arma por (sesión, `dataset_nombre`) y el merge renombra el resultado a `merge(ADMISSIONS.csv,PATIENTS.csv)`: ADMISSIONS.csv = CARGA → TRANSFORMACION → TRANSFORMACION; el resultado = 3 TRANSFORMACION → EXPORTACION → `reporte_clinico_cohorte.csv`; sin arista entre los dos. La carga de PATIENTS.csv queda aislada. |
| 1.5 | Referencias normativas correctas por tipo | **CUMPLE** | Las 15 filas del CSV del dashboard coinciden con `MAPEO_NORMATIVO`; p. ej. CARGA = «HIPAA §164.312(b) \| Ley 1581 Art. 17 lit. m \| Matriz CT-12». |

**Evidencia:** `caso1/eventos_servidor_central.json`, `caso1/eventos_base_local.json`, `caso1/linaje_api.json`, `caso1/reporte_auditoria_sesion.csv`, `caso1/salidas_del_analista.json`.
**Observaciones:** el linaje es exacto mientras el dataset conserva su nombre; cualquier `merge` (o un DataFrame construido a mano) inicia una cadena nueva.

## 2.3 Caso de uso 2 — Comportamiento anómalo

| | |
|---|---|
| **Objetivo** | Verificar que una exportación masiva fuera de horario activa las dos reglas de anomalía, queda marcada, se explica y se notifica por correo de forma independiente. |
| **Datos de entrada** | `LABEVENTS.csv` |
| **Pasos** | 1) Línea base: del 16 al 20/11 (simulados), entre 09:15 y 11:55, la misma científica exporta muestras de 120, 150, 180, 140 y 160 filas (`caso2_muestra_habitual.py`). 2) El 21/11 a las 03:10 exporta la tabla completa: 76 074 filas (`caso2_exportacion_masiva.py`). 3) El administrador había registrado a `oficial.cumplimiento@…` como destinatario de alertas (severidad mínima MEDIA). |
| **Resultado esperado** | Sección 7.4.3 del documento. |

| # | Afirmación | Resultado | Lo obtenido |
|---|---|---|---|
| 2.1 | Se activan las dos reglas sobre el evento registrado | **NO CUMPLE** | Evento #53: nivel CRITICO, motivo «Exportación masiva: 76074 filas (> 1000)». El detector no se ejecutó: `app.py:1126` lo aplica solo a eventos sin firma y que no lleguen como CRITICO. |
| 2.1b | El detector, con el historial que habría al recibir el evento, activa las dos reglas | **NO CUMPLE** | Volumen: sí («76,074 filas supera … promedio histórico (150.0 filas)»). Horario: no; el horario habitual calculado es 07–19 UTC porque incluye el `INICIO_SESION` y la `CARGA` de las 03:10 de la misma sesión. |
| 2.1c | El detector, con el historial previo a la sesión, activa las dos reglas | **CUMPLE** | Volumen y horario («08:10 fuera del horario habitual (13:00 - 19:00)»). |
| 2.2 | El evento queda con su nivel de alerta | **CUMPLE** | CRITICO (por la regla de exportación masiva de la librería, no ANOMALIA). |
| 2.3 | Se genera la descripción del motivo (reglas de anomalía) | **NO CUMPLE** | Solo «Exportación masiva: 76074 filas (> 1000)». |
| 2.4a | Correo automático al oficial de cumplimiento | **CUMPLE** | `alertas_notificaciones`: ENVIADA, tipo EXPORTACION_MASIVA, severidad ALTA, 1 intento; el `.eml` va (en copia oculta) a admin, auditor y `oficial.cumplimiento@…` con el enlace al evento. Lo dispara la exportación masiva, no una anomalía. Se usó la entrega en carpeta del sistema; no se probó un servidor SMTP real. |
| 2.4b | El correo es independiente del registro | **CUMPLE** | Con un servicio de correo que tarda 2 s y falla siempre: `insert_event` volvió en 0,009 s, el evento quedó guardado y la notificación terminó FALLIDA tras 3 intentos en otro hilo. |

**Evidencia:** `caso2/linea_base.json`, `caso2/eventos_servidor_central.json`, `caso2/evaluacion_detector_anomalias.json`, `caso2/notificacion.json`, `caso2/correo_oficial_cumplimiento.eml`, `caso2/independencia_correo.json`.
**Observaciones:** la detección que sí funciona en el flujo real es la de la librería (umbral fijo de 1 000 filas y horario laboral fijo 8:00–18:00 hora Colombia para cargas y consultas: la CARGA de las 03:10 quedó CRITICO por esa regla). Las anomalías del bloque D de la validación externa existen porque `preparar_sesion.py` envía eventos **sin firma** por la API.

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
| 3.2b | También sesión, origen de la solicitud y huella del evento | **NO CUMPLE** | El CSV no trae `sesion_id`, `contexto_ejecucion`, `hash_integridad`, `ruta_destino` ni `filas_exportadas` (están en `audit_log` y en el detalle del dashboard). |
| 3.3 | CSV válido aunque no haya resultados | **CUMPLE** | Solo la cabecera (8 columnas) y 0 filas; `csv.reader` lo lee sin errores. |
| 3.4a | Integridad de un evento por su hash | **CUMPLE** | Evento #53: SHA-256 recalculado sobre los 13 campos = almacenado; al cambiar `filas_exportadas` el hash cambia; «Verificar integridad» reporta todos los registros íntegros. |
| 3.4b | Prueba de Merkle para lotes históricos | **CUMPLE** | Lote `2026-11-21T08` (UTC): prueba de inclusión del evento #53 válida (2 pasos); raíz publicada = recalculada; firma Ed25519 del ancla válida. El ancla es un archivo JSON en el disco del servidor, no un servicio externo. |

**Evidencia:** `caso3/reporte_*.csv`, `caso3/consultas.json`, `caso3/integridad_hash.json`, `caso3/merkle.json`, `caso3/merkle_2026-11-21T08.json`.
**Observaciones:** el filtro de usuario del reporte compara `usuario_id` exacto; escribir el correo no devuelve resultados.

# 3. Suite automatizada

## 3.1 Resultado

Ejecución completa: `python -m pytest -q --junitxml=…` sobre el commit `31361a3`, 21/11/2026 de 13:24:46 a 13:30:49 (338,6 s).

| Medida | Valor |
|---|---|
| Archivos de prueba (`tests/test_*.py`) | 32 |
| Pruebas recolectadas (`pytest --collect-only -q`) | 1 006 |
| Aprobadas | 989 |
| Fallidas | 4 |
| Fallos esperados (`xfail`, documentados) | 13 (8 riesgos abiertos del modelo STRIDE + 5 afirmaciones de MIMIC que no se cumplen) |
| Omitidas | 0 |

**Las 4 fallas** están en `tests/test_modelo_amenazas.py` y ya fallaban antes de este trabajo (misma ejecución sobre `55d3791` el 21/11/2026: 971 pruebas, 959 aprobadas, 4 fallidas, 8 xfail). La causa es la prueba, no el sistema: el ayudante `_sesion()` de ese archivo crea una sesión web sin `token_id`, y desde el commit `3d7dc2b` (08/11/2026, «sesión web de una hora») el dashboard exige un token de sesión vigente y redirige a `/login`. Dos pruebas de riesgos abiertos pasan por esa redirección (XPASS estricto), una falla con `KeyError` y una de mitigación verificada recibe la página de login en vez del listado.

| Prueba que falla | Síntoma |
|---|---|
| `TestMitigacionesVerificadas::test_datos_del_evento_se_escapan_en_listados_y_reportes` | Recibe 302 a `/login` |
| `TestRiesgosAbiertos::test_riesgo_abierto_post_sin_token_csrf_es_rechazado` | XPASS(strict) por la redirección |
| `TestRiesgosAbiertos::test_riesgo_abierto_csv_neutraliza_formulas` | `KeyError: 'dataset_nombre'` (el CSV es la página de login) |
| `TestRiesgosAbiertos::test_riesgo_abierto_token_personal_no_viaja_en_la_cookie` | XPASS(strict) por la redirección |

## 3.2 Pruebas por archivo y componente

| Archivo | Pruebas | Resultado | Componente que cubre |
|---|---|---|---|
| test_alertas_tiempo_real.py | 61 | 61 ✓ | Alertas por correo, catálogo, reintentos, independencia del registro (HU-7.2) |
| test_anomaly_detector.py | 13 | 13 ✓ | Tres reglas de anomalía: volumen, horario, correlación (HU-6.3) |
| test_ataques_simulados.py | 32 | 32 ✓ | Ataques simulados (HU-6.5) |
| test_audit_log.py | 44 | 44 ✓ | Modelo de eventos, hash, consultas, reportes |
| test_autenticacion.py | 5 | 5 ✓ | Login, intentos fallidos, bloqueo |
| test_benchmark_overhead.py | 10 | 10 ✓ | Benchmark de sobrecarga (HU-6.7) |
| test_central_db.py | 23 | 23 ✓ | Base central, WAL, inmutabilidad, idempotencia (HU-5.4) |
| test_consulta_eventos.py | 5 | 5 ✓ | Consulta de eventos (HU-4.1) |
| test_control_acceso.py | 54 | 54 ✓ | RBAC y bloqueo de escalada (HU-1.4) |
| test_data_capture.py | 45 | 45 ✓ | Captura de carga y consulta (HU-2.1) |
| test_db.py | 2 | 2 ✓ | Conexión y esquema |
| test_detalle_evento.py | 17 | 17 ✓ | Detalle y explicador de eventos (HU-4.3, HU-7.4) |
| test_device_login.py | 34 | 34 ✓ | Flujo de código de dispositivo, RFC 8628 (HU-5.7) |
| test_digital_signatures.py | 34 | 34 ✓ | Firmas Ed25519 (HU-6.1) |
| test_export_capture.py | 26 | 26 ✓ | Captura de exportaciones (HU-2.3) |
| test_failed_access.py | 29 | 29 ✓ | Accesos fallidos (HU-2.4) |
| test_integracion_automatica.py | 26 | 26 ✓ | `import audit_tracer` en script y notebook (HU-5.1) |
| test_lineage.py | 24 | 24 ✓ | Grafo de linaje (HU-7.1) |
| test_mapeo_normativo.py | 54 | 54 ✓ | Mapeo normativo de reportes y su coherencia con la matriz (HU-7.3) |
| test_matriz_normativa.py | 100 | 100 ✓ | Coherencia de la matriz con el código y las pruebas (HU-6.6) |
| test_merkle.py | 17 | 17 ✓ | Árbol de Merkle, pruebas de inclusión, ancla (HU-6.2) |
| test_modelo_amenazas.py | 165 | 153 ✓ · 4 ✗ · 8 xfail | Modelo STRIDE: coherencia del anexo, mitigaciones y riesgos abiertos (HU-6.4) |
| test_paginacion_eventos.py | 2 | 2 ✓ | Paginación y filtro de acción de /eventos |
| test_registro.py | 6 | 6 ✓ | Registro de usuarios (HU-1.1) |
| test_reporte_pdf.py | 15 | 15 ✓ | Exportación del reporte en PDF (nueva, 21/11/2026) |
| test_seed_usuarios.py | 6 | 6 ✓ | Cuentas por `SEED_USUARIOS` |
| test_session_tracker.py | 13 | 13 ✓ | Sesiones de la librería |
| test_sync_events.py | 33 | 33 ✓ | Sincronización y cola ante caídas de red (HU-5.6, HU-5.8) |
| test_tokens.py | 29 | 29 ✓ | Tokens personales (HU-5.5) |
| test_transform_capture.py | 46 | 46 ✓ | Captura de transformaciones (HU-2.2) |
| test_validacion_mimic.py | 20 | 15 ✓ · 5 xfail | Casos de uso con MIMIC-III (nueva, 21/11/2026) |
| test_zona_horaria.py | 16 | 16 ✓ | Hora de Colombia en la interfaz |
| **Total** | **1 006** | 989 ✓ · 4 ✗ · 13 xfail | |

Los componentes que enumera la sección 7.4.5 del documento tienen todos al menos un archivo de pruebas: registro y autenticación (test_registro, test_autenticacion), RBAC y escalada (test_control_acceso, test_ataques_simulados), cada tipo de evento (test_data_capture, test_transform_capture, test_export_capture, test_failed_access, test_session_tracker), hashes e inmutabilidad (test_audit_log, test_central_db, test_ataques_simulados), cola de sincronización ante caídas (test_sync_events), device code flow (test_device_login), tres patrones de anomalía (test_anomaly_detector), Merkle (test_merkle), alertas por correo (test_alertas_tiempo_real), linaje (test_lineage) y consistencia normativa (test_matriz_normativa, test_mapeo_normativo, test_modelo_amenazas::TestDocumento).

## 3.3 Ataques simulados (HU-6.5)

`tests/test_ataques_simulados.py`: **32 pruebas, 32 aprobadas** el 21/11/2026; forman parte del total de 1 006. El archivo se agregó en el commit `bb1548d` (22/10/2026 15:54). La «ejecución registrada el 22 de octubre» que cita el documento consta solo en el texto de `docs/validacion_resultados.md` (commit `1ef9c97`, 22/10/2026 15:54:51: «32 de 32 casos superados; suite completa 491/491»). No hay CI ni log de esa ejecución en el repositorio. Al recolectar las pruebas del commit `a116a44` (punta de la rama de HU-6.5, 22/10/2026) se obtienen exactamente **491** pruebas, lo que es consistente con esa cifra.

# 4. Sobrecarga de rendimiento

Script: `benchmarks/overhead_referencia.py` (HU-6.7). Un flujo de referencia en pandas (lectura de dos CSV, 9 transformaciones, 2 exportaciones) sobre **datos sintéticos** se ejecuta en procesos nuevos en tres modos intercalados: sin auditoría, con `import audit_tracer`, y con auditoría y servidor de sincronización caído.

Ejecución del 21/11/2026 (13:31–13:37), 5 corridas por modo, mismo hardware de la sección 1:

| Filas | Sin auditoría (s) | Con auditoría (s) | Sobrecarga total | Sobrecarga solo pandas | Con servidor caído |
|---|---|---|---|---|---|
| 50 000 | 2,945 | 3,020 | +2,56 % | +1,48 % | +3,38 % |
| 200 000 | 4,015 | 4,284 | +6,70 % | +1,31 % | +9,10 % |
| 1 000 000 | 10,673 | 10,851 | **+1,67 %** | +1,05 % | +3,42 % |

«Total» incluye importar pandas (y la librería); «solo pandas» es el cuerpo del análisis. Resultados completos: `benchmarks/resultados_benchmark_2026-11-21.json`.

**Comparación con la cifra del documento.** El 0,11 % y el 4,5 % salen de la ejecución anterior (`benchmarks/resultados_benchmark.json`, 03/11/2026, 3 corridas):

| Filas | Total (03/11) | Solo pandas (03/11) | Total (21/11) | Solo pandas (21/11) |
|---|---|---|---|---|
| 50 000 | +14,39 % | **+4,55 %** | +2,56 % | +1,48 % |
| 200 000 | +18,67 % | +19,11 % | +6,70 % | +1,31 % |
| 1 000 000 | **+0,11 %** | −1,89 % | +1,67 % | +1,05 % |

El 4,5 % del documento es la sobrecarga del cuerpo pandas con 50 000 filas, no la del tiempo total (14,4 % ese día), y el documento omite el tamaño mediano (18,7 % ese día). Con 3 a 5 corridas, la variación entre ejecuciones es del mismo orden que la sobrecarga medida. La operación más costosa es la transformación en conjuntos pequeños (+50 % el 21/11 con 50 000 filas: unos 20 ms por la envoltura de los DataFrames).

# 5. Archivos de evidencia

| Qué | Dónde |
|---|---|
| Casos de uso MIMIC | `validacion/evidencia/2026-11-21/` · `validacion/casos_mimic.ipynb` (ejecutado) |
| Suite completa | Resultado reproducible con `python -m pytest`; los conteos de esta sección vienen del JUnit XML de la ejecución del 21/11/2026 |
| Benchmark | `benchmarks/resultados_benchmark_2026-11-21.json` |
