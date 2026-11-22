---
titulo: Análisis de eventos de auditoría y necesidades de trazabilidad
anexo: Anexo 10 · Documento técnico
fecha: 2026-11-21
---

[TOC]

# 1. Propósito y fuentes

Este documento describe **qué registra Audit Tracer, cuándo lo registra y con qué atributos**, cómo se clasifica la criticidad de cada evento y qué norma respalda cada registro. Se construyó leyendo el código, no la documentación previa: cada afirmación cita el archivo y la línea donde se implementa.

| Fuente | Detalle |
|---|---|
| Código analizado | Rama `entregables-documento-final`, commit `31361a3` (21/11/2026). Las líneas citadas corresponden a ese commit. |
| Segunda ronda (21/11/2026, noche) | Captura ampliada (lectores, consultas, exportaciones y modelado), eventos nuevos del servidor (consultas y descargas de la bitácora, llaves, desbloqueo y reclasificación) y mapeo a ISO/IEC 27701:2019. Las secciones marcadas «segunda ronda» describen ese estado; sus referencias son a funciones, no a números de línea. |
| Ejecución de referencia | Validación con MIMIC-III Demo del 21/11/2026 (`validacion/evidencia/2026-11-21/`): los eventos de los ejemplos son reales. |
| Mapeo normativo | `audit_tracer/normative_mapping.py` (tabla `MAPEO_NORMATIVO`), derivada de `docs/matriz_trazabilidad_normativa.csv` (HU-6.6). |

**Convención.** Un *evento* es una fila de la tabla `audit_log`. El campo `tipo_accion` dice qué ocurrió y `nivel_alerta` cuán grave es. Las transformaciones guardan además un subtipo entre corchetes al inicio de `motivo_fallo` (p. ej. `[IMPUTACION] fillna()`).

# 2. Estructura común de un evento

Todos los eventos comparten la misma tabla y los mismos atributos (detalle de tipos y restricciones en el Anexo 11).

| Atributo | Qué responde | Origen |
|---|---|---|
| `usuario_id` | ¿Quién? | Token del login por dispositivo cacheado (HU-5.7/5.1) o sesión del dashboard. Sin identidad: `DESCONOCIDO` y nivel `CRITICO` (`models/audit_log.py:49-56`). |
| `sesion_id` | ¿En qué ejecución? | UUID por proceso de Python o por sesión web (`utils/session.py`). Sin sesión: `SIN_SESION`. |
| `timestamp` | ¿Cuándo? | UTC ISO 8601 generado en el momento de la operación (`datetime.utcnow()`); el dashboard lo muestra en hora de Colombia. |
| `tipo_accion` | ¿Qué? | Ver catálogo (sección 3). |
| `dataset_nombre` | ¿Sobre qué dato? | Nombre del archivo leído (p. ej. `ADMISSIONS.csv`), propagado a los DataFrames derivados (`_metadata`). |
| `columnas_afectadas` | ¿Qué columnas? | JSON con las columnas leídas, consultadas o transformadas. Nunca se guardan valores de celdas. |
| `ruta_destino`, `filas_exportadas`, `sobrescritura` | ¿A dónde salió y cuánto? | Solo en `EXPORTACION`. |
| `contexto_ejecucion` | ¿Desde dónde? | `Script: <archivo o notebook [celda N]> \| Env: <Script (.py) / Jupyter / Google Colab> \| Host: <equipo>` (`utils/contexto.py:91`). |
| `motivo_fallo` | ¿Qué falló / qué transformación? | Excepción en accesos fallidos; `[SUBTIPO] descripción` en transformaciones. |
| `nivel_alerta`, `motivo_alerta` | ¿Cuán grave y por qué? | Ver sección 4. |
| `evento_uuid` | Identidad global del evento | UUID4 asignado al crearlo; el mismo en la base local y en la central (idempotencia). |
| `hash_integridad` | ¿Fue alterado? | SHA-256 sobre los 13 campos funcionales (`models/audit_log.py:15`). |
| `firma_digital` | ¿Quién lo produjo (no repudio)? | Firma Ed25519 con la llave del usuario, aplicada antes de guardar en la base local (`models/audit_log.py:616-623`). |

# 3. Catálogo de eventos auditables

## 3.1 Eventos sobre datos (librería `audit_tracer`)

Se activan con `import audit_tracer` (HU-5.1): el paquete reemplaza funciones de pandas por versiones auditadas (`audit_tracer/__init__.py`).

| `tipo_accion` | Disparador técnico (método interceptado) | Atributos específicos | Nivel que asigna la librería | Código |
|---|---|---|---|---|
| `CARGA` | `pd.read_csv()`, `pd.read_excel()` (también `pd.io.parsers.readers.read_csv`) y, desde el 21/11/2026, `pd.read_sql()`, `pd.read_sql_query()` y `pd.read_sql_table()` (el dataset se llama `sql:<tabla>`; el texto SQL no se guarda). Segunda ronda: `read_table`, `read_fwf`, `read_json`, `read_parquet`, `read_feather`, `read_orc`, `read_pickle`, `read_xml`, `read_stata`, `read_sas`, `read_spss`, `read_hdf`, `np.load`/`loadtxt`/`genfromtxt`/`fromfile` y, si polars está instalado, `polars.read_*`/`scan_*`. Con `sheet_name=None`, un evento por hoja. | `dataset_nombre` (nombre del archivo), `columnas_afectadas` (todas las columnas leídas) | `NORMAL`; `CRITICO` si el usuario es `DESCONOCIDO` o la operación ocurre fuera del horario laboral (8:00–18:00 hora Colombia, configurable) | `data_capture.py:231`, `:101`, `:416` |
| `CONSULTA` | `df[columna]`, `df[[columnas]]`, `df.query(expr)` y, desde el 21/11/2026, `df.loc[...]` y `df.iloc[...]`; segunda ronda: `head`, `tail`, `sample`, `nlargest`, `nsmallest`, `describe`, `value_counts`, `filter`, `groupby`, `at`, `iat` y la lectura con `open()` de un archivo ya cargado como dataset (lecturas por celda repetidas se registran una vez por segundo) sobre DataFrames cargados con los lectores anteriores | `columnas_afectadas` (columnas seleccionadas o mencionadas en la expresión) | Igual que `CARGA` | `data_capture.py:274`, `:301` |
| `TRANSFORMACION` | `df[mascara_booleana]` y `df.loc[mascara]` → `[FILTRADO]` (desde el 21/11/2026); `fillna` → `[IMPUTACION]`; `dropna` → `[ELIMINACION_FILAS]` o `[ELIMINACION_COLS]`; `drop` → `[ELIMINACION_COLS]`/`[ELIMINACION_FILAS]`; `rename` → `[RENOMBRE]`; `apply` → `[APLICACION]` o `[NORMALIZACION]` si la función se llama *normalize/scale/minmax/zscore/standard*; `df.merge()` y `pd.merge()` → `[MERGE]` | `columnas_afectadas`; en `contexto_ejecucion` el sufijo `Comparacion:v1:filas,cols antes:después:agregadas,retiradas` | `NORMAL`; `CRITICO` solo si el usuario es `DESCONOCIDO` | `transform_capture.py:368-404`, `:415`, `:278` |
| `EXPORTACION` | `df.to_csv()`, `to_excel()`, `to_json()`, `to_parquet()`; segunda ronda: `to_feather`, `to_orc`, `to_pickle`, `to_xml`, `to_stata`, `to_hdf`, `to_sql` (ruta `sql:<tabla>`), `to_clipboard` (ruta `portapapeles`), `to_html`/`to_markdown`/`to_latex` cuando escriben a un archivo y `np.save`/`savez`/`savetxt`; además `audited_open()` para escrituras fuera de pandas (debe llamarse explícitamente) | `ruta_destino`, `filas_exportadas`, `sobrescritura` (0/1), formato en `contexto_ejecucion` | `NORMAL`; `CRITICO` si `filas_exportadas > 1000` (`UMBRAL_EXPORTACION_MASIVA`) o usuario `DESCONOCIDO` | `export_capture.py:42`, `:84`, `:249`, `:285` |
| `ACCESO_FALLIDO` (datos) | `FileNotFoundError`, `PermissionError`, `IsADirectoryError`, `OSError` al leer con los lectores auditados, o con el decorador `@intercept_access_failures` | `motivo_fallo` (tipo de error), `dataset_nombre` | `NORMAL`; `CRITICO` desde el 4.º fallo del mismo usuario en 5 minutos | `failed_access.py:40`, `:59`, `:101` |
| `AUDITORIA_DESACTIVADA` | Llamar a `deactivate()` de cualquier interceptor | Interceptor desactivado en `contexto_ejecucion` | `CRITICO` | `data_capture.py:447` |
| `MODELADO` (segunda ronda) | `fit`, `fit_transform`, `fit_predict`, `predict` y `predict_proba` de cualquier estimador de scikit-learn (también los definidos por el usuario), `cross_val_score`, `cross_validate`, `cross_val_predict`, `learning_curve`, `validation_curve` y `permutation_test_score`. Solo se registra la operación más externa: un `Pipeline` o un `GridSearchCV` son un evento, no cientos; las predicciones repetidas se registran una vez por segundo | `dataset_nombre` de origen, `columnas_afectadas` (variables de entrada), y en `contexto_ejecucion` el modelo, la operación y el número de filas; `motivo_fallo = [ENTRENAMIENTO|PREDICCION|VALIDACION] Modelo.operación()` | `NORMAL`; `CRITICO` si el usuario es `DESCONOCIDO` | `model_capture.py` |
| `MODELADO_FALLIDO` (segunda ronda) | La misma operación termina con una excepción (que le llega intacta al usuario) | Tipo y mensaje de la excepción en `motivo_fallo` | Igual que `MODELADO` | `model_capture.py` |

**Alcance de la captura (segunda ronda, 21/11/2026).** Antes no se interceptaban `read_parquet`, `read_json` y los demás lectores distintos de `read_csv`/`read_excel`/`read_sql*`; las consultas con `head`, `tail`, `at`, `filter`, `groupby`, `describe` y `sample`; ni el modelado. Ahora sí (tabla anterior y `tests/test_captura_ampliada.py`). **Sigue sin registrarse:**

- Un archivo que se lee por primera vez sin pandas, NumPy ni polars (por ejemplo con el módulo `csv` o con `open()` sin haberlo cargado antes como dataset). Si el archivo ya se cargó como dataset, la lectura directa con `open()` sí queda como `CONSULTA`.
- Escrituras con `open()` o con librerías distintas de pandas y NumPy, salvo que se use `audited_open()`.
- Copiar datos a mano (portapapeles del sistema, capturas de pantalla). `to_clipboard()` sí se registra.

Por eso la guía de buenas prácticas (Anexo 14) complementa la captura con la política de uso de la institución.

## 3.2 Eventos de sesión del entorno de análisis

| `tipo_accion` | Disparador | Atributos | Nivel | Código |
|---|---|---|---|---|
| `INICIO_SESION` | `import audit_tracer` (una vez por proceso) | `contexto_ejecucion = MODO_LIBRERIA \| Env \| Host` | `NORMAL`; `CRITICO` si aún no hay usuario identificado | `session_tracker.py:78` |
| `ATRIBUCION_SESION` | `audit_tracer.login()` cuando la sesión ya tenía eventos como `DESCONOCIDO`: como `audit_log` es inmutable, se agrega un evento que liga el `sesion_id` al usuario | número de eventos atribuidos | `ADVERTENCIA` | `session_tracker.py:162` |
| `CIERRE_SESION` / `SESION_INTERRUMPIDA` | Fin normal del proceso (atexit) / señal de interrupción | Duración en `contexto_ejecucion` | `NORMAL` / `ADVERTENCIA` | `session_tracker.py:278` |

## 3.3 Eventos de identidad y control de acceso (servidor y dashboard)

| `tipo_accion` | Disparador | Nivel | Código |
|---|---|---|---|
| `INICIO_SESION` / `CIERRE_SESION` (web) | Login y logout del dashboard | `NORMAL` | `auth/autenticacion.py:65`, `:149` |
| `ACCESO_FALLIDO` (login) | Contraseña incorrecta | `NORMAL`; `ADVERTENCIA` desde 3 fallos acumulados; `CRITICO` si hay más de 3 en 5 minutos; `CRITICO` y bloqueo de la cuenta al 5.º | `auth/autenticacion.py:97-125` |
| `ACCESO_DENEGADO` | Un rol intenta abrir un módulo que no le corresponde (HU-1.4) | `ADVERTENCIA` | `app.py:273`, `auth/control_acceso.py` |
| `CREACION_USUARIO` | Alta de usuario | `NORMAL` | `auth/registro.py:37` |
| `MODIFICACION_ROL` | Cambio de rol | `ADVERTENCIA` si involucra ADMIN; si no, `NORMAL` | `auth/gestion_roles.py:38` |
| `GENERACION_TOKEN` / `REVOCACION_TOKEN` | Token personal emitido / revocado | `NORMAL` / `ADVERTENCIA` | `auth/tokens.py:102`, `:222` |
| `CONFIRMACION_LOGIN_DISPOSITIVO` | El usuario confirma en el dashboard el código mostrado por la librería (RFC 8628) | `NORMAL` | `auth/device_codes.py:78` |
| `CONFIGURACION_ALERTAS` | Alta o cambio de destinatarios de alertas | `NORMAL` | `app.py:675` |

## 3.4 Eventos de integridad del registro y de transmisión

| Evento | Disparador | Nivel | Dónde queda |
|---|---|---|---|
| `INTENTO_MODIFICACION` / `INTENTO_ELIMINACION` | `UPDATE` o `DELETE` sobre `audit_log` (disparadores de inmutabilidad) | `CRITICO` | Tabla `audit_intentos_bloqueados` (no en `audit_log`: la transacción se aborta con `RAISE(FAIL)`) — `db.py:27-75` |
| `FIRMA_INVALIDA` | Evento sincronizado con firma que no verifica, o sin firma de un usuario con llave registrada | `CRITICO` | `audit_log` del servidor — `app.py:1062-1121` |
| `SINCRONIZACION_RECHAZADA` | Token inválido, vencido o revocado en `/api/eventos/sincronizar` | `ADVERTENCIA` | `audit_log` del servidor — `app.py:1036-1045` |
| `ANOMALIA_DETECTADA` | El servidor detecta una o más reglas de anomalía sobre un evento **firmado** (se agrega desde el 21/11/2026; el evento original no se modifica) | `ANOMALIA` | `audit_log` del servidor — `app.py`, `_registrar_anomalia_de_evento_firmado` |

## 3.5 Eventos agregados en la segunda ronda (servidor y dashboard)

| `tipo_accion` | Disparador | Nivel | Código |
|---|---|---|---|
| `CONSULTA_BITACORA` | Un usuario ve `/eventos`, el detalle de un evento, `/reportes` o `/linaje`; una misma vista con los mismos filtros se registra una vez por minuto | `NORMAL` | `app.py` (`_auditar_acceso_bitacora`) |
| `DESCARGA_REPORTE` | Descarga del reporte CSV o PDF o del CSV de eventos críticos, con filtros, filas y el SHA-256 del archivo (que viaja también en la cabecera `X-Contenido-SHA256`) | `NORMAL` | `app.py` (`_descarga`) |
| `REGISTRO_LLAVE_PUBLICA` | La librería registra una llave Ed25519 nueva (la misma llave otra vez no genera evento); intento de registrar una llave revocada | `NORMAL`; `ADVERTENCIA` si el usuario ya tenía otra llave activa (equipo nuevo o token robado); `CRITICO` si la llave estaba revocada | `app.py` (`api_registrar_llave_publica`), `models/llaves.py` |
| `REVOCACION_LLAVE_PUBLICA` | Un ADMIN revoca una llave desde la administración de usuarios | `ADVERTENCIA` | `app.py` (`revocar_llave_post`) |
| `DESBLOQUEO_CUENTA` | Vence el bloqueo temporal de 15 minutos (actor `SISTEMA`) o un ADMIN desbloquea la cuenta | `NORMAL` (automático) / `ADVERTENCIA` (ADMIN) | `auth/autenticacion.py` (`desbloquear_cuenta`) |
| `RECLASIFICACION_SERVIDOR` | Un evento **firmado** llega con un nivel menor que el que calcula el servidor (no se puede modificar sin invalidar la firma) | El nivel calculado (`CRITICO` o `ADVERTENCIA`) | `app.py` (`_registrar_reclasificacion`), `clasificacion_servidor.py` |
| `SINCRONIZACION_RECHAZADA` (ampliado) | Además del token inválido: un evento a nombre de otro usuario distinto del dueño del token | `CRITICO` (posible suplantación) | `app.py` (`api_sincronizar_evento`) |
| `ACCESO_DENEGADO` (ampliado) | Además de los rechazos por rol: un POST del dashboard sin token CSRF válido, publicar anclajes Merkle sin rol ADMIN/AUDITOR y la verificación completa de integridad por otros roles | `ADVERTENCIA` | `app.py` |
| `ACCESO_FALLIDO` (ampliado) | Intento de iniciar sesión en una cuenta bloqueada | `ADVERTENCIA` | `auth/autenticacion.py` |

# 4. Niveles de criticidad y reglas que los asignan

`nivel_alerta` toma **cuatro valores** en el código: `NORMAL`, `ADVERTENCIA`, `CRITICO` y `ANOMALIA`. El esquema (`schema/audit_log.sql:90`) documenta solo los tres primeros; `ANOMALIA` lo asigna el detector de HU-6.3.

| Nivel | Regla | Dónde se decide |
|---|---|---|
| `NORMAL` | Valor por defecto | — |
| `ADVERTENCIA` | Acceso denegado por rol; 3–4 contraseñas erróneas; cambio de rol que involucra ADMIN; revocación de token; atribución tardía de sesión; sesión interrumpida; sincronización rechazada | Servidor y librería (tabla 3.2–3.4) |
| `CRITICO` | Usuario no identificado (siempre); exportación de más de 1000 filas; carga o consulta fuera de 8:00–18:00 hora Colombia; más de 3 accesos fallidos en 5 min; bloqueo de cuenta; desactivación de la auditoría; firma inválida; intento de UPDATE/DELETE | **Cliente** (librería), salvo login, firma e intentos bloqueados |
| `ANOMALIA` | Al menos una de tres reglas: **(1) volumen** — filas exportadas > 3 × promedio histórico del usuario (y ≥ 50), o ≥ 250 sin histórico, u operaciones del día ≥ 3 × su promedio diario (y ≥ 5); **(2) horario inusual** — hora UTC del evento fuera de [mín − 1, máx + 1] de las horas de sus eventos previos (con < 5 eventos, 07–19); **(3) correlación** — 2 o más usuarios distintos sobre el mismo dataset en 15 minutos | `anomaly_detector.py`, aplicado en el servidor a todo evento recibido (ver el detector corregido más abajo) |

**Clasificación en el servidor (segunda ronda, SRV-T3).** El servidor ya no confía en el nivel que trae el cliente: aplica las mismas reglas de la librería (exportación de más de 1000 filas, carga o consulta fuera de horario por el timestamp del evento, usuario `DESCONOCIDO`) y dos propias, con su reloj: timestamp más de 5 minutos en el futuro (`CRITICO`) y evento recibido más de 72 horas después de ocurrido (`ADVERTENCIA`, configurable con `AUDIT_DESFASE_MAX_HORAS`). Guarda la fecha de recepción en la columna `recibido_en`. Un evento sin firma se guarda ya reclasificado; uno firmado se guarda intacto y el servidor agrega `RECLASIFICACION_SERVIDOR`.

**Detector de anomalías (corregido el 21/11/2026).** El servidor evalúa **todos** los eventos que recibe, firmados o no y clasificados o no como CRITICO por la librería (`app.py`, función `api_sincronizar_evento`). El historial de referencia es el anterior al evento y **no incluye su propia sesión** (`anomaly_detector.py`: parámetros `excluir_sesion` y `antes_de`). El resultado depende de si el evento viene firmado, porque `nivel_alerta` y `motivo_alerta` forman parte del mensaje firmado y del hash:

| Evento recibido | Qué queda guardado | Nivel y motivo |
|---|---|---|
| **Con firma** (todo lo que genera la librería) — solo operaciones sobre datos (CARGA, CONSULTA, TRANSFORMACION, EXPORTACION) | El evento **intacto** (su firma y su hash siguen válidos) **más** un evento `ANOMALIA_DETECTADA` del servidor, de la misma sesión, que lo referencia por `event_id` y `evento_uuid`. Una por sesión y conjunto de reglas. | El evento conserva el nivel de la librería (p. ej. `CRITICO` «Exportación masiva: 76074 filas (> 1000)»). El evento `ANOMALIA_DETECTADA` tiene nivel `ANOMALIA` y motivo «Anomalía (reglas: volumen anómalo, horario inusual): <detalle de cada regla>». |
| **Sin firma** (cuentas sin llave registrada) | El evento reclasificado en el sitio | Si era NORMAL pasa a `ANOMALIA`; si era `CRITICO` sigue `CRITICO`. En ambos casos `motivo_alerta` suma al final el detalle de cada regla. |

Cuando se activan **las dos reglas** sobre una exportación masiva firmada hay, entonces, dos eventos: la exportación (`CRITICO`, motivo de la regla de la librería) y la anomalía (`ANOMALIA`, motivo con las dos reglas). Cada uno dispara su propia notificación (`EXPORTACION_MASIVA` y `ANOMALIA_DETECTADA`). Como el nivel lo decide el cliente, el servidor sigue sin recalcular el nivel de la librería (riesgo abierto SRV-T3 del modelo STRIDE). Pruebas: `tests/test_anomalias_eventos_firmados.py` (12). Antes de esta corrección, ningún evento de la librería pasaba por el detector (`app.py:1126` lo limitaba a eventos sin firma y no CRITICO) y el horario habitual incluía la propia sesión sospechosa.

**Severidad de notificación (HU-7.2)** — es una escala distinta de `nivel_alerta`, usada solo para decidir a quién se envía correo (`alerts/catalogo.py`):

| Tipo crítico | Regla | Severidad |
|---|---|---|
| `EXPORTACION_MASIVA` | `EXPORTACION` con más de 1000 filas | ALTA |
| `ACCESOS_DENEGADOS_REPETIDOS` | ≥ 3 `ACCESO_DENEGADO`/`ACCESO_FALLIDO` del mismo usuario en 10 min (agrupa en un solo correo) | ALTA |
| `ANOMALIA_DETECTADA` | `nivel_alerta = ANOMALIA` | MEDIA |
| `FIRMA_INVALIDA` | `tipo_accion = FIRMA_INVALIDA` | CRITICA |
| `AUDITORIA_DESACTIVADA` | `tipo_accion = AUDITORIA_DESACTIVADA` | CRITICA |

# 5. Mapeo normativo por evento

Copia exacta de `MAPEO_NORMATIVO` (`normative_mapping.py:36`). Es la columna `referencia_normativa` del reporte CSV y PDF. `tests/test_mapeo_normativo.py::test_tabla_coincide_exactamente_con_la_matriz_hu_6_6` verifica que la tabla coincide con la matriz HU-6.6.

| `tipo_accion` | HIPAA (45 CFR 164) | Ley 1581 de 2012 | Control (matriz) | ISO/IEC 27701 |
|---|---|---|---|---|
| CARGA | §164.312(b) | Art. 17 lit. m | CT-12 | 6.9.4.1; 7.2.8 (apoyo) |
| CONSULTA | §164.312(b) | Art. 17 lit. m | CT-12 | 6.9.4.1; 7.2.8 (apoyo) |
| TRANSFORMACION | §164.312(b); §164.312(c)(1) | Art. 4 lit. d; Art. 17 lit. m | CT-13 | 6.9.4.1; 7.2.8 (apoyo); 7.4.3 (apoyo) |
| EXPORTACION | §164.312(b); §164.308(a)(1)(ii)(D); §164.528 (apoyo) | Art. 4 lit. f; Art. 17 lit. m | CT-14 | 6.9.4.1; 7.5.4 (apoyo) |
| ACCESO_FALLIDO | §164.312(d); §164.308(a)(5)(ii)(C); §164.312(a)(1); §164.308(a)(6)(ii); §164.308(a)(1)(ii)(D); §164.312(b) | Art. 4 lit. g; Art. 4 lit. h; Art. 17 lit. d; Art. 17 lit. n | CT-03; CT-04; CT-05; CT-15 | 6.6; 6.9.4.1; 6.13 |
| ACCESO_DENEGADO | §164.312(a)(1); §164.308(a)(4)(ii)(B); §164.502(b); §164.312(b); §164.308(a)(1)(ii)(D) | Art. 4 lit. f; Art. 18 lit. j; Art. 17 lit. d | CT-09; CT-11 | 6.6; 6.9.4.1 |
| CREACION_USUARIO | §164.312(a)(2)(i); §164.308(a)(4)(ii)(C); §164.308(a)(3)(ii)(B) | Art. 4 lit. g; Art. 17 lit. d; Art. 18 lit. j | CT-02; CT-10 | 6.6; 6.9.4.3 |
| MODIFICACION_ROL | §164.308(a)(4)(ii)(C); §164.308(a)(3)(ii)(B) | Art. 17 lit. d; Art. 18 lit. j | CT-10 | 6.6; 6.9.4.3 |
| GENERACION_TOKEN | §164.312(d); §164.312(a)(1); §164.308(a)(3)(ii)(C) | Art. 4 lit. g; Art. 17 lit. d; Art. 18 lit. j | CT-06 | 6.6; 6.9.4.3 |
| REVOCACION_TOKEN | §164.312(d); §164.312(a)(1); §164.308(a)(3)(ii)(C) | Art. 4 lit. g; Art. 17 lit. d; Art. 18 lit. j | CT-06 | 6.6; 6.9.4.3 |
| CONFIRMACION_LOGIN_DISPOSITIVO | §164.312(d) | Art. 4 lit. g; Art. 17 lit. d | CT-07 | 6.6 |
| ATRIBUCION_SESION | §164.312(a)(2)(i); §164.312(b) | Art. 17 lit. m | CT-16 | 6.9.4.1 |
| INICIO_SESION / CIERRE_SESION / SESION_INTERRUMPIDA | §164.312(b) | Art. 17 lit. m | CT-17 | 6.9.4.1 |
| AUDITORIA_DESACTIVADA | §164.312(b); §164.308(a)(1)(ii)(D) | Art. 17 lit. d | CT-18 | 6.9.4.2; 6.13 |
| INTENTO_MODIFICACION / INTENTO_ELIMINACION | §164.312(c)(1); §164.312(b) | Art. 17 lit. d; Art. 18 lit. b | CT-21 | 6.9.4.2 |
| FIRMA_INVALIDA | §164.312(c)(2); §164.312(e)(2)(i); §164.312(d) | Art. 17 lit. d; Art. 18 lit. b | CT-22 | 6.7; 6.9.4.2 |
| SINCRONIZACION_RECHAZADA | §164.312(d); §164.312(e)(1) | Art. 4 lit. h; Art. 17 lit. d | CT-25 | 6.6; 6.10 |

| DESBLOQUEO_CUENTA | §164.308(a)(5)(ii)(C); §164.308(a)(4)(ii)(C) | Art. 17 lit. d | CT-34 | 6.6; 6.9.4.3 |
| CONSULTA_BITACORA / DESCARGA_REPORTE | §164.312(b); §164.308(a)(1)(ii)(D) | Art. 17 lit. m | CT-38 | 6.9.4.1; 6.9.4.2; 7.5.4 (apoyo) |
| MODELADO / MODELADO_FALLIDO | §164.312(b) | Art. 4 lit. d; Art. 17 lit. m | CT-39 | 6.9.4.1; 7.2.8 (apoyo) |
| REGISTRO_LLAVE_PUBLICA / REVOCACION_LLAVE_PUBLICA | §164.312(c)(2); §164.312(d) | Art. 17 lit. d | CT-40 | 6.7; 6.9.4.3 |
| RECLASIFICACION_SERVIDOR | §164.312(c)(1); §164.312(d); §164.308(a)(1)(ii)(D) | Art. 17 lit. d | CT-41 | 6.9.4.1; 6.9.4.4 |

Las filas de la segunda ronda (21/11/2026) corresponden a los controles CT-33 a CT-46 de la matriz. Sin referencia (la celda dice «Sin referencia normativa asociada»): `ANOMALIA_DETECTADA`, `CONFIGURACION_ALERTAS` y cualquier tipo no listado.

**ISO/IEC 27701 (segunda ronda).** La columna usa la numeración de ISO/IEC 27701:2019, verificada contra el índice oficial de la norma: 6.6 Control de acceso; 6.7 Criptografía; 6.9.4.1 Registro de eventos; 6.9.4.2 Protección de la información de registro; 6.9.4.3 Registros de administrador y operador; 6.9.4.4 Sincronización de relojes; 6.10 Seguridad de las comunicaciones; 6.13 Gestión de incidentes; 7.2.8 Registros relacionados con el tratamiento de PII; 7.4.3 Exactitud y calidad; 7.5.4 Registros de divulgación de PII a terceros. «Apoyo» indica que el evento contribuye a la cláusula sin satisfacerla solo (p. ej. 7.2.8 exige además el registro de actividades de tratamiento de la institución). La tabla completa control por control está en la sección 5.1 de la matriz (Anexo 15). La edición de 2025 renumeró los controles (el registro de eventos quedó en A.3.25), así que para una auditoría contra esa edición hay que traducir la numeración.

# 6. Cobertura de «ejecución de scripts» y «accesos a recursos»

No existen eventos propios llamados `EJECUCION_SCRIPT` ni `ACCESO_RECURSO`. Ambas necesidades se cubren así:

| Necesidad | Cómo se cubre | Evidencia real (validación MIMIC, 21/11/2026) |
|---|---|---|
| **Ejecución de scripts** | Cada proceso que importa la librería abre una sesión: `INICIO_SESION` … `CIERRE_SESION` con un `sesion_id` propio. Cada evento lleva en `contexto_ejecucion` el script o notebook (con número de celda), el entorno y el host. | `Script: caso1_analisis_cohorte.py \| Env: Script (.py) \| Host: AlexComputer`; 15 eventos con el mismo `sesion_id` de `INICIO_SESION` a `CIERRE_SESION` |
| **Accesos a recursos (datos)** | `CARGA`, `CONSULTA` y `ACCESO_FALLIDO` con `dataset_nombre` y `columnas_afectadas` | `CARGA` de `PATIENTS.csv`, `ADMISSIONS.csv`, `LABEVENTS.csv` |
| **Accesos a recursos (dashboard)** | Login (`INICIO_SESION`/`ACCESO_FALLIDO`) y accesos bloqueados por rol (`ACCESO_DENEGADO`, con rol, módulo y ruta en `contexto_ejecucion`). | — |
| **Consultas y descargas en el dashboard** (segunda ronda) | `CONSULTA_BITACORA` y `DESCARGA_REPORTE` con usuario, rol, filtros, filas y SHA-256 del archivo descargado (DSH-R1 cerrado; `tests/test_modelo_amenazas.py::TestMitigacionesDelPlan::test_mitigado_descarga_de_reporte_queda_registrada`). | — |

# 7. Requerimientos de trazabilidad

La columna **Origen** distingue los requerimientos que vienen de una historia de usuario (HU) de los **derivados** de la implementación (decisiones de diseño que el código impone y que no estaban escritas en una HU).

## 7.1 Requerimientos funcionales

| ID | Requerimiento | Origen | Estado en el código |
|---|---|---|---|
| RF-01 | Registrar cada carga y consulta de datos clínicos con usuario, sesión, fecha, dataset y columnas | HU-2.1 | Implementado (`read_csv`, `read_excel`, `read_sql*`, `df[...]`, `query`, `loc`, `iloc`; segunda ronda: demás lectores de pandas, NumPy y polars, `head`/`tail`/`groupby`/`describe`/`at`/`iat` y `open()` sobre datasets cargados) |
| RF-02 | Registrar cada transformación con su tipo y columnas afectadas | HU-2.2 | Implementado para `fillna`, `dropna`, `drop`, `rename`, `apply`, `merge` |
| RF-03 | Registrar cada exportación con destino, filas y sobrescritura; marcar CRITICO las masivas | HU-2.3 | Implementado (umbral 1000 filas) |
| RF-04 | Registrar los intentos fallidos de acceso y escalar a CRITICO los repetidos | HU-2.4 | Implementado |
| RF-05 | Ningún evento se pierde por falta de identidad: `DESCONOCIDO` + CRITICO | HU-2.5 | Implementado |
| RF-06 | Registrar eventos de modelado | HU-03 del documento | Implementado en la segunda ronda (`model_capture.py`: entrenamiento, predicción y validación cruzada con scikit-learn; `MODELADO_FALLIDO` si la operación falla) |
| RF-07 | Activar la captura con `import audit_tracer`, sin modificar el código | HU-5.1 | Implementado; la identidad requiere un `audit_tracer.login(api_url=…)` previo (una vez, el token queda cacheado) |
| RF-08 | Autenticación por código de dispositivo para Colab | HU-5.7 | Implementado |
| RF-09 | Sincronizar con el servidor central con cola persistente y reintentos, sin duplicados | HU-5.6, HU-5.8 | Implementado (`evento_uuid UNIQUE`) |
| RF-10 | Impedir la modificación y el borrado de eventos y dejar constancia del intento | HU-3.3, HU-5.4 | Implementado (disparadores; constancia en `audit_intentos_bloqueados`) |
| RF-11 | Hash SHA-256 por evento y verificación de integridad | HU-3.2 | Implementado |
| RF-12 | Firma Ed25519 por evento y verificación en el servidor | HU-6.1 | Implementado |
| RF-13 | Árbol de Merkle por lote horario, prueba de inclusión y ancla firmada | HU-6.2 | Implementado; el ancla es un archivo JSON en el servidor y, con `AUDIT_TSA_URL`, lleva un sello de tiempo RFC 3161 de una autoridad externa (segunda ronda) |
| RF-14 | Detectar volumen anómalo, horario inusual y correlación entre usuarios | HU-6.3 | Implementado; desde el 21/11/2026 se aplica también a los eventos firmados y CRITICO (sección 4) |
| RF-15 | Notificar por correo los eventos críticos sin bloquear el registro | HU-7.2 | Implementado (hilo aparte, reintentos) |
| RF-16 | Consultar y filtrar eventos por usuario, fecha, acción, dataset y nivel | HU-4.1, HU-4.2 | Implementado |
| RF-17 | Reporte exportable con referencia normativa, sesión, origen y hash por evento | HU-4.5, HU-7.3 | Implementado en CSV y PDF (11 columnas desde el 21/11/2026) |
| RF-18 | Grafo de linaje por dataset o por evento | HU-7.1 | Implementado; una unión (`merge`) conecta sus entradas con el resultado en un solo grafo (21/11/2026) |
| RF-19 | Explicación en lenguaje natural de cada evento | HU-7.4 | Implementado (`event_explainer.py`) |
| RF-20 | Registrar los accesos denegados por rol | Derivado (HU-6.5, hallazgo de seguridad) | Implementado (`ACCESO_DENEGADO`) |
| RF-21 | Ligar a un usuario los eventos que se registraron antes de su login | Derivado de la inmutabilidad (HU-5.1) | Implementado (`ATRIBUCION_SESION`) |
| RF-22 | Registrar la desactivación de la captura | Derivado (HU-5.1) | Implementado (`AUDITORIA_DESACTIVADA`) |
| RF-23 | Registrar las consultas y descargas de la bitácora | Derivado (DSH-R1, modelo STRIDE) | Implementado en la segunda ronda (`CONSULTA_BITACORA`, `DESCARGA_REPORTE`) |
| RF-24 | Rechazar eventos a nombre de otro usuario y recalcular su criticidad en el servidor | Derivado (SRV-S1, SRV-T3) | Implementado en la segunda ronda |
| RF-25 | Historial de llaves públicas con registro y revocación | Derivado (SRV-S2, SRV-R2) | Implementado en la segunda ronda (`REGISTRO_LLAVE_PUBLICA`, `REVOCACION_LLAVE_PUBLICA`) |
| RF-26 | Bloqueo temporal tras 5 intentos y desbloqueo por ADMIN | Derivado (B6, DSH-D1) | Implementado en la segunda ronda (`DESBLOQUEO_CUENTA`) |
| RF-27 | Política de retención y archivo de conservación verificable | Derivado (B7) | Implementado en la segunda ronda (`retencion.py`, comandos `flask retencion-*`) |

## 7.2 Requerimientos no funcionales

| ID | Requerimiento | Origen | Cómo se verifica |
|---|---|---|---|
| RNF-01 | La auditoría nunca interrumpe ni cambia el resultado del análisis: los errores internos van a un log aparte | HU-5.1 CA4 | `tests/test_integracion_automatica.py` |
| RNF-02 | Sobrecarga baja sobre pandas | HU-5.1 CA3, HU-6.7 | Benchmark (Anexo 13, sección 4) |
| RNF-03 | El envío de red nunca ocurre en el hilo del usuario | Derivado (HU-5.1) | `sync_client.schedule_sync()` solo despierta un hilo de fondo |
| RNF-04 | Funcionamiento sin conexión: persistencia local inmediata y sincronización diferida | HU-5.8 | `tests/test_sync_events.py` |
| RNF-05 | HTTPS obligatorio hacia el servidor (salvo localhost) | HU-5.6 CA5 | `sync_client._validar_https`, `app._peticion_es_segura` |
| RNF-06 | No guardar valores clínicos en la bitácora: solo metadatos (nombres de archivo y columnas) | Derivado (minimización, Ley 1581 Art. 4) | Revisión de `_log_event`/`_log_transform`/`_log_export` |
| RNF-07 | Despliegue en infraestructura propia, sin servicios de terceros obligatorios (SQLite, Flask) | Documento §7.3.1 | `audit_tracer/db.py` |
| RNF-08 | Concurrencia en la base central (SQLite WAL + `busy_timeout` de 5 s) | HU-5.4 CA2 | `db.py:276-277` |
| RNF-09 | Mismo hash del evento en la base local y en la central | HU-5.4 CA1 | `_HASHED_COLUMNS` idéntica en ambas |
| RNF-10 | Horario laboral configurable y en hora de Colombia | HU-4.4, derivado de la operación en Colombia | `utils/horario.py` |
| RNF-11 | Credenciales protegidas en reposo: contraseñas con bcrypt, tokens y códigos como SHA-256, llave de firma local cifrada | Derivado (B3, LIB-I2) | `tests/test_robustez.py` |
| RNF-12 | Sesión web con cierre por inactividad, cookie Secure/HttpOnly/SameSite y protección CSRF | Derivado (B1, DSH-S3, DSH-T1) | `tests/test_modelo_amenazas.py::TestMitigacionesDelPlan` |
| RNF-13 | Resistencia a la inundación: límite de peticiones por IP y por token y tamaño máximo de 2 MB | Derivado (SRV-D1, DSH-D1) | `tests/test_robustez.py::TestLimiteDePeticiones` |
| RNF-14 | El usuario nunca ve detalles internos de un error; el servidor de producción es Gunicorn con depuración apagada | Derivado (SRV-I2) | `tests/test_robustez.py::TestErroresYRechazos` |
