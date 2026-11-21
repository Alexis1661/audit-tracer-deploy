---
titulo: Guía de buenas prácticas y lineamientos de seguridad por perfil
anexo: Anexo 14 · HU-5.2
fecha: 2026-11-21
---

[TOC]

# 0. Procedencia y cambios

Esta guía parte de `docs/lineamientos_buenas_practicas_seguridad.md` (commit `0182ad6`, 04/11/2026, PDGTRAZDSA-88, 89 y 90). Se revisó contra el código del commit `31361a3` el 21/11/2026 y se corrigió todo lo que no coincidía con el sistema. El documento original no se modificó.

| Sección del original | Decía | Lo que hace el sistema | Corrección |
|---|---|---|---|
| Escenario 1 (código) | `audit_tracer.login(token=os.environ["AUDIT_TRACER_TOKEN"])` y `audit_tracer.device_login()` | `login()` no acepta `token` (TypeError) y `audit_tracer.device_login` es un módulo, no una función (TypeError). La librería no lee `AUDIT_TRACER_TOKEN`. | Se usa `audit_tracer.login(api_url=...)` (código de dispositivo). |
| 4.2 | Guardar el token en `AUDIT_TRACER_TOKEN` para scripts | Ninguna variable de entorno entrega el token a la librería; el login por dispositivo lo cachea en `~/.audit_tracer/token_cache.json` (o en Google Drive). | Reescrita. |
| 4.3 | Usar `audit_tracer.device_login()` | La API pública es `audit_tracer.login(api_url=...)` | Corregido. |
| 4.4 (roles) | El científico genera «reportes propios»; ADMIN audita `CAMBIO_ROL` | `CIENTIFICO_DATOS` no tiene el módulo de reportes (`control_acceso.py`); el evento se llama `MODIFICACION_ROL` | Tabla rehecha desde `PERMISSION_MATRIX`. |
| 4.5 y diagrama de capas | «5 fallos en 5 minutos bloquean temporalmente»; «rate limiting» | El bloqueo ocurre al 5.º intento fallido acumulado y es permanente hasta que alguien edite la base (brecha B6); más de 3 fallos en 5 min elevan a CRITICO. No hay límite de peticiones (riesgo SRV-D1). | Corregido. |
| 3.3 | Exportación masiva → CRITICO «o ANOMALIA» | Una exportación > 1000 filas queda CRITICO; el detector de anomalías no se aplica a eventos firmados ni CRITICO (`app.py:1126`) | Corregido; el escenario 2 se reescribió con lo que se observa hoy. |
| 5 (diagrama) y 5.4 | La raíz Merkle «se ancla a un proveedor externo (RFC 3161 / ledger)» | El ancla es un archivo JSON firmado en la carpeta `merkle_anchors/` del servidor; publicarlo fuera es un paso manual (plan de mitigación 12 del modelo STRIDE) | Corregido. |
| 5.1 | El trigger registra «el usuario» que intentó la alteración | Registra el usuario del evento objetivo; SQLite no conoce a quien ejecuta la sentencia | Corregido. |
| 5.2 | `verify_integrity` «recalcula periódicamente» | Se ejecuta a demanda (botón «Verificar integridad») | Corregido. |
| 5.3 | Llave privada en `~/.audit_keys/user_ed25519.key` | `~/.audit_tracer/keys/private_key.pem` (`utils/paths.py`, `digital_signatures.py`) | Corregido. |
| Escenario 3 | CONSULTA → «Ley 1581 Art. 17 lit. a»; EXPORTACION → «§164.312(a)(2)(iv) / Art. 18 lit. b»; el CSV trae «los hashes de cada evento» | CONSULTA → §164.312(b) \| Art. 17 lit. m; EXPORTACION → §164.312(b); §164.308(a)(1)(ii)(D); §164.528 \| Art. 4 lit. f; Art. 17 lit. m. El reporte no trae hashes (el de críticos sí). | Corregido con la tabla real. |
| Marco normativo | HIPAA, Ley 1581 e ISO/IEC 27001:2022 | El documento final dice ISO/IEC 27701. Ningún archivo del repositorio la mencionaba. | Se agregó la sección 9 con la alineación a ISO/IEC 27701:2019 (solo lo verificado; el resto, [PENDIENTE]). |

**Verificación de los requisitos de HU-5.2 que pide el documento:**

| Requisito | ¿Está? | Dónde |
|---|---|---|
| Perfiles: científico de datos, analista clínico, administrador, oficial de cumplimiento | Sí | Secciones 1.2 y 7 |
| Tres categorías: identificadores, seudonimizados, anonimizados | Sí | Sección 3.1 |
| Políticas de credenciales y tokens, incluida la revocación | Sí | Sección 4 |
| Protocolo ante incidentes: triaje con el explicador, integridad y firma, linaje, acción correctiva, reporte | Sí | Sección 6 |
| Tres escenarios: Colab con datos oncológicos seudonimizados; exportación masiva fuera de horario; reporte para la SIC | Sí | Sección 8 |
| Alineación con HIPAA, Ley 1581 e ISO/IEC 27701 | Sí, con límites | HIPAA y Ley 1581 en toda la guía; ISO/IEC 27701:2019 en la sección 9, citando solo los encabezados verificados y marcando el resto como [PENDIENTE] |

# 1. Propósito y alcance

Esta guía fija las prácticas obligatorias para usar Audit Tracer con datos clínicos. Audit Tracer **no es una base de historias clínicas**: guarda metadatos de cada operación (quién, cuándo, qué dataset, qué columnas, qué transformación, cuántas filas salieron), firmados con Ed25519 y protegidos contra modificación. Nunca guarda valores de celdas.

Aplica a los entornos de análisis (Jupyter, Google Colab, scripts de Python), a la infraestructura central (servidor, base SQLite, dashboard) y a cuatro perfiles:

| Perfil | Rol en el sistema | Qué hace |
|---|---|---|
| Científico de datos | `CIENTIFICO_DATOS` | Analiza datos con la librería; confirma su login por dispositivo; ve alertas |
| Analista clínico | `ANALISTA` | Consulta eventos, linaje, reportes y alertas; revisa alertas |
| Administrador | `ADMIN` | Usuarios, roles, tokens, destinatarios de alertas, sincronización |
| Oficial de cumplimiento / auditor | `AUDITOR` | Consulta eventos, linaje, integridad y Merkle; exporta reportes. Solo lectura |

# 2. Marco normativo

| Marco | Disposiciones que usa esta guía |
|---|---|
| Ley Estatutaria 1581 de 2012 (Colombia) | Art. 4 (principios: finalidad, libertad, veracidad, seguridad, confidencialidad), Art. 5 (datos sensibles: salud), Art. 17 y 18 (deberes del responsable y del encargado) |
| HIPAA, 45 CFR Parte 164 | §164.308 (salvaguardas administrativas), §164.312(a) control de acceso, §164.312(b) controles de auditoría, §164.312(c) integridad, §164.312(d) autenticación, §164.312(e) transmisión; §164.502(b) mínimo necesario |
| ISO/IEC 27001:2022, Anexo A | A.5.15 control de acceso, A.8.15 registro de eventos, A.8.24 uso de criptografía |
| ISO/IEC 27701:2019 | Ver la sección 9 |

**Principios obligatorios:** finalidad y libertad (Ley 1581 Art. 4 lit. a y b); mínimo necesario (HIPAA §164.502(b)): solo las columnas y filas que exige el objetivo; veracidad (Art. 4 lit. c); responsabilidad demostrada: la institución debe poder probar con la bitácora cómo se custodiaron los datos.

# 3. Manejo de datos sensibles

## 3.1 Clasificación operativa

| Categoría | Ejemplos | Regla |
|---|---|---|
| **1. Identificadores (PHI directo)** | Nombres, documentos, número de historia clínica, teléfonos, correos, direcciones | **Prohibido cargarlos** en entornos de análisis. Se eliminan o sustituyen antes de entrar al pipeline. |
| **2. Seudonimizados** | Registros con identificador sintético (`PAC_84729`), diagnósticos CIE-10, variables fisiológicas, medicación | Permitidos para análisis si la tabla de correspondencia queda aislada y cifrada bajo custodia del oficial de seguridad. |
| **3. Anonimizados / agregados** | Métricas de cohorte con k-anonimato ≥ 5 | Únicos autorizados para publicaciones e informes de acceso amplio. |

## 3.2 Estaciones de trabajo

* Cifrado de disco completo (BitLocker, LUKS o FileVault) en todo equipo que tenga datos clínicos.
* No guardar CSV, Parquet o Excel clínicos en carpetas sincronizadas con nubes personales.
* Borrar los archivos intermedios al terminar la sesión.
* Proteger `~/.audit_tracer/` (base local, llaves y token cacheado): en Unix, `chmod 700 ~/.audit_tracer`. En Colab, si la carpeta está en Google Drive, no compartirla.

## 3.3 Transformación y exportación

1. **No sobrescribir el dataset fuente.** La exportación registra `sobrescritura = 1` y el listado de eventos lo marca.
2. **Exportación masiva.** Toda exportación de más de 1 000 filas queda `CRITICO` y genera una notificación de severidad ALTA (`EXPORTACION_MASIVA`). Debe justificarse en la bitácora del proyecto.
3. **Linaje.** El grafo se arma por sesión y nombre de dataset. Un `merge` nombra el resultado `merge(A,B)` y, desde el 21/11/2026, el grafo conecta las dos entradas con el resultado: la cohorte unida se ve en un solo grafo (siempre que las entradas se hayan cargado en la misma sesión).
4. **Lo que se registra y lo que no.** Se registran `read_csv`, `read_excel`, `read_sql*` (solo se guarda la tabla, nunca el texto SQL), `df[col]`, `df.loc`, `df.iloc`, `query`, las máscaras booleanas (subtipo `FILTRADO`), las transformaciones y las exportaciones de pandas. No generan eventos `read_parquet`, `read_json`, `head`, `groupby`, `describe`, `sample` ni las escrituras con `open()` (usar `audited_open()`). Tampoco se registra el entrenamiento de modelos (la HU-03 no está implementada).

# 4. Credenciales, tokens y acceso

## 4.1 Identidad única

Prohibidas las cuentas compartidas o genéricas. Todo evento sin identidad queda como `DESCONOCIDO` y nivel `CRITICO` (HU-2.5), y no se puede reatribuir después: la bitácora es inmutable (el login tardío solo agrega un evento `ATRIBUCION_SESION`).

## 4.2 Login de la librería y tokens personales

* **Una vez por equipo o cuenta de Drive:** `audit_tracer.login(api_url="https://<servidor>")`. La librería muestra un código de 8 caracteres y la dirección de confirmación; el usuario lo confirma en el dashboard con su sesión abierta. No se escribe ninguna contraseña en el notebook.
* El token resultante (256 bits, 30 días por defecto) queda en `~/.audit_tracer/token_cache.json`, o en `/content/drive/MyDrive/.audit_tracer/` si Google Drive está montado. Desde ahí, `import audit_tracer` identifica al usuario sin volver a pedir nada.
* **Nunca** escribir tokens ni contraseñas en notebooks, scripts o repositorios.
* **Revocación inmediata** (administrador, Administración › Tokens de Acceso › Revocar) cuando un investigador termina su vinculación o se sospecha un compromiso. El servidor rechaza el token desde la petición siguiente (401, «Token revocado») y la librería vuelve a `DESCONOCIDO` y pide un nuevo login.

## 4.3 Control de acceso por rol (HU-1.4)

Matriz real (`audit_tracer/auth/control_acceso.py`, `PERMISSION_MATRIX`):

| Módulo | ADMIN | ANALISTA | AUDITOR | CIENTIFICO_DATOS |
|---|---|---|---|---|
| Captura de eventos | ✓ | — | — | ✓ |
| Consulta y reportes (eventos, linaje, reportes, Merkle) | ✓ | ✓ | ✓ | — |
| Gestión de usuarios y tokens | ✓ | — | — | — |
| Visualización de alertas | ✓ | ✓ | — | ✓ |
| Exportaciones | ✓ | ✓ | ✓ | — |

Todo intento fuera de lo permitido devuelve 403 y queda como `ACCESO_DENEGADO` (ADVERTENCIA) con rol, módulo, ruta y método. Los cambios de rol quedan como `MODIFICACION_ROL` (ADVERTENCIA si involucran ADMIN).

## 4.4 Intentos fallidos

* 3 contraseñas erróneas: `ACCESO_FALLIDO` con ADVERTENCIA. Más de 3 en 5 minutos: CRITICO. Al 5.º intento fallido acumulado la cuenta se **bloquea**; hoy no hay desbloqueo desde la aplicación (brecha B6): requiere intervención del administrador sobre la base.
* 3 o más accesos denegados o fallidos del mismo usuario en 10 minutos generan una notificación (`ACCESOS_DENEGADOS_REPETIDOS`, severidad ALTA), agrupada en un solo correo por ventana.
* En la librería, más de 3 fallos de acceso a archivos en 5 minutos elevan el evento a CRITICO.

# 5. Auditoría, trazabilidad e integridad

Cadena de integridad, en orden:

1. Captura en pandas sin modificar el código.
2. Hash SHA-256 sobre los 13 campos funcionales (`hash_integridad`).
3. Firma Ed25519 con la llave local del usuario (`firma_digital`), antes de guardar.
4. Envío idempotente a `/api/eventos/sincronizar` por HTTPS; el servidor verifica la firma.
5. Disparadores que bloquean `UPDATE` y `DELETE` sobre `audit_log`, en la base local y en la central.
6. Árbol de Merkle por lote horario y ancla firmada (archivo JSON en `merkle_anchors/`).

**Inmutabilidad.** Todo `UPDATE` o `DELETE` sobre `audit_log` se aborta y deja una fila `CRITICO` en `audit_intentos_bloqueados` con el evento objetivo (el usuario que figura es el del evento, no el de quien lo intentó). Nunca desactivar los disparadores en producción.

**Hash.** «Verificar integridad» (Eventos) recalcula el hash de todos los eventos a demanda. Límite conocido: el hash no usa clave, así que quien controla una base puede recalcularlo; la firma y la copia central lo cubren.

**Firma.** La llave privada vive en `~/.audit_tracer/keys/private_key.pem`, sin cifrar (riesgo LIB-I2). Protegerla con los permisos del sistema operativo. Si un usuario ya registró su llave, el servidor rechaza sus eventos sin firma (HU-6.5).

**Merkle.** La raíz de cada lote se firma y se guarda en el disco del servidor. Para que sirva como evidencia ante terceros, la institución debe copiar periódicamente esos archivos a un medio que el administrador del servidor no controle (repositorio externo, almacenamiento WORM o un sello de tiempo RFC 3161): hoy ese paso es manual.

**Anomalías.** El servidor evalúa todo evento recibido (volumen > 3 × el promedio del usuario, horario fuera de su rango habitual, 2 o más usuarios sobre el mismo dataset en 15 min), con un historial anterior al evento que excluye su propia sesión. Como los eventos de la librería van firmados y no se pueden reclasificar sin invalidar la firma, el servidor deja el evento intacto y agrega un evento `ANOMALIA_DETECTADA` (nivel ANOMALIA) cuyo motivo nombra las reglas activadas; aparece en **Solo anomalías** y genera su propia notificación. La vigilancia diaria revisa **Solo Críticos** y **Solo anomalías**.

# 6. Protocolo ante incidentes

1. **Triaje.** Abrir el evento (Eventos › fila) y leer el resumen del explicador contextual (HU-7.4): quién, qué, impacto y recomendaciones.
2. **Integridad y firma.** En el detalle: hash, «Firma Válida y Verificada» y «Verificar Integridad Merkle». Si algo no verifica, tratarlo como manipulación.
3. **Linaje.** Abrir Linaje del dataset para ver de dónde salió y a dónde fue el dato.
4. **Acción correctiva.** Revocar el token del usuario, bloquear la cuenta si hace falta y pedir el informe al investigador.
5. **Reporte.** Reportes › filtrar por usuario, fechas y tipo › Exportar Reporte (CSV o PDF) con la referencia normativa; para la huella de cada evento, Exportar Críticos (CSV), que incluye el hash.

**Integridad comprometida** (`verify_integrity` encuentra registros alterados): poner la base central en solo lectura; usar las pruebas Merkle y las anclas para acotar el lote afectado; revisar `audit_intentos_bloqueados`; conciliar con las colas locales (`audit_sync_queue`) de los clientes y con las anclas copiadas fuera del servidor.

**Sin conexión:** la librería guarda cada evento localmente con estado `PENDIENTE` y no interrumpe el análisis; al volver la red, la cola se envía sola (o con `audit_tracer.sync_now()`), sin duplicados (`evento_uuid` único).

# 7. Lineamientos por perfil

| Perfil | Debe | No debe |
|---|---|---|
| Científico de datos | Hacer `audit_tracer.login(api_url=…)` antes de trabajar; usar solo datos de categoría 2 o 3; cargar y exportar con pandas; justificar exportaciones de más de 1 000 filas | Cargar identificadores directos; escribir credenciales en notebooks; desactivar interceptores (queda `AUDITORIA_DESACTIVADA`, CRITICO) |
| Analista clínico | Revisar alertas y su estado en `/auditoria/alertas`; usar linaje y explicador | Compartir su cuenta; descargar reportes fuera de su finalidad |
| Administrador | Mantener `SECRET_KEY` y `FLASK_DEBUG=0`; revocar tokens al terminar vínculos; registrar destinatarios de alertas; copiar las anclas Merkle fuera del servidor | Desactivar disparadores; activar `SEED_DEMO_DATA` en un servidor con datos reales (brecha B10) |
| Oficial de cumplimiento | Revisar a diario Solo Críticos y Solo anomalías; verificar integridad y anclas; conservar los reportes exportados | Modificar datos (su rol es solo lectura) |

# 8. Escenarios

## Escenario 1 — Científico de datos en Google Colab con datos oncológicos seudonimizados

```python
# Celda 1 (una vez): Drive conserva el token y las llaves entre sesiones de Colab
from google.colab import drive
drive.mount("/content/drive")

# Celda 2: instalar e importar (esta línea activa toda la captura)
!pip install --quiet "git+https://github.com/Alexis1661/audit-tracer-deploy.git"
import audit_tracer
import pandas as pd

# Celda 3 (solo la primera vez): login por código de dispositivo, sin contraseña en el notebook
audit_tracer.login(api_url="https://<servidor-institucional>")

# Celda 4: datos seudonimizados (categoría 2) → evento CARGA
pacientes = pd.read_csv("/content/drive/MyDrive/estudio/pacientes_oncologia_seudonimizados.csv")

# Mínimo necesario: solo las columnas del estudio → evento CONSULTA
analisis = pacientes[["edad", "estadio_tumoral", "biomarcador_kras", "supervivencia_meses"]]

# Limpieza → eventos TRANSFORMACION
limpio = analisis.dropna(subset=["estadio_tumoral"]).fillna({"biomarcador_kras": "NO_EVALUADO"})

# Resultado agregado (categoría 3) → evento EXPORTACION
limpio.groupby("estadio_tumoral").agg(n=("edad", "size"), supervivencia=("supervivencia_meses", "median")) \
      .to_csv("/content/drive/MyDrive/estudio/resumen_por_estadio.csv")

audit_tracer.sync_status()   # muestra sincronizados / pendientes
```

`groupby` y `agg` no generan eventos; la exportación sí.

## Escenario 2 — Exportación masiva fuera de horario

Lo que ocurre hoy (validado con MIMIC-III el 21/11/2026, Anexo 13, caso 2): a las 03:10 un usuario cuyo promedio es de 150 filas exporta 76 074.

1. La librería registra la `CARGA` como CRITICO por estar fuera del horario laboral (8:00–18:00 hora Colombia) y la `EXPORTACION` como CRITICO, «Exportación masiva: 76074 filas (> 1000)».
2. El servidor envía de inmediato un correo de severidad ALTA (`EXPORTACION_MASIVA`) a los destinatarios configurados, en un hilo aparte.
3. El detector compara con el historial del usuario anterior a esa sesión y activa **volumen anómalo** y **horario inusual**. Como los eventos están firmados, el servidor no los modifica: agrega un evento `ANOMALIA_DETECTADA` (nivel ANOMALIA) con el motivo «Anomalía (reglas: volumen anómalo, horario inusual): …», que genera su propio correo (severidad MEDIA).
4. Respuesta del oficial: Eventos › Solo anomalías y Solo Críticos › abrir la exportación › leer el explicador › Verificar Integridad Merkle › Linaje del dataset › revocar el token (administrador) › pedir el informe al investigador › exportar el reporte del período.

## Escenario 3 — Reporte para una auditoría de la Superintendencia de Industria y Comercio

1. El auditor abre **Reportes** y en «Generar Reporte de Auditoría» filtra por fechas (y, si se pide, usuario, tipo de acción o dataset).
2. Revisa la tabla: cada fila trae su `referencia_normativa`. Valores reales:

| Tipo | Referencia normativa que imprime el sistema |
|---|---|
| CARGA, CONSULTA | HIPAA §164.312(b) \| Ley 1581 Art. 17 lit. m \| Matriz CT-12 |
| TRANSFORMACION | HIPAA §164.312(b); §164.312(c)(1) \| Ley 1581 Art. 4 lit. d; Art. 17 lit. m \| Matriz CT-13 |
| EXPORTACION | HIPAA §164.312(b); §164.308(a)(1)(ii)(D); §164.528 (apoyo) \| Ley 1581 Art. 4 lit. f; Art. 17 lit. m \| Matriz CT-14 |

3. Descarga **Exportar Reporte (CSV)** o **Exportar Reporte (PDF)**; ambos tienen las mismas filas y las mismas 11 columnas, entre ellas la sesión, el origen (contexto de ejecución) y el hash SHA-256 de cada evento. Si los filtros no dan resultados, el archivo es válido y lo indica.
4. Documenta la verificación con «Verificar integridad» y las anclas Merkle del período; **Exportar Críticos (CSV)** reúne solo los eventos críticos.
5. El filtro de usuario acepta el ID o el correo de la cuenta.

# 9. Alineación con ISO/IEC 27701:2019

ISO/IEC 27701:2019 extiende ISO/IEC 27001 y 27002 con un sistema de gestión de privacidad (PIMS). Su Anexo A reúne los objetivos y controles para quien decide el tratamiento de datos personales (responsable) y su Anexo B los del encargado. La institución que use Audit Tracer con datos clínicos suele ser responsable; el equipo que opera el servidor puede actuar como encargado.

**Qué se verificó y cómo.** No se dispone del texto de la norma en el repositorio. El 21/11/2026 se consultó la búsqueda web ([ISO/IEC 27701 en Wikipedia, con enlace a la tabla de contenido oficial de ISO](https://en.wikipedia.com/wiki/ISO/IEC_27701), [guía de controles del Anexo A de NQA](https://www.nqa.com/medialibraries/NQA/NQA-Media-Library/PDFs/NQA-ISO-27701-Annex-A-Controls-Analysis.pdf)), que confirmó los encabezados de tres grupos del Anexo A. No se pudo confirmar el contenido de sus subcontroles ni la numeración de las cláusulas 5 y 6; por eso no se citan.

| Grupo del Anexo A (responsable; el Anexo B equivale para el encargado) | Qué aporta Audit Tracer / esta guía | Estado |
|---|---|---|
| **A.7.2 Conditions for collection and processing** (condiciones de recolección y tratamiento) | Clasificación de datos y prohibición de cargar identificadores directos (sección 3.1); mínimo necesario (sección 2); la bitácora registra qué dataset y columnas se tocan (Anexo 10), lo que permite demostrar el tratamiento. | Parcial: la guía no define base legal, consentimiento ni evaluación de impacto de privacidad. [PENDIENTE: subcontroles de A.7.2] |
| **A.7.3 Obligations to PII principals** (obligaciones frente a los titulares) | Ninguna: Audit Tracer no gestiona solicitudes de acceso, corrección ni supresión de titulares, y la bitácora es inmutable por diseño. | No cubierto. [PENDIENTE: subcontroles de A.7.3 y su tensión con la inmutabilidad] |
| **A.7.4 Privacy by design and by default** (privacidad desde el diseño y por defecto) | La bitácora guarda solo metadatos y nunca valores de celdas (sección 1); captura sin modificar el código del analista; minimización de columnas registradas. | Parcial. [PENDIENTE: subcontroles de A.7.4] |
| A.7.5 (compartición, transferencia y divulgación de datos personales) | Los reportes salen del dashboard solo para roles con permiso; no hay controles de transferencia entre países. | [PENDIENTE: no verificado el título ni los subcontroles] |
| Cláusulas 5 y 6 (requisitos y controles adicionales sobre 27001 y 27002) | La guía ya cubre controles de acceso, registro, criptografía e integridad con HIPAA y ISO/IEC 27001 (secciones 4 y 5). | [PENDIENTE: numeración de cláusulas] |

**Conclusión.** La guía queda alineada con ISO/IEC 27701:2019 en lo que corresponde a minimización y seguridad del tratamiento (que comparte con ISO/IEC 27001, HIPAA y la Ley 1581), pero **no** puede afirmarse una alineación completa: faltan los procesos de privacidad (base legal, derechos de los titulares, evaluaciones de impacto) que la norma exige al responsable y que están fuera del alcance de la herramienta. Para el documento final conviene decir «alineada con los principios de ISO/IEC 27701», no «cumple la norma».

**Matriz de trazabilidad (06).** No se agregó una columna ISO/IEC 27701: no hay cláusulas verificadas con número y título para mapear los 32 controles uno a uno, y una columna con numeración sin verificar sería inventada. [PENDIENTE: mapeo control por control cuando el equipo tenga el texto de la norma]
