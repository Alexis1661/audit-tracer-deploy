# Audit Tracer

Sistema de auditoría de trazabilidad para entornos de ciencia de datos en salud.

## Descripción
Este sistema registra, almacena y reporta automáticamente todas las operaciones que un usuario realiza sobre datos clínicos sensibles dentro de Jupyter Notebooks y scripts Python. 
Cumple con normativas como HIPAA §164.312(b) y §164.312(c)(1), Ley 1581 de 2012 e ISO/IEC 27001:2022.

## Instalación
```bash
pip install -r requirements.txt
```

## Pruebas
Para correr las pruebas:
```bash
python -m pytest tests/
```

## Módulos
- `db.py`: Conexión a SQLite e inicialización de la BD.
- `models/audit_log.py`: Operaciones en la tabla `audit_log` para registrar eventos y recuperarlos.
- `models/usuarios.py`: Gestión de usuarios (creación, obtención, bloqueo).
- `auth/registro.py`: Registro de nuevos usuarios y hashing de contraseñas.
- `auth/autenticacion.py`: Inicio de sesión y manejo de accesos fallidos.
- `session_tracker.py`: Rastreo de sesión del modo librería (notebook/script) y autenticación del usuario activo.
- `utils/hashing.py`: Utilidades para hashing de contraseñas y cálculo de hashes de integridad SHA-256.
- `utils/session.py`: Generación de UUIDs de sesión.

## Asociación de eventos a un usuario (HU-2.5)

Todo evento en `audit_log` queda asociado a un `usuario_id` y a un `sesion_id`, por dos caminos:

- **App web (`app.py`)**: al iniciar sesión, `auth.autenticacion.login()` valida las
  credenciales contra `usuarios` y `app.py` guarda `usuario_id`/`sesion_id` en la
  sesión de Flask (cookie firmada). Todas las rutas que auditan usan esos valores,
  nunca uno enviado directamente por el cliente.
- **Modo librería (`import audit_tracer`)**: `SessionTracker` mantiene la sesión
  activa (`sesion_id` fijo) del proceso/notebook. El usuario permanece en
  `DESCONOCIDO` hasta que se llama a `audit_tracer.login(email, password)`, que
  reutiliza el mismo `auth.autenticacion.login()` de la app web y actualiza la
  identidad sin generar una sesión nueva. `audit_tracer.logout()` revierte a
  `DESCONOCIDO`.

Cuando no es posible identificar al usuario, `models/audit_log.py::insert_event()`
normaliza el evento de forma centralizada: `usuario_id='DESCONOCIDO'`,
`sesion_id='SIN_SESION'` (si faltan) y `nivel_alerta='CRITICO'` — el evento
**siempre se registra**, nunca se descarta. Los reportes (`/eventos`,
`get_events()`, `get_critical_events()`) permiten filtrar por `usuario_id`.

## Reportes de auditoría por fechas y usuario (HU-4.5)

`models/audit_log.py::generate_report(conn, usuario_id=None, fecha_inicio=None,
fecha_fin=None, tipo_accion=None, dataset_nombre=None)` genera el reporte de
evidencia de auditoría: reutiliza `get_events()` (mismos filtros, combinables
entre sí, orden `timestamp ASC`) y recorta cada evento a las 7 columnas del
reporte: `event_id, usuario_id, timestamp, tipo_accion, dataset_nombre,
columnas_afectadas, nivel_alerta`.

`export_report_to_csv(conn, dest, ...)` exporta ese mismo reporte a CSV con
esa cabecera exacta (mismo patrón que `export_critical_events_to_csv()`:
`csv.DictWriter`, `dest` puede ser una ruta o un objeto file-like como
`io.StringIO` para servir la descarga por HTTP). Si los filtros no producen
eventos, el CSV se genera igual, solo con la cabecera — nunca queda corrupto
ni se lanza una excepción.

En la app web, la sección "Generar Reporte de Auditoría" de `/reportes`
(ruta `GET /reportes`, filtros vía query string `reporte_*`) usa
`generate_report()` para la tabla y `GET /reportes/exportar` para el CSV. Si
no hay resultados, la tabla muestra exactamente el mensaje de
`NO_RESULTS_MESSAGE`: *"No se encontraron eventos para los filtros
seleccionados."* — constante única compartida entre backend y plantilla, para
que el texto no se duplique ni se desincronice.

## Base de datos central consolidada (HU-5.4)

### Por qué

El diseño original era 100% local: cada usuario tenía su propio SQLite. Eso
no funciona porque (a) los científicos de datos trabajan en Google Colab,
donde el filesystem se destruye al cerrar la sesión, y (b) el dashboard
administrativo necesita ver la actividad de 20-30 analistas a la vez, algo
imposible con bases aisladas.

La arquitectura objetivo es híbrida: cada evento se persiste primero en el
SQLite local (caché/respaldo inmediato) y luego se sincroniza vía HTTPS a
un servidor central. HU-5.4 construyó el destino de esa sincronización; el
endpoint que la recibe y el envío desde la librería se implementan en
HU-5.8 (ver más abajo) — el endpoint de ingesta no existía como HU propia
(HU-5.6) en el repositorio, así que HU-5.8 lo incluyó como prerrequisito
directo, sin el cual no tenía a dónde sincronizar.

### Motor: SQLite en modo WAL

Se evaluó frente a PostgreSQL y se eligió SQLite en modo WAL, condicionado a
que la base central viva en el mismo servidor donde se despliegan el
dashboard y, más adelante, el endpoint de ingesta de HU-5.6 — una sola
máquina de infraestructura propia, no instancias balanceadas. Bajo ese
supuesto:

- Ningún cliente necesita alcanzar la base por red directamente: la
  librería (Colab u otro entorno) nunca abre una conexión a la base, siempre
  pasa por el endpoint HTTPS de HU-5.6. Lo único que abre la base
  directamente es el propio backend (dashboard hoy, endpoint de ingesta
  después), y ambos corren en la misma máquina.
- 20-30 usuarios haciendo operaciones esporádicas de pandas (inserts cortos,
  no escritura continua de alta frecuencia) están muy por debajo de donde
  WAL empieza a doler: los lectores no bloquean al escritor ni viceversa, y
  los escritores se serializan por milisegundos, no compiten por row-locks.
- Cero dependencias nuevas ni servidor adicional que mantener — coherente
  con "infraestructura propia, sin servicios de terceros".
- Si en el futuro el endpoint de ingesta necesita escalar horizontalmente
  (varias instancias balanceadas), esa condición se rompe y ahí sí toca
  migrar a PostgreSQL. Para que esa migración sea acotada, **toda la lógica
  de hashing e inmutabilidad vive en Python** (`hash_event()`,
  `_prepare_event()`, `verify_integrity()`), no en SQL específico del motor
  — lo único atado a SQLite son los dos triggers de bloqueo UPDATE/DELETE
  (`schema/audit_log_central.sql`), que es la única pieza que habría que
  reescribir en PL/pgSQL.

`get_central_connection()` en `audit_tracer/db.py` abre la conexión con
`PRAGMA journal_mode = WAL` y `PRAGMA busy_timeout = 5000`: el busy_timeout
es lo que hace que un escritor concurrente espere su turno en vez de fallar
de inmediato con `database is locked` (CA2) — probado con hilos concurrentes
reales en `tests/test_central_db.py::TestConcurrencia`, no simulado.

### Esquema (diccionario de datos)

`schema/audit_log_central.sql` es estructuralmente compatible con
`schema/audit_log.sql` (el `audit_log` local): mismos 13 campos
funcionales sobre los que se calcula `hash_integridad` (antes se
documentaban como 11; `filas_exportadas` y `sobrescritura` se sumaron
después, en HU-2.3). La única columna nueva es `evento_uuid`:

| Columna | Tipo | Igual que el local | Descripción |
|---|---|---|---|
| `event_id` | INTEGER PK | Sí (autoincremental, único solo dentro de esta base) | Identificador local de la fila. |
| `evento_uuid` | TEXT UNIQUE NOT NULL | **Nueva (HU-5.4 CA1)** | UUID4 generado en Python al construir el evento. No participa del hash. Permite que la futura sincronización (HU-5.8) reintente sin duplicar eventos en la central (idempotencia). |
| `usuario_id`, `sesion_id`, `timestamp`, `tipo_accion`, `dataset_nombre`, `columnas_afectadas`, `ruta_destino`, `filas_exportadas`, `sobrescritura`, `contexto_ejecucion`, `motivo_fallo`, `nivel_alerta`, `motivo_alerta` | — | Sí, sin cambios | Los 13 campos funcionales del evento auditado. Con múltiples orígenes consolidados en una sola tabla, `usuario_id` es lo que permite trazar el usuario emisor de cada evento. |
| `hash_integridad` | TEXT NOT NULL | Sí | SHA-256 calculado en Python sobre los 13 campos funcionales — idéntico al del evento en la base local, porque `evento_uuid`/`event_id` quedan fuera del cálculo. |

También incluye `audit_intentos_bloqueados` (ver más abajo) y, a través de
`get_central_connection()`, la tabla `usuarios` sin cambios
(`schema/usuarios.sql`): el dashboard Flask lee y escribe todo — auth,
roles y eventos — contra esta misma conexión, porque en este diseño el
dashboard es parte de la infraestructura central, no un cliente
intermitente como una notebook de Colab.

### Inmutabilidad (CA3) — cierra un faltante real de HU-3.3

Antes de esta HU, **el `audit_log` local no tenía ningún mecanismo que
impidiera un `UPDATE`/`DELETE` real** — solo el hash SHA-256 +
`verify_integrity()`, que detecta la alteración después del hecho, no la
previene. HU-3.3 sí implementó triggers de bloqueo
(`feature/HU-3.3-Juan-Pablo`, commit `c90db4c`), pero esa rama nunca se
mergeó a `main` (confirmado con `git log --all -S "CREATE TRIGGER"`: es el
único commit en todo el historial que introduce esa cadena, y vive
únicamente en esa rama huérfana). HU-5.4 cierra ese faltante — en local y en
central, con el mismo patrón:

- `trg_audit_log_no_update` / `trg_audit_log_no_delete`: dos triggers
  `BEFORE UPDATE`/`BEFORE DELETE` sobre `audit_log` que registran el intento
  en `audit_intentos_bloqueados` y luego rechazan la operación con
  `RAISE(FAIL, ...)` (se usa `FAIL` y no `ABORT` para que ese registro del
  intento sobreviva aunque la operación original se rechace — `ABORT`
  también lo revertiría).
- `audit_intentos_bloqueados`: tabla separada que deja constancia de cada
  intento de alterar o borrar un registro de auditoría — un trigger que
  bloquea sin dejar rastro sería una versión incompleta de "restricción de
  UPDATE/DELETE" para un sistema cuyo propósito es justamente dejar rastro.

`audit_tracer/db.py::get_connection()` y `get_central_connection()`
aplican esta infraestructura también a bases creadas *antes* de HU-5.4, vía
`_migrate_audit_log()` — mismo patrón aditivo que ya se usaba para
`filas_exportadas`/`sobrescritura` (HU-2.3). El backfill de `evento_uuid`
en filas preexistentes se ejecuta **antes** de instalar los triggers,
porque una vez instalados, ni siquiera ese `UPDATE` de backfill podría
correr.

**No se implementó** el encadenamiento de hashes (`hash_previo`) que
también está en esa misma rama de HU-3.3: CA3 de esta HU solo pide hash por
registro (ya existía) + restricción de UPDATE/DELETE (agregado aquí), y
encadenar hashes obliga a serializar inserciones — tensiona directamente
con CA2 (escrituras concurrentes). Queda como posible HU aparte.

### Persistencia dual sin duplicar hashing

`audit_tracer/models/audit_log.py::insert_event(conn, event)` no cambió de
firma ni de comportamiento — sigue escribiendo en una sola conexión. Para
escribir el mismo evento en local y en central a la vez existe
`insert_event_dual(local_conn, central_conn, event)`: calcula el hash y el
`evento_uuid` **una sola vez** (`_prepare_event()`) y los escribe en ambas
conexiones ya resueltos — no se recalculan por separado. Si la escritura
central falla (servidor no disponible), el evento igual queda persistido
localmente; ese es el modelo de resiliencia que sustenta HU-5.6/5.8. Esta
HU deja la función lista y probada (`tests/test_central_db.py::
TestInsertEventDual`); conectarla a la librería de interceptores
(`data_capture.py`, `export_capture.py`, etc.) no terminó siendo el
mecanismo que usa HU-5.8 — ver la sección "Sincronización de eventos
hacia el servidor central (HU-5.8)" más abajo para el porqué (Colab no
puede abrir la base central directamente, solo HTTPS).

### Dashboard → base central (CA4)

`app.py::get_db()` es el único punto de conexión de las rutas del
dashboard (ninguna llama a `get_connection()` directo). Redirigirlo a la
base central fue, en la práctica, cambiar esa única función: ahora llama a
`get_central_connection()` en vez de `get_connection()`. Todas las rutas
existentes (`/eventos`, `/eventos/<id>`, `/reportes`, login, gestión de
usuarios, etc.) siguen funcionando sin cambios adicionales porque ya
pasaban todas por `get_db()`.

## Sincronización de eventos hacia el servidor central (HU-5.8)

### Por qué y qué encontró esta HU al empezar

El objetivo es que los eventos capturados en un entorno intermitente
(Google Colab u otro) lleguen al dashboard administrativo aunque ese
entorno nunca abra una conexión directa a la base central — el modelo que
ya describía la sección de HU-5.4 de arriba, pero que hasta esta HU nadie
había construido. Al empezar, en el repositorio **no existía** ningún
cliente HTTP, mecanismo de reintento, cola de pendientes, ni endpoint
receptor: solo el comentario `# TODO(HU-5.8): encolar para reintento de
sincronización` en `insert_event_dual()`. Tampoco existía HU-5.6 (el
endpoint de ingesta) como pieza separada — HU-5.8 lo incluyó porque, sin
él, no había a dónde sincronizar.

Lo que sí existía y se reutilizó tal cual, sin modificarlo:
- `evento_uuid` (HU-5.4): UUID4 generado una sola vez en `_prepare_event()`
  y `UNIQUE NOT NULL` en ambos esquemas — es el identificador de
  idempotencia que pedía esta HU, no se creó uno nuevo.
- `validar_token()` (HU-5.5, `auth/tokens.py`): distingue token
  inexistente / expirado / revocado. El endpoint receptor lo usa sin
  tocar su código.

### Cola local de sincronización (`audit_sync_queue`)

Nueva tabla, solo en la base **local** (`schema/audit_log.sql`), NO en la
central. Cada evento capturado por la librería tiene una fila espejo con
`estado` (`PENDIENTE` | `SINCRONIZADO` | `FALLIDO`), `intentos`,
`ultimo_intento`, `ultimo_error` y `sincronizado_en`.

Se modela como tabla separada — y no como columnas nuevas en `audit_log`
— a propósito: `audit_log` tiene los triggers de inmutabilidad de HU-5.4
(`trg_audit_log_no_update`/`no_delete`), que bloquean *cualquier* UPDATE.
El estado de sincronización necesita mutar (`PENDIENTE` → `SINCRONIZADO`),
así que vive aparte, como metadata operativa de transporte — mismo
criterio que ya justificaba dejar `evento_uuid` fuera de
`hash_integridad`. Esto evita tocar (o debilitar) la inmutabilidad ya
probada en `tests/test_central_db.py::TestInmutabilidad`.

`models/audit_log.py::insert_event_and_enqueue_sync(conn, event)` es el
único punto que usan los cuatro interceptores de captura
(`data_capture.py`, `export_capture.py`, `failed_access.py`,
`session_tracker.py`): inserta en `audit_log` y encola en
`audit_sync_queue` en la misma operación. **CA1 se garantiza aquí**: el
envío HTTP, si se intenta, ocurre en la línea siguiente, después de que
esta función ya retornó — nunca antes.

### Cliente HTTP (`audit_tracer/sync_client.py`)

Usa `requests` (ya estaba instalado en el entorno como dependencia
transitiva; se agregó explícitamente a `requirements.txt`). No se usó el
paquete `backoff` sugerido en la HU porque no estaba instalado — se
implementó backoff exponencial acotado a mano (`BACKOFF_BASE_SEGUNDOS *
2^intento`, máx. `MAX_INTENTOS_POR_EVENTO = 3` intentos por evento).

- **CA2**: fallos de red/timeout/5xx se reintentan con backoff hasta
  agotar los 3 intentos; nunca un bucle infinito en memoria — el estado
  vive en SQLite (`audit_sync_queue`), así que un evento sobrevive al
  cierre del proceso/notebook y se retoma en cualquier sincronización
  posterior (`sync_now()`, o el hilo automático de abajo).
- **CA4**: un 401/403 (token inválido/expirado/revocado) **no se
  reintenta** — reintentar con el mismo token no cambia el resultado. El
  token nunca se imprime, nunca se guarda en `ultimo_error`.
- **CA3**: mientras no llega un 200/201 del servidor, el evento se queda
  en `audit_sync_queue` con estado `FALLIDO` (nunca se borra ni se marca
  `SINCRONIZADO` sin confirmación positiva).
- **HTTPS obligatorio**: `configure_sync()` rechaza URLs que no sean
  `https://`, con una única excepción para `localhost`/`127.0.0.1` (uso
  exclusivo de pruebas/desarrollo).

`configure_sync(api_url, token, auto=True)` es el punto de entrada desde
un notebook — usa un token personal ya emitido (HU-5.5, vía
`/admin/tokens` o `generar_token()`). Con `auto=True` (por defecto)
arranca un hilo daemon que barre la cola cada 30s, así un evento
capturado sin conexión se sincroniza solo en cuanto el servidor vuelve a
estar disponible, sin que el notebook tenga que hacer nada.

### Endpoint receptor: `POST /api/eventos/sincronizar`

Mismo patrón que los endpoints existentes de HU-5.5
(`/api/tokens/validar`): sin sesión Flask, autenticado por
`Authorization: Bearer <token>`. Recibe el evento como JSON con los
mismos nombres de campo que `schema/audit_log.sql` /
`audit_log_central.sql` (`usuario_id`, `sesion_id`, `timestamp`,
`tipo_accion`, `dataset_nombre`, `columnas_afectadas`, `ruta_destino`,
`filas_exportadas`, `sobrescritura`, `contexto_ejecucion`,
`motivo_fallo`, `nivel_alerta`, `motivo_alerta`) más `evento_uuid`.

1. **CA4** — Valida el token con `validar_token()` contra la base
   central antes de aceptar nada. Si es inválido, responde `401` y deja
   constancia en `audit_log` central (`tipo_accion =
   'SINCRONIZACION_RECHAZADA'`) sin guardar ni loguear el valor del
   token — solo el motivo (`"Token revocado"`, `"Token expirado"`, etc.).
2. Valida que el payload traiga los campos `NOT NULL` del esquema
   (`evento_uuid`, `usuario_id`, `sesion_id`, `timestamp`, `tipo_accion`)
   — si falta alguno, `400`, nunca `500`.
3. **CA5** — Inserta con `models/audit_log.py::insert_event_if_new()`.

### Idempotencia a nivel de base de datos (CA5)

`insert_event_if_new(conn, event)` primero hace un `SELECT` por
`evento_uuid` (optimización del camino feliz), pero la garantía real de
no-duplicados es la restricción `evento_uuid TEXT UNIQUE NOT NULL` que ya
traía el esquema central desde HU-5.4: si dos reintentos llegan casi a la
vez, el que pierde la carrera choca con esa `UNIQUE` en el `INSERT` y se
recupera capturando el `IntegrityError` — la base de datos es quien
impide el duplicado, no un `SELECT` previo que podría perder la carrera.
Responde `201` en la primera inserción y `200` con `{"status":
"duplicado"}` en cualquier reintento posterior del mismo `evento_uuid`.

### Indicador en el notebook (Sub-tarea 5)

`audit_tracer.sync_status()` imprime y devuelve un resumen (`{pendientes,
fallidos, sincronizados, ultimo_intento, ultimo_error}`) leído de
`audit_sync_queue`. `audit_tracer.sync_now()` fuerza un barrido
inmediato de la cola sin esperar al hilo automático.

### Dashboard administrativo — `/admin/sincronizacion` (Sub-tarea 6)

Extiende el dashboard existente (mismo patrón que `/admin/tokens`, un
link más en el sidebar de "Administración") — no se construyó un
dashboard nuevo.

**Límite honesto de arquitectura**: el dashboard Flask lee
`audit_central.db`; la cola de pendientes/fallidos vive en el
`audit_trail.db` **local de cada notebook/Colab**. En un despliegue real,
un Colab remoto corre en otra máquina que el servidor central jamás toca
directamente — el servidor no puede saber cuántos eventos tiene
pendientes un cliente que nunca le reportó su estado (eso requeriría un
protocolo de heartbeat que esta HU no pide y que sería alcance nuevo). Por
eso el panel muestra dos cosas con procedencia distinta, explícitamente
etiquetadas:
- **Cola de "esta instancia"**: leída directamente de `audit_trail.db` si
  existe en este mismo servidor (como en este repo, donde local y central
  conviven en el mismo filesystem para pruebas/demo) — pendientes,
  fallidos, sincronizados, último intento, último error.
- **Rechazos de autenticación**: esta sí es una señal genuinamente
  centralizada — eventos `SINCRONIZACION_RECHAZADA` que el servidor
  central observó de verdad, sin exponer ningún token.

### Pruebas

`tests/test_sync_events.py` — cola local y `evento_uuid` estable entre
reintentos, persistencia-antes-que-red (CA1), cliente HTTP con
`requests.post` mockeado (envío exitoso, servidor caído, recuperación de
conexión, token inválido sin retry infinito, no reenvío de un evento ya
sincronizado), idempotencia a nivel de BD (incluida la rama de
`IntegrityError` por carrera concurrente), el endpoint receptor completo
con `app.test_client()` contra una base central aislada (a diferencia de
otros tests del repo, que sin querer pegan contra `audit_central.db`
real), y una integración extremo a extremo con un servidor Flask real en
un hilo (`werkzeug.serving.make_server`, sin mocks) que prueba caída y
recuperación con sockets reales.

## Login por código de dispositivo (HU-5.7)

### Por qué

`audit_tracer.login(email, password)` (HU-2.5) ya existía, pero obliga a
escribir la contraseña en texto plano dentro de una celda de notebook —
mala práctica en un entorno compartido/versionado como Colab, y fricción
real cada vez que se reinicia el runtime. HU-5.7 agrega un segundo camino,
sin credenciales: `audit_tracer.login()` — el mismo patrón "device flow"
de OAuth 2.0 (RFC 8628) que ya usan `gh auth login` o la CLI de Google
Cloud: un código corto que se confirma en el navegador, mientras la
librería espera por polling.

Los dos caminos conviven en la misma función (`SessionTracker.login()`):
si se pasan `email`/`password`, es exactamente el comportamiento de
HU-2.5, sin cambios. Si no se pasa nada, se dispara el flujo de código.

### Dos secretos, no uno

Cada intento de login genera **dos** valores distintos, con roles
distintos — el mismo diseño que OAuth Device Authorization Grant:

- `codigo` — 8 caracteres legibles (`XXXX-XXXX`, sin `0/O/1/I` para
  evitar errores de tecleo). Es lo único que ve un humano; se muestra en
  el notebook y se escribe en el dashboard.
- `device_code` — un secreto largo (`secrets.token_urlsafe(32)`) que solo
  conoce el proceso que llamó a `/iniciar`. Es la credencial real del
  polling (`/api/auth/dispositivo/estado`).

Si el `codigo` corto alcanzara para consultar el estado, cualquiera que
lo viera de reojo en la pantalla de otra persona podría hacer polling y
robarle el token en cuanto lo confirmara. Con dos secretos separados,
"ver el código" y "poder recuperar el token" son cosas distintas.

### Servidor: `audit_tracer/auth/device_codes.py` + `models/device_codes.py`

Mismo patrón que `auth/tokens.py`/`models/tokens.py` (HU-5.5): tabla
`codigos_dispositivo` creada de forma perezosa en la conexión que se le
pase (sin tocar `schema/*.sql` ni las migraciones de `db.py`). No está
sujeta a los triggers de inmutabilidad de `audit_log` (HU-5.4): esos
triggers son específicos de esa tabla, y `codigos_dispositivo` — igual
que `tokens_acceso` — es metadata operativa que necesita mutar
(`PENDIENTE` → `CONFIRMADO` → `CONSUMIDO`).

- **CA1** — `POST /api/auth/dispositivo/iniciar`: sin autenticación (es
  el primer paso, antes de que exista cualquier token). Código válido
  por `CODIGO_EXPIRACION_MINUTOS = 10` — una ventana corta, distinta de
  los 30 días de vigencia del token que se genera al confirmar.
- **CA2** — `GET/POST /auth/dispositivo`: requiere sesión de dashboard
  (`@login_required`). Al confirmar, reutiliza `generar_token()` de
  HU-5.5 sin modificarlo, y registra `CONFIRMACION_LOGIN_DISPOSITIVO` en
  auditoría.
- **CA3** — `GET /api/auth/dispositivo/estado?device_code=...`: sin
  sesión ni token — el `device_code` largo y secreto ES la credencial.
  Al reportar `CONFIRMADO` por primera vez, entrega el token y marca el
  código `CONSUMIDO` de inmediato (`token = NULL`): una segunda consulta
  con el mismo `device_code` responde `410 Gone`, nunca el token dos
  veces.

`login_required` (en `app.py`) ahora arma un parámetro `next` con la ruta
a la que iba el usuario antes de exigirle sesión, y `/login` lo respeta
al redirigir tras un login exitoso — así, visitar el link de activación
sin sesión abierta cae en el login normal y, al autenticarse, vuelve
exactamente a la página de confirmación con el código ya precargado
(verificado en navegador de punta a punta, no solo con tests).

### Cliente: `audit_tracer/device_login.py`

`device_login(api_url, cache_dir=None, ...)` es una función pura de
"consíguime un token", sin efectos secundarios sobre `SessionTracker` —
eso lo orquesta `SessionTracker.login()` por separado (separación de
responsabilidades, y más fácil de probar cada pieza por su lado):

1. **CA4/CA5** — Si hay un token cacheado, lo valida contra
   `/api/tokens/validar` (HU-5.5, reutilizado tal cual). Si sigue
   vigente, retorna de inmediato sin imprimir ningún código
   (`origen: 'cache'`). Si no (expiró/fue revocado), **descarta el
   caché y repite el flujo automáticamente** — el usuario no tiene que
   notar la diferencia ni intervenir.
2. **CA1** — Si no hay token reusable, pide `/iniciar` e imprime el
   código + URL de activación en la salida del notebook.
3. **CA3** — Polling de `/estado` cada `intervalo_polling` segundos
   (por defecto 5, el mismo valor que sugiere el servidor) hasta
   `CONFIRMADO`, `EXPIRADO`, o agotar `timeout_seconds` (600s por
   defecto — la misma ventana que el código en el servidor). Un error de
   red durante el polling no aborta: se reintenta en el siguiente ciclo.
4. **CA4** — Al confirmarse, cachea `{token, usuario_id, guardado_en}`
   en disco.

`_default_cache_dir()` prioriza `/content/drive/MyDrive/.audit_tracer`
(el punto de montaje estándar de `drive.mount()` en Colab) si existe —
porque sobrevive al cierre de la sesión de Colab, que es exactamente el
problema que motiva esta HU. Si no existe (entorno local, script, CI),
cae a `~/.audit_tracer`.

`SessionTracker.login()` sin credenciales resuelve `api_url` desde el
parámetro o la variable de entorno `AUDIT_TRACER_API_URL`, llama a
`device_login()`, actualiza `self.usuario_id` en éxito (igual que el
camino de HU-2.5, para que los eventos posteriores queden bien
atribuidos), y además **configura `sync_client` automáticamente** con el
token recién obtenido — así "un solo comando" deja lista tanto la
identidad local como la sincronización hacia la central, sin un segundo
paso manual.

No se reexporta `device_login()` a nivel de paquete (`audit_tracer.device_login`
sigue siendo el submódulo, no la función): nombrar la función igual que
su módulo y hacer `from .device_login import device_login` en
`__init__.py` sombrea `audit_tracer.device_login` con la función,
rompiendo cualquier `import audit_tracer.device_login as m; m.requests`
— exactamente el bug que atrapó la primera versión de los tests de esta
HU. `audit_tracer.login()` ya es el único comando que pide CA1; acceso
directo a `device_login()` sigue disponible vía
`from audit_tracer.device_login import device_login`.

### Pruebas

`tests/test_device_login.py` — generación de código (CA1: legible, único,
`device_code` no adivinable desde el código corto), confirmación (CA2:
éxito, código inexistente/ya usado/expirado, evento de auditoría),
consulta de estado (CA3: pendiente, confirmado con entrega única del
token, expirado, inexistente), los tres endpoints HTTP completos con
`app.test_client()` (incluido que `GET /auth/dispositivo` sin sesión
redirige con `next`), `device_login()` con `requests` mockeado (polling
exitoso, timeout de confirmación, expiración a mitad del polling, caché
válido evita repetir el flujo, caché inválido dispara uno nuevo, `force=True`,
sin conexión al iniciar), y una integración extremo a extremo con un
servidor Flask real en un hilo — un segundo hilo confirma el código
mientras `device_login()` hace polling real por la red, sin mocks.
`tests/test_session_tracker.py::TestSessionTrackerLoginPorCodigo` cubre
la orquestación de `SessionTracker.login()` (actualización de
`usuario_id`, configuración automática de `sync_client`, resolución de
`AUDIT_TRACER_API_URL`, y que el camino con `email`/`password` no toca
`device_login()` en absoluto).
