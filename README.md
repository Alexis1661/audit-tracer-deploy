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
un servidor central. HU-5.4 construye el destino de esa sincronización — el
endpoint que la recibe (HU-5.6) y el envío desde la librería (HU-5.8) son
trabajo de HUs posteriores.

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
(`data_capture.py`, `export_capture.py`, etc.) es trabajo de HU-5.8, que
todavía no existe.

### Dashboard → base central (CA4)

`app.py::get_db()` es el único punto de conexión de las rutas del
dashboard (ninguna llama a `get_connection()` directo). Redirigirlo a la
base central fue, en la práctica, cambiar esa única función: ahora llama a
`get_central_connection()` en vez de `get_connection()`. Todas las rutas
existentes (`/eventos`, `/eventos/<id>`, `/reportes`, login, gestión de
usuarios, etc.) siguen funcionando sin cambios adicionales porque ya
pasaban todas por `get_db()`.
