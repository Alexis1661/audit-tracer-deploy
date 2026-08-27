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
