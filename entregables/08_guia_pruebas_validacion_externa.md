---
titulo: Guía de pruebas de la validación externa
anexo: Anexo 13 · Validación externa (20 de noviembre de 2026)
fecha: 2026-11-21
---

[TOC]

# 0. Procedencia y verificación de la estructura

| | |
|---|---|
| Fuente | `Guia_Pruebas_Validacion_Audit_Tracer_Entrega (2).pdf` (16 páginas, fechada el 9 de noviembre de 2026) y `Audit_Tracer_Validacion.ipynb` (SHA-256 `129449eb…88b679f7`, modificado el 20/11/2026 09:53), usados en la sesión del 20/11/2026. Ninguno de los dos estaba versionado en el repositorio. |
| Notebook | Se incluye tal cual como `entregables/08_notebook_validacion_externa.ipynb` (42 celdas, sin salidas y sin contraseñas: las pide con un campo oculto). |
| Qué se omitió | Las dos hojas de credenciales (páginas 4 y 5 del PDF original) contienen contraseñas reales de las cuentas de prueba. **No se incluyen** en este documento ni en el repositorio. |
| Datos | **Sintéticos.** La celda A1 genera `pacientes_sinteticos.csv` con `random.seed(7)` (2 500 pacientes) y el notebook lo declara en su primera celda. El contexto del bloque D (`vitals_icu_demo.csv`, línea base y anomalías) lo siembra `validacion_usuarios/preparar_sesion.py`, también con datos sintéticos. No se usó MIMIC-III. |
| Servidor | Despliegue de demostración en Render (plan gratuito, disco efímero), sin servidor de correo. |

**Estructura verificada (21/11/2026):** 26 escenarios en 4 bloques, tal como dice el documento.

| Bloque | Escenarios | Cantidad | Dónde se ejecuta |
|---|---|---|---|
| A · Captura transparente y atribución | A1–A6 | 6 | Notebook + dashboard |
| B · Integridad y no repudio | B1–B6 | 6 | Notebook (B4 y B5 también dashboard) |
| C · Autenticación, tokens y control de acceso | C1–C7 | 7 | Notebook + dashboard |
| D · Detección, investigación y evidencia | D1–D7 | 7 | Solo dashboard |
| **Total** | | **26** | 19 automatizados en el notebook (A1–C7) + 7 en el dashboard |

Conteo hecho sobre el texto del PDF (identificadores A1…D7) y sobre las celdas del notebook (A1…C7; el bloque D no tiene celdas porque es manual).

# 1. Qué se evalúa

Audit Tracer se instala con `import audit_tracer` en un notebook y registra cada operación sobre datos clínicos. Cada evento se guarda y se firma en el equipo del usuario y luego viaja al servidor central que usan los auditores. El entorno de Colab se considera hostil: por eso el bloque B parte de un atacante con control total de ese equipo. Duración prevista: 45 minutos.

# 2. Antes de empezar

Cada evaluador recibió una hoja privada con su código (`p1` o `p2`) y cinco cuentas:

| Cuenta (correo) | Rol | Para qué se usa |
|---|---|---|
| `cientifico.<código>@validacion.audit` | CIENTIFICO_DATOS | Confirmar el login desde Colab (A2, C1) y probar accesos prohibidos (C4) |
| `auditor.<código>@validacion.audit` | AUDITOR | Revisar en el dashboard lo que dejan los bloques A, B y C, y hacer D1–D7 |
| `analista.<código>@validacion.audit` | ANALISTA | Intentar escalar privilegios (C4) y revisar alertas (D4) |
| `admin.<código>@validacion.audit` | ADMIN | Revocar tokens (C3), ver tokens, rechazos y usuarios (C2, C3, C6) y las alertas (D4) |
| `bloqueo.<código>@validacion.audit` | CIENTIFICO_DATOS | Se bloquea a propósito en C6 |

1. Entrar a Google Colab y subir `Audit_Tracer_Validacion.ipynb` (Archivo › Subir notebook).
2. En la celda de configuración, cambiar `EVALUADOR` por el código asignado (`p1` o `p2`).
3. Ejecutar las tres primeras celdas (configuración, instalación y utilidades). La primera respuesta puede tardar un minuto si el servidor estaba dormido.
4. Abrir el dashboard en otra pestaña.

Cada prueba imprime `CUMPLE` o `NO CUMPLE`. Las líneas marcadas «Límite conocido» confirman una debilidad que el equipo ya conoce: ahí `CUMPLE` significa que el comportamiento coincide con lo declarado.

# 3. Mapa de escenarios

| ID | Qué se prueba | Propiedad de seguridad | Dónde |
|---|---|---|---|
| A1 | Actividad sin usuario identificado | Registro completo | Notebook + dashboard |
| A2 | Login por código y atribución tardía | Autenticación, atribución | Notebook + dashboard |
| A3 | Análisis clínico sin cambios de código | Captura no invasiva | Notebook + dashboard |
| A4 | Errores del usuario intactos | Captura no invasiva | Notebook + dashboard |
| A5 | Exportación masiva | Detección de exfiltración | Notebook + dashboard |
| A6 | Servidor central caído | Disponibilidad de la evidencia | Notebook + dashboard |
| B1 | UPDATE y DELETE directos sobre SQLite | Inmutabilidad | Notebook |
| B2 | Alteración tras borrar los triggers | Detección de manipulación | Notebook |
| B3 | Alteración con SHA-256 recalculado | Firma digital | Notebook |
| B4 | Atacante con la llave privada | Copia central como defensa | Notebook + dashboard |
| B5 | Eventos manipulados en tránsito | No repudio, anti-replay | Notebook + dashboard |
| B6 | Árbol de Merkle y ancla externa | Integridad por lotes | Notebook |
| C1 | Dos secretos del flujo de dispositivo | Autenticación | Notebook + dashboard |
| C2 | Tokens inválidos y HTTPS obligatorio | Autenticación, canal seguro | Notebook + dashboard |
| C3 | Revocación inmediata de un token | Gestión de credenciales | Notebook + dashboard |
| C4 | Escalada de privilegios | Control de acceso (RBAC) | Notebook + dashboard |
| C5 | Cookie de sesión forjada | Integridad de la sesión | Notebook + dashboard |
| C6 | Fuerza bruta | Bloqueo de cuenta | Notebook + dashboard |
| C7 | Cookie reutilizada tras cerrar sesión | Gestión de sesiones | Notebook + dashboard |
| D1 | Consulta forense de eventos | Trazabilidad | Dashboard |
| D2 | Linaje del dato | Trazabilidad | Dashboard |
| D3 | Anomalías | Detección | Dashboard |
| D4 | Alertas y su seguimiento | Respuesta a incidentes | Dashboard |
| D5 | Exploración y actividad en vivo | Investigación | Dashboard |
| D6 | Reportes para auditoría | Evidencia normativa | Dashboard |
| D7 | Verificación de integridad y anclas | Evidencia de integridad | Dashboard |

# 4. Bloque A — Captura transparente y atribución (≈ 10 min)

**A1. Actividad sin identificar.** La celda genera 2 500 pacientes sintéticos y carga el archivo sin iniciar sesión.
*Notebook:* la carga queda con usuario `DESCONOCIDO` y nivel `CRITICO`; el evento nunca se descarta.
*Dashboard (auditor, después de A2):* Eventos › Dataset `pacientes_sinteticos.csv` › Solo Críticos → una fila `CARGA` de `DESCONOCIDO`, `CRITICO`, motivo «Operación ejecutada por usuario no identificado».

**A2. Login por código y atribución.** La celda imprime una URL y un código; se abre la URL con la cuenta *cientifico* y se confirma el código.
*Notebook:* login sin escribir la contraseña; aparece `ATRIBUCION_SESION` y el evento de A1 sigue como `DESCONOCIDO` (bitácora inmutable).
*Dashboard (auditor):* filtrar Acción `ATRIBUCION_SESION` → fila `ADVERTENCIA`, motivo «Identificación tardía»; el detalle muestra el correo de la cuenta *cientifico*.

**A3. Análisis sin cambios de código.** Pandas corriente, sin llamadas a la librería; se ejecuta con auditoría y en un proceso sin Audit Tracer.
*Notebook:* quedan `CARGA`, `CONSULTA`, `TRANSFORMACION` y `EXPORTACION`, todos firmados; los dos archivos de salida son idénticos byte a byte.
*Dashboard:* filas de esos tipos del usuario; una `EXPORTACION` de 200 filas hacia `salida_auditada.csv` (buscar en la columna Detalle); firma «Válida y Verificada»; el linaje muestra la carga seguida de las transformaciones.

**A4. Errores intactos.** Abre un archivo inexistente.
*Notebook:* llega el `FileNotFoundError` normal de pandas y queda un `ACCESO_FALLIDO`.
*Dashboard:* Acción `ACCESO_FALLIDO`, Dataset `no_existe.csv` → el detalle muestra el motivo y la celda del notebook.

**A5. Exportación masiva.** Exporta más de 1 000 filas y sincroniza.
*Notebook:* `CRITICO` con el número de filas en el motivo; sin pendientes.
*Dashboard:* Acción `EXPORTACION` + Solo Críticos → destino `extraccion_masiva.csv`, motivo «Exportación masiva» con el número de filas.

**A6. Servidor central caído.** Apunta la sincronización a un puerto sin servicio, exporta y luego restablece la conexión.
*Notebook:* la operación termina sin esperar al servidor; el evento queda en cola local y se envía al volver la conexión.
*Dashboard:* una `EXPORTACION` hacia `sin_conexion.csv` de 10 filas, con la hora en que se hizo la exportación.

# 5. Bloque B — Integridad y no repudio (≈ 10 min)

B1, B2, B3 y B6 ocurren en copias locales o temporales; B4 y B5 dejan huella en el servidor.

**B1. UPDATE y DELETE directos.** Con `sqlite3`, sin la librería, intenta alterar y borrar la exportación de A5. *Notebook:* ambas fallan con `INMUTABILIDAD`, el registro no cambia y los dos intentos quedan en `audit_intentos_bloqueados`.

**B2. Alteración tras borrar los triggers.** Sobre una copia, borra los triggers y cambia `filas_exportadas`. *Notebook:* `verify_integrity()` señala únicamente el registro alterado.

**B3. Alteración con SHA-256 recalculado.** El atacante recalcula el hash. *Notebook:* el hash ya no delata el cambio (límite conocido: SHA-256 sin clave); la firma Ed25519 sí lo detecta.

**B4. Atacante con la llave privada.** Vuelve a firmar el registro alterado y lo reenvía. *Notebook:* la copia local pasa la verificación (límite conocido); el servidor responde duplicado y conserva el hash original. *Dashboard:* el hash de la exportación de A5 es el original y la prueba Merkle es válida.

**B5. Eventos manipulados en tránsito.** Envía un evento válido, lo reenvía y prueba alteraciones campo por campo, una llave ajena, una firma basura y la eliminación de la firma. *Notebook:* 201 en el control, 200 en el reenvío y 422 en las ocho manipulaciones. *Dashboard:* ocho filas `FIRMA_INVALIDA` de nivel `CRITICO`.

**B6. Árbol de Merkle y ancla externa.** Construye un lote de 16 eventos, publica su raíz firmada y altera un evento. *Notebook:* la prueba de inclusión es válida con 4 pasos y falla con la hoja alterada; el ancla coincide antes del cambio y señala alteración después.

# 6. Bloque C — Autenticación, tokens y control de acceso (≈ 10 min)

**C1. Dos secretos en el flujo de dispositivo.** *Notebook:* el código corto no sirve como credencial (404), el token se entrega al confirmar y una segunda consulta responde 410. *Dashboard:* una fila `CONFIRMACION_LOGIN_DISPOSITIVO` nueva.

**C2. Tokens inválidos y HTTPS.** Token alterado, inventado y ausente. *Notebook:* 401 en los tres casos; el cliente rechaza una URL `http://` externa. *Dashboard (admin):* Administración › Sincronización › Rechazos de autenticación: dos «Token inexistente o inválido» y uno «Token no proporcionado o formato inválido».

**C3. Revocación inmediata.** *Notebook:* el token funciona (201), el administrador lo revoca y la siguiente petición recibe 401 «Token revocado». *Dashboard (admin):* el token aparece como Revocado y hay un rechazo nuevo con ese motivo.

**C4. Escalada de privilegios.** *Notebook:* `CIENTIFICO_DATOS` recibe 403 en `/eventos` y `/merkle/publicar`; `ANALISTA` no puede crear un ADMIN ni emitir un token ajeno. *Dashboard:* tres filas `ACCESO_DENEGADO` de nivel `ADVERTENCIA`, con rol, módulo, ruta y método.

**C5. Cookie de sesión forjada.** Cookie con `rol=ADMIN` firmada con la clave que estuvo publicada y con una aleatoria. *Notebook:* en ambos casos el servidor la trata como sesión inexistente y redirige a `/login`.

**C6. Fuerza bruta.** Con la cuenta *bloqueo*. *Notebook:* la quinta contraseña errónea bloquea la cuenta. *Dashboard:* cinco `ACCESO_FALLIDO` con nivel creciente: NORMAL, NORMAL, ADVERTENCIA, CRITICO, CRITICO; la cuenta aparece Bloqueada.

**C7. Cookie reutilizada tras cerrar sesión.** *Notebook:* la cookie funciona antes del cierre y después redirige a `/login`. *Dashboard:* una fila `CIERRE_SESION` y una `REVOCACION_TOKEN`.

# 7. Bloque D — Detección, investigación y evidencia (≈ 15 min, cuenta auditor)

**D1. Consulta forense.** Eventos › Acción `EXPORTACION` › Desde = hoy; abrir la exportación de A5; revisar resumen forense, usuario, sesión, hash y firma; Verificar Integridad Merkle. *Esperado:* los filtros se combinan; Merkle responde que la prueba es válida.

**D2. Linaje.** Linaje › `vitals_icu_demo.csv` (carga, tres transformaciones y exportación) y `pacientes_sinteticos.csv`. *Esperado:* orden temporal; cada nodo abre su evento.

**D3. Anomalías.** Eventos › Solo anomalías. *Esperado:* al menos tres casos sembrados (5 000 filas frente a un promedio cercano a 105; una consulta a las 02:14 UTC; un dataset usado por dos usuarios en 15 minutos).

> Observación del 21/11/2026: estos tres casos los siembra `preparar_sesion.py` enviando eventos **sin firma** por la API. Los eventos que genera la librería van firmados y no pasan por el detector (Anexo 13, caso de uso 2).

**D4. Alertas.** Con admin: Administración › Alertas (catálogo de cinco tipos e historial). Con analista: `/auditoria/alertas`, cambiar una alerta a `EN_REVISION`. Con auditor: la misma ruta responde 403. Sin servidor de correo el estado es `SIN_SERVICIO_CORREO`.

**D5. Exploración.** `/auditoria`: buscar un evento por su hash, guardar un filtro por `CRITICO`, Ver relaciones, Actividad en vivo.

**D6. Reportes.** Reportes › filtrar por usuario y fecha › Exportar Reporte (CSV) y Exportar Críticos (CSV). *Esperado:* el CSV coincide con la tabla; trae la referencia normativa por evento; el de críticos incluye el hash.

**D7. Integridad y anclas.** Eventos › Verificar Integridad; Integridad Merkle › Verificar un lote. *Esperado:* todos los registros íntegros; cada ancla con integridad y firma válidas.

# 8. Registro de resultados

La guía original termina con una tabla para marcar cada escenario (A1–D7) y una tabla de hallazgos adicionales (severidad, componente, descripción, recomendación). Los resultados de la sesión del 20/11/2026 y la encuesta SUS están en el capítulo 8 del documento final; [PENDIENTE: la hoja de resultados diligenciada por el evaluador no está en el repositorio].
