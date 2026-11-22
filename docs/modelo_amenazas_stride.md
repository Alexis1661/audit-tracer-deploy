# Anexo — Modelo de amenazas STRIDE (HU-6.4)

| | |
|---|---|
| **Sistema** | Audit Tracer — trazabilidad y auditoría de datos clínicos |
| **Versión del modelo** | 1.1 |
| **Fecha** | 03/11/2026 · actualizado el 21/11/2026 (plan de mitigación ejecutado) |
| **Código evaluado** | rama `feature/HU-6.4-Modelo-de-amenazas-STRIDE`, commit `b6fd6e8` (incluye hasta HU-7.3); estados y evidencias actualizados sobre la rama `entregables-documento-final` el 21/11/2026 |
| **Método** | STRIDE por elemento sobre el diagrama de flujo de datos, con riesgo cualitativo (probabilidad × impacto) |
| **Versión para máquinas** | [`modelo_amenazas_stride.csv`](modelo_amenazas_stride.csv) |
| **Anexos relacionados** | [Matriz de trazabilidad normativa (HU-6.6)](matriz_trazabilidad_normativa.md) · [Pruebas de ataque simulado (HU-6.5)](validacion_resultados.md) |
| **Estado** | Pendiente de revisión del equipo (ver sección 9) |

## 1. Propósito y alcance

Este anexo identifica, componente por componente, qué puede salir mal en la seguridad de Audit Tracer y qué lo impide. Sirve para que la institución de salud tenga confianza en que los riesgos se identificaron antes de operar los componentes centralizados, y para que el equipo sepa qué falta.

**Qué cubre.** La arquitectura completa, incluida la arquitectura híbrida de HU-5.4 a HU-5.8 (base central, endpoint receptor, tokens, login por dispositivo y sincronización), que a la fecha está implementada, no solo diseñada:

1. la **librería** `audit_tracer`, que corre en el notebook o script del científico de datos;
2. el **canal de transmisión** entre la librería y el servidor;
3. el **servidor central** (API, base consolidada y anclaje Merkle);
4. el **dashboard** web.

**Qué no cubre.** La seguridad física, la del proveedor de hospedaje (Railway) y la de los equipos personales, más allá de lo que la librería puede controlar. También quedan fuera las amenazas organizacionales (ingeniería social genérica, personal malintencionado con acceso físico) que no tienen una contramedida en el software. Las obligaciones normativas están en la matriz de HU-6.6.

**Cómo se construyó.** Además de revisar el diseño y el código, cada amenaza que el análisis consideró posible y no cubierta se **probó contra el sistema real** (cliente de pruebas de Flask y base central temporal). Las que se confirmaron quedaron como pruebas automáticas (sección 2). Así el modelo no depende de suposiciones: cada "implementada" tiene una prueba que la demuestra y cada riesgo abierto tiene una prueba que lo reproduce.

## 2. Cómo leer y reproducir el modelo

Cada amenaza tiene un identificador `COMPONENTE-LetraSTRIDE-número`: `LIB` librería, `CAN` canal, `SRV` servidor central, `DSH` dashboard. Por ejemplo, `SRV-T3` es la tercera amenaza de *Tampering* del servidor.

| Estado | Significado |
|---|---|
| **Implementada** | La mitigación existe, cubre la amenaza y tiene una prueba automatizada que lo demuestra. |
| **Parcial** | Hay una mitigación implementada, pero deja un riesgo residual; se indica qué falta. |
| **Planeada** | Todavía no hay mitigación en el código; se indica la medida concreta que se debe implementar. |

```bash
python -m pytest tests/test_modelo_amenazas.py -v    # coherencia del anexo, mitigaciones y riesgos abiertos
python -m pytest tests/test_ataques_simulados.py     # ataques simulados de HU-6.5, citados como evidencia
```

`tests/test_modelo_amenazas.py` tiene tres grupos:

- **`TestDocumento`** falla si el anexo y el CSV dejan de coincidir, si falta una categoría STRIDE en algún componente (CA1), si una amenaza queda sin mitigación (CA2) o si una prueba o un control citados desaparecen.
- **`TestMitigacionesVerificadas`** prueba las mitigaciones que no tenían una prueba propia (por ejemplo, que el token de la librería no abre el dashboard).
- **`TestRiesgosAbiertos`** reproduce los riesgos confirmados. Cada prueba describe el comportamiento seguro y está marcada `xfail(strict=True)`: hoy aparece como `XFAIL`. **Cuando alguien implemente la mitigación, la prueba pasará y la suite fallará**, lo que obliga a quitar el `xfail` y actualizar el estado de la amenaza en este anexo.

**Ejecución registrada:** 21/11/2026, Python 3.12.6, Windows 11. Resultado: 154 pruebas superadas y 9 riesgos abiertos reproducidos (`XFAIL`). Entre el 03/11 y el 21/11 el commit `3d7dc2b` (08/11) cerró DSH-I1 y DSH-I3, y el 21/11 se corrigió el ayudante `_sesion()` de las pruebas, que había quedado sin token de sesión.

## 3. Arquitectura y superficies de ataque

### 3.1 Diagrama de flujo de datos

Las líneas punteadas son límites de confianza: los datos que los cruzan vienen de una zona que la otra no controla.

```
  ┌─ LB1: equipo del científico de datos (Colab, Jupyter o script) ────────────────┐
  │                                                                                 │
  │   Científico ──pandas──▶ [ Librería audit_tracer ]──escribe──▶ (audit_trail.db) │
  │                           interceptores · firma Ed25519        cola de sync     │
  │                                │                                                │
  │       (~/.audit_tracer: token cacheado y llave privada; o carpeta de Drive)     │
  └────────────────────────────────┼────────────────────────────────────────────────┘
  - - - - - - - - - - - - - - - - -│- - - - LB2: Internet (canal de transmisión) - - -
                                   │ HTTPS · Bearer token · evento firmado
  ┌─ LB3: servidor central (Railway) ──────────────────────────────────────────────┐
  │                                ▼                                                │
  │   [ API Flask ] /api/eventos/sincronizar · /api/usuarios/llave-publica          │
  │                 /api/auth/dispositivo/* · /api/tokens/*                         │
  │        │                                                                        │
  │        ▼                                                                        │
  │   (audit_central.db)  ◀──lee── [ Dashboard Flask ] ◀──── sesión (cookie) ───┐   │
  │   audit_log · usuarios · tokens_acceso · device_codes                       │   │
  │        │                                                                    │   │
  │        └──lotes horarios──▶ [ Merkle ] ──raíz firmada──▶ (merkle_anchors/)  │   │
  └─────────────────────────────────────────────────────────────────────────────┼───┘
  - - - - - - - - - - - - - - - - - - - - - - - - - LB4: navegador - - - - - - -│- - -
                                                    Auditor · Analista · Admin ─┘
```

### 3.2 Componentes

| Componente | Qué hace | Dónde corre | Código principal |
|---|---|---|---|
| **Librería** | Con solo `import audit_tracer` intercepta pandas (cargas, transformaciones, exportaciones), registra cada evento en la base local, lo firma con Ed25519 y lo encola para sincronizar. | Equipo del usuario, con sus privilegios. **El usuario controla todo este entorno.** | `audit_tracer/data_capture.py`, `transform_capture.py`, `export_capture.py`, `session_tracker.py`, `digital_signatures.py`, `device_login.py` |
| **Canal de transmisión** | Envía cada evento a la central con reintentos, autenticado con el token personal; el login por dispositivo entrega ese token. | Internet | `audit_tracer/sync_client.py`, `app.py` (`_peticion_es_segura`) |
| **Servidor central** | Valida token, firma y campos; guarda el evento de forma idempotente en la base consolidada; publica la raíz Merkle de cada lote. | Railway, proceso `python app.py` | `app.py` (rutas `/api/*`, `/merkle/*`), `audit_tracer/db.py`, `models/`, `merkle.py`, `merkle_scheduler.py`, `schema/audit_log_central.sql` |
| **Dashboard** | Login, administración de usuarios y tokens, consulta y detalle de eventos, reportes CSV, linaje e integridad. | Mismo proceso Flask; se usa desde el navegador | `app.py`, `templates/`, `audit_tracer/auth/`, `event_explainer.py`, `lineage.py` |

### 3.3 Activos

| Activo | Por qué importa | Propiedad principal |
|---|---|---|
| Eventos de `audit_log` (local y central) | Son la evidencia de quién hizo qué con datos clínicos | Integridad, no repudio |
| Metadatos de los eventos (nombres de datasets, columnas, rutas) | Revelan qué datos de salud se tratan, aunque no incluyan valores | Confidencialidad |
| Tokens personales y device codes | Permiten enviar eventos y registrar llaves a nombre de un usuario | Confidencialidad |
| Llave privada Ed25519 de cada usuario | Respalda la autoría de sus eventos | Confidencialidad |
| Credenciales y cookie de sesión del dashboard | Dan acceso a la bitácora y a la administración | Confidencialidad, autenticidad |
| Raíces Merkle publicadas | Permiten detectar alteraciones de la central | Integridad |
| Disponibilidad de la central | Sin ella la bitácora consolidada no se puede consultar | Disponibilidad |

### 3.4 Actores de amenaza

| Actor | Descripción | Capacidad |
|---|---|---|
| **A1 · Científico de datos malintencionado** | Usuario legítimo que quiere ocultar o maquillar lo que hizo con los datos (el actor más relevante para un sistema de auditoría) | Control total de su entorno, token propio, rol `CIENTIFICO_DATOS` |
| **A2 · Atacante en la red** | Intercepta o manipula el tráfico entre el notebook y el servidor | Lectura y escritura en la red; sin credenciales |
| **A3 · Atacante con un token o un equipo robado** | Obtuvo el token cacheado, la carpeta de Drive o la llave de un usuario | Lo que permita ese token o esa llave |
| **A4 · Usuario del dashboard con rol bajo** | `ANALISTA` o `CIENTIFICO_DATOS` que intenta ver o hacer más de lo que su rol permite | Sesión válida en el dashboard |
| **A5 · Atacante externo en Internet** | Sin cuenta; ataca los endpoints públicos o engaña a usuarios legítimos (phishing, CSRF) | Peticiones HTTP, páginas web propias |
| **A6 · Administrador del servidor** | Acceso al sistema de archivos o a la base central | Lectura y escritura directa en SQLite y en `merkle_anchors/` |

### 3.5 Superficies de ataque

| Punto de entrada | Componente | Autenticación | Quién lo usa |
|---|---|---|---|
| Interceptores de pandas y `audit_tracer.login()` | Librería | Ninguna (corren en el proceso del usuario) | A1 |
| `audit_trail.db`, `~/.audit_tracer/` (token y llave) | Librería | Permisos del sistema de archivos del usuario | A1, A3 |
| `POST /api/eventos/sincronizar` | Canal / servidor | Bearer token; firma Ed25519 | Librería; A1, A2, A3, A5 |
| `POST /api/usuarios/llave-publica` | Servidor | Bearer token | Librería; A3 |
| `POST /api/auth/dispositivo/iniciar`, `GET /api/auth/dispositivo/estado` | Canal / servidor | Ninguna (el device_code es la credencial) | Librería; A5 |
| `POST /api/tokens/validar` | Servidor | Ninguna (requiere conocer el token) | Librería; A5 |
| `POST /login` | Dashboard | Correo y contraseña | Todos; A5 |
| Rutas del dashboard (`/eventos`, `/reportes`, `/linaje`, `/merkle/*`, `/admin/*`, `/auth/dispositivo`) | Dashboard | Cookie de sesión + rol | A4, A5 (vía CSRF o XSS) |
| `audit_central.db`, `merkle_anchors/` | Servidor | Acceso al servidor | A6 |

## 4. Metodología

Se aplicó **STRIDE por elemento**: para cada componente de la sección 3.2 se recorrieron las seis categorías y, para cada una, las superficies de la sección 3.5 y los actores de la 3.4.

| Categoría | Propiedad que viola | Pregunta guía |
|---|---|---|
| **Spoofing** | Autenticación | ¿Alguien puede hacerse pasar por otro usuario o por el servidor? |
| **Tampering** | Integridad | ¿Se puede alterar un evento, un mensaje o una configuración sin que se note? |
| **Repudiation** | No repudio | ¿Alguien puede negar una acción porque no quedó evidencia? |
| **Information Disclosure** | Confidencialidad | ¿Se pueden leer tokens, llaves o metadatos clínicos sin autorización? |
| **Denial of Service** | Disponibilidad | ¿Se puede impedir que los eventos se registren, lleguen o se consulten? |
| **Elevation of Privilege** | Autorización | ¿Alguien puede obtener más permisos de los que su rol le da? |

**Riesgo residual.** Se estima después de las mitigaciones implementadas combinando probabilidad (qué tan fácil es y qué actor lo puede hacer) e impacto (qué se pierde):

| | Impacto bajo | Impacto medio | Impacto alto |
|---|---|---|---|
| **Probabilidad alta** | Medio | Alto | Alto |
| **Probabilidad media** | Bajo | Medio | Alto |
| **Probabilidad baja** | Bajo | Bajo | Medio |

## 5. Resumen

**54 amenazas** en los cuatro componentes, con al menos una por categoría STRIDE en cada uno (CA1). Todas tienen al menos una mitigación implementada o planeada (CA2). Estado al 21/11/2026, después de ejecutar el plan de mitigación de la sección 8.

| Componente | S | T | R | I | D | E | Implementadas | Parciales | Planeadas |
|---|---|---|---|---|---|---|---|---|---|
| Librería | 2 | 3 | 2 | 2 | 2 | 2 | 7 | 5 | 1 |
| Canal de transmisión | 2 | 3 | 1 | 2 | 1 | 1 | 10 | 0 | 0 |
| Servidor central | 3 | 3 | 3 | 2 | 2 | 2 | 12 | 3 | 0 |
| Dashboard | 4 | 2 | 1 | 4 | 2 | 3 | 15 | 1 | 0 |
| **Total** | **11** | **11** | **7** | **10** | **7** | **8** | **44** | **9** | **1** |

| Riesgo residual | Amenazas |
|---|---|
| Alto | 0 |
| Medio | 8 |
| Bajo | 46 |

**Riesgos residuales altos:**

- Ninguna. El 21/11/2026 se ejecutó el plan de la sección 8: las siete amenazas de riesgo alto bajaron a medio o bajo (las de riesgo medio que quedan se listan en la sección 8).

## 6. Amenazas por componente

Cada fila indica la amenaza y su superficie, la mitigación (implementada, planeada o ambas), el estado con el riesgo residual, la HU y los controles de la [matriz HU-6.6](matriz_trazabilidad_normativa.md) que la respaldan (`CT-xx` controles, `Bx` brechas) y la prueba que lo demuestra.

### 6.1 Librería

La librería corre en un entorno que **controla el propio usuario auditado** (actor A1). Por eso ninguna mitigación local es definitiva: la defensa efectiva es que el evento salga del equipo firmado y llegue pronto a la central, donde el usuario ya no lo puede cambiar.

| ID | STRIDE | Amenaza | Mitigación | Estado · riesgo residual | HU · controles | Evidencia |
|---|---|---|---|---|---|---|
| LIB-S1 | Spoofing | Un científico de datos trabaja sin identificarse, o edita la identidad cacheada, para que sus acciones no se le atribuyan<br>*Superficie:* audit_tracer.login(); archivo de identidad en .audit_tracer/ | **Implementada:** Sin identidad válida cada evento queda como DESCONOCIDO con nivel CRITICO; desde el 21/11/2026 el servidor solo acepta eventos del dueño del token (o DESCONOCIDO) y registra como CRITICO cualquier otro (SRV-S1) | Implementada · Bajo | **HU-2.5, HU-5.7, HU-5.6**<br>CT-16, CT-07, CT-41 | `test_audit_log.py` → `test_usuario_no_identificado_se_marca_desconocido_y_critico`<br>`test_modelo_amenazas.py` → `test_mitigado_evento_a_nombre_de_otro_usuario_es_rechazado` |
| LIB-S2 | Spoofing | Robo del token personal cacheado para enviar eventos y registrar llaves a nombre de la víctima<br>*Superficie:* ~/.audit_tracer/ o /content/drive/MyDrive/.audit_tracer/ (carpeta de Google Drive que se puede compartir) | **Implementada:** Token de 256 bits que vence a los 30 días y se revoca de inmediato; el caché del token se crea con permisos 0600 y la librería advierte cuando queda en una carpeta de Google Drive<br>**Planeada:** Vincular el token a la llave del dispositivo (prueba de posesión) para que copiar el archivo no baste | Parcial · Medio | **HU-5.5, HU-5.7**<br>CT-06, CT-46 | `test_ataques_simulados.py` → `test_token_revocado_deja_de_funcionar_de_inmediato`<br>`test_robustez.py` → `test_el_token_cacheado_queda_con_permisos_de_solo_dueno` |
| LIB-T1 | Tampering | UPDATE o DELETE directo sobre la base local para cambiar o borrar un evento antes de que se sincronice<br>*Superficie:* audit_trail.db (SQLite local) | **Implementada:** Triggers que rechazan UPDATE y DELETE y dejan el intento en audit_intentos_bloqueados; hash SHA-256 por evento | Implementada · Bajo | **HU-3.3, HU-5.4**<br>CT-20, CT-21 | `test_ataques_simulados.py` → `test_update_directo_es_bloqueado_y_queda_registrado`<br>`test_ataques_simulados.py` → `test_delete_directo_es_bloqueado_y_queda_registrado` |
| LIB-T2 | Tampering | Con control total del equipo, el atacante borra los triggers, altera el evento, recalcula el hash y lo vuelve a firmar con la llave local<br>*Superficie:* audit_trail.db; llave privada local | **Implementada:** La firma detecta el cambio si el atacante no tiene la llave, que ahora se guarda cifrada (LIB-I2); la copia ya sincronizada vive en la central; Merkle y el sello RFC 3161 detectan cambios posteriores a la publicación del lote<br>**Planeada:** Comparar periódicamente la base local con la central por evento_uuid y hash_integridad; la alteración ANTES de sincronizar no es detectable en el servidor (B9) | Parcial · Medio | **HU-5.8, HU-6.1, HU-6.2**<br>CT-22, CT-23, CT-27, CT-46, B9 | `test_ataques_simulados.py` → `test_hash_recalculado_lo_detecta_la_firma_digital`<br>`test_modelo_amenazas.py` → `test_riesgo_abierto_evento_alterado_antes_de_sincronizar_es_detectado` |
| LIB-T3 | Tampering | Modificar el código de la librería instalada, o reasignar en memoria los métodos de pandas a sus originales, para que dejen de registrar sin pasar por la desactivación oficial<br>*Superficie:* site-packages/audit_tracer; pandas.read_csv y DataFrame.to_* en el proceso del notebook | **Implementada:** Desactivar la captura con la API oficial deja AUDITORIA_DESACTIVADA (CRITICO); el servidor muestra las sesiones de la librería que dejaron de reportar sin cerrarse<br>**Planeada:** Verificar la integridad del paquete (wheel firmado, instalación con hashes) | Parcial · Medio | **HU-5.1, HU-5.8**<br>CT-18, CT-45 | `test_integracion_automatica.py` → `test_desactivar_la_captura_queda_registrado_como_critico`<br>`test_robustez.py` → `test_lista_las_sesiones_de_la_libreria_que_dejaron_de_reportar` |
| LIB-R1 | Repudiation | El usuario niega haber cargado, transformado o exportado un dataset<br>*Superficie:* Eventos CARGA, CONSULTA, TRANSFORMACION y EXPORTACION | **Implementada:** Cada evento lleva usuario_id único, sesion_id, entorno y host, y la firma Ed25519 hecha con la llave del usuario | Implementada · Bajo | **HU-2.5, HU-3.2, HU-6.1**<br>CT-16, CT-17, CT-22 | `test_audit_log.py` → `test_usuario_autenticado_queda_asociado_al_evento`<br>`test_digital_signatures.py` → `test_evento_manipulado_tras_firma` |
| LIB-R2 | Repudiation | Leer o exportar datos por vías que la librería no intercepta (módulo csv, open(), polars, numpy, copiar al portapapeles) para que la acción no quede registrada<br>*Superficie:* Cualquier API de E/S distinta de pandas | **Implementada:** Se interceptan los lectores y exportadores de pandas (incluidos parquet, json, feather, pickle, sql y portapapeles), los de NumPy y polars, las consultas head/tail/groupby/describe/at/iat, la lectura con open() de un dataset ya cargado y el modelado con scikit-learn<br>**Planeada:** Documentar a los usuarios el alcance y complementarlo con la política de uso de la institución: un archivo leído por primera vez sin pandas, NumPy ni polars sigue sin registrarse | Parcial · Medio | **HU-2.1, HU-2.2, HU-2.3, HU-5.1**<br>CT-12, CT-13, CT-14, CT-39 | `test_integracion_automatica.py` → `test_flujo_sin_wraps_registra_todos_los_tipos_de_evento`<br>`test_captura_ampliada.py` → `test_read_parquet_y_read_json_son_carga`<br>`test_captura_ampliada.py` → `test_leer_con_open_un_dataset_ya_cargado_es_consulta`<br>`test_captura_ampliada.py` → `test_fit_y_predict_son_modelado` |
| LIB-I1 | Information Disclosure | La bitácora local revela metadatos sensibles (nombres de datasets, columnas como diagnóstico, rutas) a quien acceda al equipo o al entorno de Colab<br>*Superficie:* audit_trail.db; audit_sync_queue | **Implementada:** No se guardan valores clínicos, solo metadatos; la base local se crea con permisos de solo-dueño<br>**Planeada:** Cifrar la base local (SQLCipher) | Parcial · Bajo | **HU-2.1**<br>CT-46, B2 | `audit_tracer/schema/audit_log.sql`<br>`test_robustez.py` → `test_la_base_local_nueva_queda_con_permisos_de_solo_dueno` |
| LIB-I2 | Information Disclosure | Robo de la llave privada Ed25519, que se guarda sin cifrar, o uso de la llave versionada en el repositorio público<br>*Superficie:* ~/.audit_tracer/keys/private_key.pem; .audit_keys/private_key.pem del repositorio | **Implementada:** La llave privada se guarda cifrada con una frase del llavero del sistema operativo o de AUDIT_TRACER_KEY_PASSPHRASE y con permisos de solo-dueño; en Colab sin llavero queda sin cifrar salvo que se defina la frase. .audit_keys/ salió del repositorio; la llave que estuvo versionada se trata como comprometida | Implementada · Medio | **HU-6.1**<br>CT-22, CT-46, B4 | `test_robustez.py` → `test_con_frase_de_entorno_la_llave_queda_cifrada`<br>`test_robustez.py` → `test_con_llavero_la_frase_vive_en_el_llavero` |
| LIB-D1 | Denial of Service | Un fallo de la auditoría (base bloqueada, disco lleno, servidor caído) interrumpe o ralentiza el trabajo del analista y lo empuja a desactivarla<br>*Superficie:* Interceptores de pandas; sync_client | **Implementada:** Los errores internos se aíslan (guard) y van a un log separado; la red nunca corre en el hilo del usuario | Implementada · Bajo | **HU-5.1, HU-5.8**<br>CT-19 | `test_integracion_automatica.py` → `test_error_interno_no_interrumpe_pandas_y_va_al_log_de_errores`<br>`test_integracion_automatica.py` → `test_sincronizacion_nunca_hace_red_en_el_hilo_del_usuario` |
| LIB-D2 | Denial of Service | Borrar la base local (o dejar que muera el entorno efímero de Colab) antes de que los eventos pendientes lleguen a la central<br>*Superficie:* audit_trail.db; audit_sync_queue | **Implementada:** Cada evento se intenta sincronizar apenas se registra, con cola y reintentos; el servidor lista las sesiones con INICIO_SESION sin cierre ni eventos recientes | Implementada · Bajo | **HU-5.8**<br>CT-27, CT-45 | `test_sync_events.py` → `test_servidor_no_disponible_evento_permanece_pendiente_localmente`<br>`test_robustez.py` → `test_lista_las_sesiones_de_la_libreria_que_dejaron_de_reportar` |
| LIB-E1 | Elevation of Privilege | Usar el token personal de la librería, emitido a un CIENTIFICO_DATOS, para entrar al dashboard o a la administración<br>*Superficie:* Encabezado Authorization: Bearer contra las rutas del dashboard | **Implementada:** El token solo autentica la API de sincronización y de registro de llave; el dashboard exige sesión y valida la matriz de permisos en cada llamada | Implementada · Bajo | **HU-1.4, HU-5.5**<br>CT-09 | `test_modelo_amenazas.py` → `test_token_personal_no_abre_el_dashboard`<br>`test_ataques_simulados.py` → `test_sin_sesion_no_se_llega_a_la_administracion` |
| LIB-E2 | Elevation of Privilege | Una dependencia comprometida o un paquete con nombre parecido ejecuta código con los privilegios del notebook<br>*Superficie:* pip install; requirements.txt; pyproject.toml | **Planeada:** Fijar versiones con hashes (pip --require-hashes); publicar el paquete firmado; revisar dependencias en cada versión | Planeada · Medio | Sin HU aún | — |

### 6.2 Canal de transmisión

| ID | STRIDE | Amenaza | Mitigación | Estado · riesgo residual | HU · controles | Evidencia |
|---|---|---|---|---|---|---|
| CAN-S1 | Spoofing | Un servidor falso o un intermediario (api_url manipulada, DNS) recibe los eventos y el token<br>*Superficie:* Conexión librería → /api/eventos/sincronizar | **Implementada:** El cliente rechaza URLs que no sean HTTPS (salvo localhost) y requests valida el certificado del servidor | Implementada · Bajo | **HU-5.6, HU-5.8**<br>CT-24 | `test_sync_events.py` → `test_url_no_https_es_rechazada` |
| CAN-S2 | Spoofing | Phishing del código de dispositivo: el atacante inicia el login, le envía su código a la víctima y, si esta lo confirma, recibe un token a nombre de la víctima<br>*Superficie:* /api/auth/dispositivo/iniciar; /auth/dispositivo | **Implementada:** El código es de un solo uso, vence a los 10 minutos, exige sesión en el dashboard y deja CONFIRMACION_LOGIN_DISPOSITIVO; la página de confirmación muestra el equipo, la IP y la hora de quien lo pidió | Implementada · Bajo | **HU-5.7**<br>CT-07 | `test_device_login.py` → `test_confirmar_codigo_ya_confirmado_no_se_puede_reconfirmar`<br>`test_robustez.py` → `test_el_polling_por_post_entrega_el_token` |
| CAN-T1 | Tampering | Modificar un evento en tránsito<br>*Superficie:* Cuerpo JSON de /api/eventos/sincronizar | **Implementada:** TLS; la firma Ed25519 se verifica antes de guardar (HTTP 422 y FIRMA_INVALIDA si no coincide) | Implementada · Bajo | **HU-5.6, HU-6.1, HU-6.5**<br>CT-22, CT-24 | `test_ataques_simulados.py` → `test_evento_manipulado_despues_de_firmar_es_rechazado`<br>`test_ataques_simulados.py` → `test_evento_firmado_con_otra_llave_es_rechazado` |
| CAN-T2 | Tampering | Degradación: quitarle la firma a un evento manipulado para saltarse la verificación<br>*Superficie:* Campo firma_digital | **Implementada:** Si el usuario tiene llave registrada, todos sus eventos deben venir firmados; con AUDIT_EXIGIR_FIRMA=1 (activado en render.yaml) se exige firma a todos | Implementada · Bajo | **HU-6.5**<br>CT-22 | `test_ataques_simulados.py` → `test_quitar_la_firma_no_salta_la_verificacion`<br>`test_robustez.py` → `test_con_firma_obligatoria_se_rechaza_un_evento_sin_firma` |
| CAN-T3 | Tampering | Reenviar (replay) eventos válidos capturados para duplicarlos o inflar el registro<br>*Superficie:* /api/eventos/sincronizar | **Implementada:** Inserción idempotente por evento_uuid (UNIQUE en la central) | Implementada · Bajo | **HU-5.4, HU-5.6**<br>CT-26 | `test_ataques_simulados.py` → `test_reenviar_un_evento_valido_no_lo_duplica`<br>`test_central_db.py` → `test_evento_uuid_sigue_siendo_unico_bajo_concurrencia` |
| CAN-R1 | Repudiation | El emisor niega haber enviado un evento, o se alega que el servidor nunca lo recibió<br>*Superficie:* Sincronización librería → central | **Implementada:** El token identifica al emisor y la firma prueba el origen; el servidor responde con el event_id y el cliente solo marca SINCRONIZADO al recibir ese acuse | Implementada · Bajo | **HU-5.6, HU-5.8, HU-6.1**<br>CT-22, CT-25, CT-27 | `test_sync_events.py` → `test_token_valido_inserta_evento_y_responde_201`<br>`test_sync_events.py` → `test_envio_exitoso_marca_evento_sincronizado` |
| CAN-I1 | Information Disclosure | Capturar el token o los metadatos de los eventos en tránsito<br>*Superficie:* Red entre el notebook y el servidor | **Implementada:** HTTPS obligatorio en cliente y servidor (HTTP 426 fuera de localhost); el token viaja en el encabezado Authorization y no se escribe en los rechazos | Implementada · Bajo | **HU-5.6, HU-5.8**<br>CT-24, CT-25 | `test_sync_events.py` → `test_peticion_no_https_fuera_de_localhost_responde_426`<br>`test_sync_events.py` → `test_rechazo_por_token_invalido_queda_registrado_sin_exponer_el_token` |
| CAN-I2 | Information Disclosure | El device_code viaja en la query string del polling y queda en los logs de proxies; quien lo lea a tiempo puede recoger el token<br>*Superficie:* GET /api/auth/dispositivo/estado?device_code=… | **Implementada:** El device_code es largo, se guarda como SHA-256 y la librería lo consulta por POST en el cuerpo (no en la URL); el token se entrega una sola vez | Implementada · Bajo | **HU-5.7**<br>CT-07, CT-35 | `test_device_login.py` → `test_estado_confirmado_entrega_el_token_una_sola_vez`<br>`test_robustez.py` → `test_el_polling_por_post_entrega_el_token` |
| CAN-D1 | Denial of Service | Bloquear la red del notebook para que los eventos nunca lleguen a la central y nadie los revise<br>*Superficie:* Conexión saliente del notebook | **Implementada:** Cola local con reintentos: los eventos quedan PENDIENTE y se envían al recuperar la conexión; el panel de sincronización alerta de las sesiones que dejaron de reportar | Implementada · Bajo | **HU-5.8**<br>CT-27, CT-45 | `test_sync_events.py` → `test_recuperacion_de_conexion_sincroniza_evento_pendiente`<br>`test_robustez.py` → `test_el_panel_de_sincronizacion_las_muestra` |
| CAN-E1 | Elevation of Privilege | Falsificar encabezados de proxy (X-Forwarded-Proto: https) para que una petición HTTP pase como segura<br>*Superficie:* Encabezados X-Forwarded-* | **Implementada:** ProxyFix solo se activa con TRUST_PROXY_HEADERS=1; sin esa variable los encabezados se ignoran | Implementada · Bajo | **HU-5.6**<br>CT-24 | `test_modelo_amenazas.py` → `test_x_forwarded_proto_falsificado_no_salta_el_https`<br>`test_sync_events.py` → `test_peticion_no_https_se_rechaza_incluso_sin_token` |

### 6.3 Servidor central

| ID | STRIDE | Amenaza | Mitigación | Estado · riesgo residual | HU · controles | Evidencia |
|---|---|---|---|---|---|---|
| SRV-S1 | Spoofing | Un usuario con token válido envía eventos con el usuario_id de otra persona, incluso firmados con su propia llave, y el servidor los guarda a nombre de la víctima<br>*Superficie:* Campo usuario_id de /api/eventos/sincronizar | **Implementada:** El servidor rechaza con 403 todo evento cuyo usuario_id no sea el dueño del token (salvo DESCONOCIDO) y lo registra como SINCRONIZACION_RECHAZADA CRITICO | Implementada · Bajo | **HU-5.6, HU-6.1**<br>CT-22, CT-25, CT-41 | `test_modelo_amenazas.py` → `test_mitigado_evento_a_nombre_de_otro_usuario_es_rechazado`<br>`test_modelo_amenazas.py` → `test_mitigado_eventos_desconocidos_del_mismo_equipo_se_aceptan` |
| SRV-S2 | Spoofing | Con un token robado, el atacante reemplaza la llave pública de la víctima y luego firma eventos que el servidor acepta como suyos; el cambio no deja rastro<br>*Superficie:* POST /api/usuarios/llave-publica | **Implementada:** Las llaves se acumulan en un historial: cada llave nueva deja REGISTRO_LLAVE_PUBLICA (ADVERTENCIA si el usuario ya tenía otra, lo que dispara el aviso de equipo nuevo) y un ADMIN puede revocarla; una llave revocada no acepta eventos ni se puede volver a registrar<br>**Planeada:** Exigir confirmación desde el dashboard para registrar una llave adicional con un token que no se acaba de confirmar | Parcial · Medio | **HU-6.1**<br>CT-22, CT-40 | `test_modelo_amenazas.py` → `test_mitigado_cambio_de_llave_publica_queda_registrado`<br>`test_modelo_amenazas.py` → `test_mitigado_llave_revocada_no_acepta_eventos_nuevos` |
| SRV-S3 | Spoofing | Adivinar o forzar un token personal<br>*Superficie:* /api/eventos/sincronizar; /api/tokens/validar | **Implementada:** Tokens de 256 bits generados con secrets; los tokens alterados o inventados se rechazan y el rechazo se registra | Implementada · Bajo | **HU-5.5, HU-6.5**<br>CT-06, CT-25 | `test_tokens.py` → `test_generar_token_seguro_formato`<br>`test_ataques_simulados.py` → `test_token_falso_o_ausente_es_rechazado` |
| SRV-T1 | Tampering | UPDATE o DELETE sobre audit_log de la base central<br>*Superficie:* audit_central.db | **Implementada:** Triggers de inmutabilidad que rechazan y registran el intento | Implementada · Bajo | **HU-5.4**<br>CT-21 | `test_central_db.py` → `test_bloquea_update`<br>`test_central_db.py` → `test_bloquea_delete`<br>`test_central_db.py` → `test_intento_de_update_queda_registrado` |
| SRV-T2 | Tampering | Quien administra el servidor borra los triggers y altera o elimina eventos de la central, y también reescribe los anclajes Merkle<br>*Superficie:* audit_central.db; directorio merkle_anchors/ | **Implementada:** verify_integrity detecta alteraciones; Merkle detecta modificaciones y eliminaciones posteriores a la publicación del lote; con AUDIT_TSA_URL cada raíz lleva un sello de tiempo RFC 3161 de una autoridad externa que el administrador no puede rehacer | Implementada · Bajo | **HU-3.3, HU-6.2**<br>CT-20, CT-23, CT-42 | `test_merkle.py` → `test_detecta_modificacion_de_evento_en_bd`<br>`test_robustez.py` → `test_el_ancla_de_merkle_lleva_sello_y_lo_verifica` |
| SRV-T3 | Tampering | El cliente decide nivel_alerta y timestamp y el servidor los acepta: un usuario puede enviar una exportación de 50 000 filas como NORMAL o fechar el evento en el pasado; la firma no lo impide porque la hace el mismo usuario<br>*Superficie:* Campos nivel_alerta, motivo_alerta y timestamp de /api/eventos/sincronizar | **Implementada:** El servidor recalcula la criticidad (umbral de 1000 filas, horario laboral, DESCONOCIDO, timestamp en el futuro o muy atrasado) y guarda su propia fecha de recepción; un evento firmado con un nivel menor se conserva intacto y el servidor agrega RECLASIFICACION_SERVIDOR | Implementada · Bajo | **HU-4.4, HU-5.6**<br>CT-14, CT-28, CT-41 | `test_modelo_amenazas.py` → `test_mitigado_servidor_reclasifica_exportacion_masiva`<br>`test_modelo_amenazas.py` → `test_mitigado_evento_firmado_subclasificado_genera_reclasificacion`<br>`test_modelo_amenazas.py` → `test_mitigado_timestamp_en_el_futuro_se_marca` |
| SRV-R1 | Repudiation | Un ADMIN niega haber creado un usuario, cambiado un rol o emitido o revocado un token<br>*Superficie:* /admin/usuarios/*; /admin/tokens/*; /api/tokens/revocar | **Implementada:** Quedan CREACION_USUARIO, MODIFICACION_ROL, GENERACION_TOKEN y REVOCACION_TOKEN con el administrador que actuó | Implementada · Bajo | **HU-1.1, HU-1.2, HU-5.5**<br>CT-06, CT-10 | `test_registro.py` → `test_register_user_success`<br>`test_tokens.py` → `test_generacion_token_registra_evento_en_audit_log`<br>`test_tokens.py` → `test_revocar_token_registra_evento_en_audit_log` |
| SRV-R2 | Repudiation | Al cambiar la llave pública, las firmas de los eventos anteriores dejan de verificarse (la vista usa la llave actual) y el usuario puede alegar que esos eventos no son válidos<br>*Superficie:* usuarios.llave_publica; /eventos/<id> | **Implementada:** Historial de llaves con su vigencia: cada evento se verifica con las llaves vigentes cuando llegó, así una llave nueva no invalida las firmas anteriores; el hash y la prueba Merkle siguen demostrando que el evento no cambió | Implementada · Bajo | **HU-6.1, HU-6.2**<br>CT-22, CT-23, CT-40 | `test_modelo_amenazas.py` → `test_mitigado_firmas_anteriores_siguen_verificandose_tras_otra_llave`<br>`test_merkle.py` → `test_generar_y_verificar_prueba_valida` |
| SRV-R3 | Repudiation | Un rol no autorizado intenta publicar anclajes Merkle y el rechazo no queda registrado<br>*Superficie:* POST /merkle/publicar | **Implementada:** El endpoint responde 403 a roles distintos de ADMIN y AUDITOR y registra el rechazo como ACCESO_DENEGADO | Implementada · Bajo | **HU-6.2**<br>CT-11 | `test_merkle.py` → `test_endpoint_publicar_restringido_a_roles_autorizados`<br>`test_robustez.py` → `test_publicar_merkle_sin_permiso_queda_registrado` |
| SRV-I1 | Information Disclosure | Quien obtiene una copia de la base central lee los tokens personales en claro y los metadatos sin cifrar<br>*Superficie:* audit_central.db (tablas tokens_acceso, device_codes y audit_log) | **Implementada:** Las contraseñas se guardan con bcrypt; los tokens y los device codes solo como SHA-256; la base no guarda valores clínicos y se crea con permisos de solo-dueño<br>**Planeada:** Cifrar el volumen del servidor (LUKS, BitLocker) o usar SQLCipher (B2) | Parcial · Bajo | **HU-1.1, HU-5.5**<br>CT-01, CT-35, B2 | `test_robustez.py` → `test_presentar_el_hash_leido_de_la_base_no_autentica`<br>`test_device_login.py` → `test_el_device_code_se_guarda_como_hash` |
| SRV-I2 | Information Disclosure | Mensajes de error y modo de depuración revelan detalles internos: /login muestra el texto de la excepción, la API devuelve el error de SQLite y FLASK_DEBUG vale 1 por defecto con el Procfile actual (python app.py)<br>*Superficie:* app.py (login_post; api_sincronizar_evento; bloque __main__); Procfile | **Implementada:** FLASK_DEBUG vale 0 por defecto; el despliegue usa Gunicorn (wsgi.py, Procfile, render.yaml); el usuario ve mensajes genéricos y el detalle queda en el log del servidor | Implementada · Bajo | **HU-6.4**<br>CT-44 | `test_robustez.py` → `test_un_error_interno_no_muestra_el_detalle`<br>`test_robustez.py` → `test_la_depuracion_esta_apagada_por_defecto` |
| SRV-D1 | Denial of Service | Inundar /api/eventos/sincronizar o /api/auth/dispositivo/iniciar (sin autenticación) o enviar cuerpos enormes; cada rechazo escribe además una fila en audit_log (amplificación)<br>*Superficie:* Endpoints públicos de la API | **Implementada:** Límite de peticiones por IP y por token en login, sincronización, registro de llave y login por código; MAX_CONTENT_LENGTH de 2 MB; los códigos de dispositivo vencidos se purgan; los rechazos por HTTPS y por token ocurren antes de procesar el evento | Implementada · Bajo | **HU-5.6, HU-5.7**<br>CT-24, CT-25, CT-44 | `test_modelo_amenazas.py` → `test_mitigado_el_servidor_limita_el_tamano_de_la_peticion`<br>`test_robustez.py` → `test_demasiados_intentos_de_login_responden_429`<br>`test_robustez.py` → `test_los_codigos_vencidos_se_purgan` |
| SRV-D2 | Denial of Service | La central es un único archivo SQLite servido por el servidor de desarrollo de Flask: una caída o la pérdida del disco deja sin la bitácora consolidada<br>*Superficie:* audit_central.db; proceso app.py | **Implementada:** La copia local y la cola conservan los eventos que no llegaron a la central; el servidor se sirve con Gunicorn<br>**Planeada:** Respaldos periódicos verificados de la base central y evaluar PostgreSQL si hay varios escritores | Parcial · Medio | **HU-5.4, HU-5.8**<br>CT-27, CT-44 | `test_sync_events.py` → `test_servidor_no_disponible_evento_permanece_pendiente_localmente` |
| SRV-E1 | Elevation of Privilege | Inyección SQL o asignación masiva desde el JSON del evento (enviar hash_integridad, event_id o columnas que no existen)<br>*Superficie:* Cuerpo de /api/eventos/sincronizar | **Implementada:** Consultas parametrizadas; solo se aceptan los campos de _CAMPOS_EVENTO_ACEPTADOS; el hash se recalcula en el servidor | Implementada · Bajo | **HU-5.6**<br>CT-20 | `test_modelo_amenazas.py` → `test_payload_no_puede_fijar_hash_ni_event_id`<br>`test_modelo_amenazas.py` → `test_inyeccion_sql_en_el_payload_se_guarda_como_texto` |
| SRV-E2 | Elevation of Privilege | Usar un token de bajo privilegio contra endpoints administrativos de la API<br>*Superficie:* POST /api/tokens/revocar | **Implementada:** El endpoint exige una sesión de ADMIN; el token Bearer no sirve | Implementada · Bajo | **HU-1.4, HU-5.5**<br>CT-09 | `test_modelo_amenazas.py` → `test_revocar_token_por_api_exige_sesion_admin` |

### 6.4 Dashboard

| ID | STRIDE | Amenaza | Mitigación | Estado · riesgo residual | HU · controles | Evidencia |
|---|---|---|---|---|---|---|
| DSH-S1 | Spoofing | Fuerza bruta o relleno de credenciales contra el login<br>*Superficie:* POST /login | **Implementada:** bcrypt con sal; política de contraseñas en register_user() para cualquier origen; bloqueo temporal tras 5 intentos; mensaje genérico; ADVERTENCIA y CRITICO por intentos repetidos; límite de intentos por IP | Implementada · Bajo | **HU-1.1, HU-1.3, HU-4.4**<br>CT-01, CT-03, CT-04, CT-05, CT-33 | `test_autenticacion.py` → `test_login_invalid_credentials`<br>`test_robustez.py` → `test_register_user_rechaza_contrasenas_debiles` |
| DSH-S2 | Spoofing | Forjar una cookie de sesión con rol=ADMIN<br>*Superficie:* Cookie session de Flask | **Implementada:** La clave de firma se toma de SECRET_KEY o se genera al azar por proceso; ya no está en el código | Implementada · Bajo | **HU-6.5**<br>CT-08 | `test_ataques_simulados.py` → `test_cookie_de_sesion_forjada_con_la_clave_antigua_no_da_acceso` |
| DSH-S3 | Spoofing | Robo o reutilización de la sesión: la cookie no se marca Secure ni SameSite, y la sesión no vence por inactividad<br>*Superficie:* Cookie session; configuración de Flask | **Implementada:** Cookie Secure, HttpOnly y SameSite=Lax; la sesión vence a la hora y se cierra tras 15 minutos de inactividad | Implementada · Bajo | **HU-1.3**<br>CT-08, CT-36 | `test_modelo_amenazas.py` → `test_mitigado_cookie_de_sesion_es_secure_y_samesite`<br>`test_modelo_amenazas.py` → `test_mitigado_sesion_inactiva_se_cierra` |
| DSH-S4 | Spoofing | Redirección abierta después del login (next=//sitio-falso o /\sitio-falso) para hacer phishing con el dominio legítimo<br>*Superficie:* Parámetro next de /login | **Implementada:** Solo se aceptan rutas relativas propias y Werkzeug escapa la barra invertida | Implementada · Bajo | **HU-5.7** | `test_modelo_amenazas.py` → `test_next_externo_no_redirige_fuera_del_dashboard` |
| DSH-T1 | Tampering | CSRF: una página externa hace que un ADMIN con sesión abierta envíe formularios (crear usuario, cambiar rol, emitir o revocar tokens, confirmar un código de dispositivo)<br>*Superficie:* Todos los formularios POST del dashboard | **Implementada:** Todo POST con la cookie del dashboard exige el token CSRF de la sesión; el rechazo queda como ACCESO_DENEGADO; la cookie es SameSite=Lax | Implementada · Bajo | **HU-1.2, HU-5.5, HU-5.7**<br>CT-10, CT-37 | `test_modelo_amenazas.py` → `test_mitigado_post_sin_token_csrf_es_rechazado` |
| DSH-T2 | Tampering | Alterar un reporte CSV después de descargarlo y presentarlo como evidencia<br>*Superficie:* /reportes/exportar; /eventos/criticos/exportar | **Implementada:** El reporte y el CSV de eventos críticos incluyen hash_integridad; cada descarga deja su SHA-256 en audit_log y en la cabecera X-Contenido-SHA256 | Implementada · Bajo | **HU-4.4, HU-6.2**<br>CT-23, CT-30, CT-38 | `test_merkle.py` → `test_endpoint_verificar_evento_individual`<br>`test_modelo_amenazas.py` → `test_mitigado_descarga_de_reporte_queda_registrada` |
| DSH-R1 | Repudiation | Un usuario del dashboard consulta eventos o descarga reportes y luego lo niega: esas lecturas no se registran, solo los accesos denegados<br>*Superficie:* /eventos; /eventos/<id>; /reportes/exportar; /eventos/criticos/exportar; /linaje | **Implementada:** Se registran los accesos denegados por rol y, desde el 21/11/2026, las consultas (una vez por minuto por vista y filtros) y todas las descargas de la bitácora | Implementada · Bajo | **HU-1.4, HU-4.5**<br>CT-11, CT-38 | `test_modelo_amenazas.py` → `test_mitigado_descarga_de_reporte_queda_registrada`<br>`test_modelo_amenazas.py` → `test_mitigado_consulta_de_la_bitacora_queda_registrada_una_vez_por_minuto` |
| DSH-I1 | Information Disclosure | XSS almacenado: la librería controla dataset_nombre, columnas, ruta y motivo; el detalle de evento (HU-7.4) los mostraba sin escapar con \| safe y ese código corría en el navegador del auditor. Cerrado el 08/11/2026 (commit 3d7dc2b)<br>*Superficie:* audit_tracer/event_explainer.py (explicación narrativa); templates/dashboard/detalle_evento.html; resto de plantillas | **Implementada:** Autoescape de Jinja en todas las plantillas, incluido el detalle de evento (ya sin \| safe); tojson para los datos que van a JavaScript; Cytoscape dibuja las etiquetas como texto en canvas | Implementada · Bajo | **HU-4.1, HU-4.3, HU-7.1, HU-7.4** | `test_modelo_amenazas.py` → `test_datos_del_evento_se_escapan_en_listados_y_reportes`<br>`test_modelo_amenazas.py` → `test_mitigado_detalle_de_evento_escapa_los_datos_de_la_libreria` |
| DSH-I2 | Information Disclosure | Inyección de fórmulas en los CSV exportados: un dataset_nombre como =HYPERLINK(...) se ejecuta cuando el auditor abre el reporte en Excel<br>*Superficie:* /reportes/exportar; /eventos/criticos/exportar | **Implementada:** Las celdas que empiezan con =, +, -, @, tabulación o retorno de carro se exportan con un apóstrofo inicial | Implementada · Bajo | **HU-4.4, HU-4.5, HU-7.3**<br>CT-30 | `test_modelo_amenazas.py` → `test_mitigado_csv_neutraliza_formulas` |
| DSH-I3 | Information Disclosure | El token personal (30 días) se guardaba en la cookie de sesión, que Flask firma pero no cifra. Cerrado el 08/11/2026 (commit 3d7dc2b): la sesión guarda solo token_id<br>*Superficie:* session['token_id'] en login_post | **Implementada:** login_post guarda en la sesión solo el token_id; el token no sale del servidor | Implementada · Bajo | **HU-5.5**<br>CT-06 | `test_modelo_amenazas.py` → `test_mitigado_token_personal_no_viaja_en_la_cookie` |
| DSH-I4 | Information Disclosure | Un rol que no lo necesita consulta la bitácora (mínimo necesario)<br>*Superficie:* Módulo consulta_reportes | **Implementada:** Matriz de permisos rol × módulo validada en cada llamada | Implementada · Bajo | **HU-1.4**<br>CT-09 | `test_ataques_simulados.py` → `test_cientifico_de_datos_no_puede_consultar_eventos` |
| DSH-D1 | Denial of Service | Bloquear cuentas ajenas: 5 contraseñas erróneas bloquean a cualquier usuario cuyo correo se conozca, y no hay desbloqueo desde la aplicación<br>*Superficie:* POST /login | **Implementada:** El bloqueo dura 15 minutos y un ADMIN puede levantarlo antes (DESBLOQUEO_CUENTA); el login tiene límite de intentos por IP | Implementada · Bajo | **HU-1.3**<br>CT-04, CT-05, CT-34, CT-44 | `test_robustez.py` → `test_el_bloqueo_es_temporal_y_se_levanta_solo`<br>`test_robustez.py` → `test_el_admin_desbloquea_y_queda_registrado` |
| DSH-D2 | Denial of Service | Páginas que cargan todo audit_log sin paginar (/dashboard, /reportes) y /verificar-integridad, que cualquier usuario con sesión puede lanzar y recorre todos los eventos<br>*Superficie:* /dashboard; /reportes; POST /verificar-integridad | **Implementada:** La verificación de un evento puntual usa la prueba Merkle en O(log n); la verificación completa solo la pueden lanzar ADMIN y AUDITOR<br>**Planeada:** Paginar en la base (LIMIT/OFFSET) y ejecutar la verificación completa en segundo plano | Parcial · Bajo | **HU-6.2**<br>CT-23 | `test_merkle.py` → `test_endpoint_verificar_evento_individual`<br>`test_robustez.py` → `test_verificacion_completa_solo_admin_o_auditor` |
| DSH-E1 | Elevation of Privilege | Un rol bajo entra a la administración, se crea un ADMIN o emite tokens ajenos<br>*Superficie:* /admin/* | **Implementada:** login_required, admin_required y modulo_required en cada ruta; el intento queda como ACCESO_DENEGADO | Implementada · Bajo | **HU-1.2, HU-1.4, HU-6.5**<br>CT-09, CT-10, CT-11 | `test_ataques_simulados.py` → `test_analista_no_puede_crearse_un_usuario_admin`<br>`test_ataques_simulados.py` → `test_analista_no_puede_generar_tokens_para_otro_usuario`<br>`test_control_acceso.py` → `test_role_check_is_per_call_not_once` |
| DSH-E2 | Elevation of Privilege | El rol y el estado de la cuenta se leen de la cookie y no de la base: después de degradar el rol o bloquear la cuenta, la sesión abierta conserva sus privilegios<br>*Superficie:* session['rol'] | **Implementada:** El rol y el estado de la cuenta se releen de la base en cada petición: degradar el rol o bloquear la cuenta surte efecto en la sesión abierta | Implementada · Bajo | **HU-1.2, HU-1.4**<br>CT-09, CT-10, CT-36 | `test_modelo_amenazas.py` → `test_mitigado_rol_degradado_pierde_privilegios_en_la_sesion_activa` |
| DSH-E3 | Elevation of Privilege | Cadena de ataque: un CIENTIFICO_DATOS sincroniza un evento con un dataset_nombre que contiene JavaScript (DSH-I1); cuando un ADMIN abre el detalle, el script envía formularios de administración con la sesión del ADMIN, sin CSRF que lo impida (DSH-T1), y crea una cuenta ADMIN<br>*Superficie:* /eventos/<id> + formularios POST de /admin/* | **Implementada:** La cadena está rota en sus tres eslabones: el detalle escapa los datos de la librería (DSH-I1), los formularios exigen token CSRF (DSH-T1) y la CSP bloquea scripts y conexiones a otros sitios | Implementada · Bajo | **HU-7.4, HU-1.2**<br>CT-10, CT-37 | `test_modelo_amenazas.py` → `test_mitigado_detalle_de_evento_escapa_los_datos_de_la_libreria`<br>`test_modelo_amenazas.py` → `test_mitigado_post_sin_token_csrf_es_rechazado`<br>`test_modelo_amenazas.py` → `test_mitigado_las_paginas_traen_cabeceras_de_seguridad` |

## 7. Hallazgos confirmados durante el análisis

Estos riesgos no estaban documentados en HU-6.5 ni en HU-6.6. Se confirmaron ejecutando el ataque contra el sistema y cada uno quedó como prueba `xfail` en `TestRiesgosAbiertos`. El 21/11/2026 se cerraron todos: sus pruebas pasaron a `TestMitigacionesDelPlan`, que repite el mismo ataque y comprueba que ahora se bloquea o queda registrado.

1. **[Cerrado el 21/11/2026] Eventos a nombre de otro usuario (SRV-S1).** `/api/eventos/sincronizar` valida el token pero guarda el `usuario_id` que trae el evento. Con su propio token, un usuario registró una exportación a nombre de otro y el servidor respondió 201. Si además firma con su llave, el evento se acepta igual: la firma se verifica con la llave del dueño del token, no con la del usuario que el evento dice ser.
2. **[Mitigado el 21/11/2026: ya no es silencioso, queda registrado y se puede revocar] Reemplazo silencioso de la llave pública (SRV-S2, SRV-R2).** Cualquier token vigente puede reemplazar la llave del usuario, cuantas veces quiera, sin que quede un evento. Con un token robado, el atacante registra su llave y firma eventos que el servidor acepta. Además, las firmas de los eventos anteriores dejan de verificarse en la vista de detalle.
3. **[Cerrado el 21/11/2026] Clasificación decidida por el cliente (SRV-T3).** Una exportación de 50 000 filas enviada como `NORMAL` y con fecha de 2020 se guardó así. El umbral de exportación masiva (HU-2.3) solo se aplica en la librería, que controla el usuario.
4. **[Cerrado el 08/11/2026, commit `3d7dc2b`] XSS almacenado en el detalle de evento (DSH-I1, DSH-E3).** La explicación narrativa de HU-7.4 (`event_explainer.py`) interpola `dataset_nombre`, `ruta_destino` y `motivo_fallo` en HTML que la plantilla pinta con `| safe`. Un `dataset_nombre` con `<script>` se ejecuta en el navegador de quien abra el evento. Como el dashboard no tiene protección CSRF (DSH-T1), ese script puede usar la sesión de un ADMIN para crear otra cuenta ADMIN.
5. **[Cerrado el 08/11/2026, commit `3d7dc2b`] Token personal legible en la cookie (DSH-I3).** El login guarda el token de 30 días en la sesión de Flask, que está firmada pero no cifrada; se lee decodificando la cookie en base64. El dashboard no lo usa.
6. **[Cerrado el 21/11/2026] Rol cacheado en la sesión (DSH-E2).** Después de degradar a un ANALISTA a CIENTIFICO_DATOS, su sesión abierta siguió consultando `/eventos` (200).
7. **[Cerrado el 21/11/2026] Configuración de sesión y peticiones (DSH-S3, DSH-T1, SRV-D1).** La cookie no se marca `Secure` ni `SameSite`, no hay tokens CSRF y no hay límite de tamaño de petición (`MAX_CONTENT_LENGTH`).
8. **[Cerrado el 21/11/2026] Bloqueo de cuentas ajenas (DSH-D1).** Cinco contraseñas erróneas enviadas por cualquiera bloquean la cuenta del dueño del correo. Es efecto de la mitigación contra fuerza bruta (CT-04) y, sin desbloqueo en la aplicación (B6), deja al usuario fuera hasta que alguien edite la base.
9. **[Cerrado el 21/11/2026] Modo de depuración por defecto (SRV-I2).** `app.py` activa `debug=True` salvo que `FLASK_DEBUG` valga distinto de `1`, y el `Procfile` arranca con `python app.py`. Hay que confirmar que el despliegue define `FLASK_DEBUG=0`: con depuración activa, cualquier error muestra el traceback y habilita el depurador de Werkzeug.

**Hallazgo funcional (no de seguridad), cerrado el 09/11/2026.** `POST /admin/usuarios/nuevo` creaba el usuario pero respondía HTTP 500; desde el commit `cfbdddd` redirige al listado.

**Lo que se probó y no resultó vulnerable:**

- La redirección abierta con `next=/\sitio-falso`: Werkzeug escapa la barra invertida.
- La inyección SQL desde el JSON del evento.
- La asignación masiva de `hash_integridad` o `event_id`.
- La falsificación de `X-Forwarded-Proto`.
- El uso del token Bearer en el dashboard.

Quedaron como pruebas en `TestMitigacionesVerificadas`.

## 8. Plan de mitigación priorizado

Las medidas se agrupan por esfuerzo y en orden de prioridad. Cada una cierra o reduce las amenazas indicadas.

| Prioridad | Medida | Amenazas | Esfuerzo | Estado al 21/11/2026 |
|---|---|---|---|---|
| 1 | Agregar una cabecera `Content-Security-Policy` (el escapado ya está hecho) | DSH-E3 | Bajo | Hecha (CT-37) |
| 2 | En `/api/eventos/sincronizar`, rechazar con 403 (y registrar como CRITICO) los eventos cuyo `usuario_id` no sea el dueño del token | SRV-S1, LIB-S1 | Bajo | Hecha (CT-41) |
| 3 | Registrar la llave pública solo una vez (o con confirmación desde el dashboard), dejar el cambio en `audit_log` y guardar el historial de llaves con vigencia | SRV-S2, SRV-R2 | Medio | Parcial: historial, registro y revocación (CT-40); falta la confirmación desde el dashboard |
| 4 | Protección CSRF en todos los formularios y cookie `Secure` + `SameSite=Lax` con vencimiento por inactividad | DSH-T1, DSH-S3, DSH-E3 | Bajo | Hecha (CT-36, CT-37) |
| 5 | `FLASK_DEBUG=0` por defecto, servidor WSGI y mensajes de error genéricos | SRV-I2, SRV-D2 | Bajo | Hecha (CT-44) |
| 6 | Guardar tokens y device codes como SHA-256 | SRV-I1 | Medio | Hecha (CT-35) |
| 7 | Recalcular en el servidor el nivel de alerta y guardar la fecha de recepción | SRV-T3 | Medio | Hecha (CT-41) |
| 8 | Recargar el rol y el estado de la cuenta en cada petición; bloqueo temporal y desbloqueo por ADMIN | DSH-E2, DSH-D1 | Medio | Hecha (CT-34, CT-36) |
| 9 | Retirar `.audit_keys/` del repositorio; cifrar la llave local o guardarla en el llavero del sistema | LIB-I2 | Bajo | Hecha (CT-46; la llave versionada sigue en el historial de Git) |
| 10 | Neutralizar fórmulas en los CSV y registrar las consultas y descargas del dashboard | DSH-I2, DSH-R1 | Bajo | Hecha (CT-30, CT-38) |
| 11 | Límite de peticiones y de tamaño en la API; polling del device code por POST | SRV-D1, CAN-I2 | Medio | Hecha (CT-44) |
| 12 | Publicar las raíces Merkle en un medio externo (sello de tiempo RFC 3161 o WORM) y comparar periódicamente local contra central | SRV-T2, LIB-T2 | Alto | Hecha para el sello RFC 3161 (CT-42); falta la comparación periódica local contra central |
| 13 | Ampliar los interceptores y alertar de sesiones sin sincronizar | LIB-R2, LIB-T3, LIB-D2, CAN-D1 | Alto | Hecha en buena parte (CT-39, CT-45); queda lo que se lee sin pandas, NumPy ni polars |

Las medidas 1 a 13 se ejecutaron el 21/11/2026 (salvo lo indicado en la columna de estado). Lo que queda abierto está en las filas PARCIAL y PLANEADA de la sección 6: firma del paquete (LIB-E2), confirmación de llaves nuevas desde el dashboard (SRV-S2), prueba de posesión del token (LIB-S2), cifrado de las bases en reposo (B2) y la alteración de eventos en el equipo antes de sincronizarlos (B9).

## 9. Revisión del equipo

La DoD exige que el equipo revise el modelo. Cada integrante verifica que las amenazas de los componentes que construyó estén completas, que las mitigaciones citadas sean las correctas y que conozca los riesgos abiertos.

| Integrante | Componentes revisados | Fecha | Aprobado / Observaciones |
|---|---|---|---|
| Valentina Gómez Rivera | | | |
| Alexis Delgado Abril | | | |
| Juan Pablo Ordoñez | | | |

La firma de esta tabla la hace cada integrante: no se puede llenar en su nombre. En la segunda ronda (21/11/2026) cambiaron 33 filas de la sección 6; conviene revisar sobre todo las que pasaron a IMPLEMENTADA y su evidencia.

## 10. Mantenimiento del modelo

- La fuente para máquinas es [`modelo_amenazas_stride.csv`](modelo_amenazas_stride.csv), con UTF-8 y comas; los valores de una misma celda se separan con `;`. Si se agrega o cambia una amenaza, hay que actualizar el CSV y este anexo en el mismo cambio; `TestDocumento` lo verifica.
- Al implementar una mitigación planeada, su prueba de `TestRiesgosAbiertos` empezará a pasar y la suite fallará por `XPASS`. En ese momento hay que quitar el `xfail`, mover la prueba a `TestMitigacionesDelPlan`, cambiar el estado de la amenaza y actualizar el riesgo residual (así se hizo con los nueve riesgos abiertos el 21/11/2026).
- El modelo se debe revisar cada vez que se agregue un componente, un endpoint o un tipo de usuario.
