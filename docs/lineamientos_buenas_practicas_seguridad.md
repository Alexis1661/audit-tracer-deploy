# Lineamientos y Buenas Prácticas para el Uso Seguro del Sistema Audit Tracer

| | |
|---|---|
| **Sistema** | Audit Tracer — Trazabilidad y Auditoría de Datos Clínicos Sensibles |
| **Documento** | Lineamientos, Políticas y Buenas Prácticas de Seguridad de la Información |
| **Fecha de emisión** | Noviembre 2026 |
| **Normativas asociadas** | Ley Estatutaria 1581 de 2012 (Colombia) · HIPAA 45 CFR Parte 164 · ISO/IEC 27001:2022 |
| **Audiencia** | Científicos de datos, ingenieros de machine learning, analistas clínicos, administradores del sistema y oficiales de cumplimiento |

---

## 1. Propósito, Alcance y Justificación

### 1.1. Propósito
El propósito de este documento es establecer lineamientos formales, directrices operativas y buenas prácticas obligatorias para el uso seguro de la plataforma **Audit Tracer**. Estas directrices abarcan el ciclo de vida completo de los datos clínicos sensibles (recolección, procesamiento, almacenamiento, exportación y auditoría), asegurando la integridad, confidencialidad, disponibilidad y no repudio de la información médica.

### 1.2. Alcance
Aplica a todos los usuarios, procesos y componentes técnicos que interactúen con el ecosistema de Audit Tracer:
1. **Entornos de Ciencia de Datos:** Jupyter Notebooks, Google Colab, scripts en Python, pipelines ETL y entornos de modelado estadístico/ML.
2. **Infraestructura Central:** API REST de ingesta, base de datos central inmutable SQLite WAL, motor de detección de anomalías y dashboard administrativo.
3. **Roles Operativos:** Investigadores, analistas de datos, personal médico-administrativo, administradores de infraestructura y auditores/oficiales de cumplimiento.

### 1.3. Rol de Audit Tracer frente a los datos clínicos
> [!IMPORTANT]
> **Audit Tracer no es una base de datos de historias clínicas.**
> Su propósito es constituir una capa de **gobernanza, auditoría no invasiva y no repudio criptográfico**. Audit Tracer no almacena el contenido clínico de los pacientes; en su lugar, captura de manera determinista metadatos de ejecución (quién, cuándo, qué dataset, qué columnas, qué transformación o cuántas filas se exportaron), vinculando cada acción a una identidad verificable mediante firmas asimétricas Ed25519 y registros inmutables.

---

## 2. Marco Normativo y Principios de Tratamiento (CA4)

Las políticas y lineamientos descritos en este documento se sustentan en tres marcos jurídicos y estándares internacionales:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        MARCO JURÍDICO APLICABLE                        │
├───────────────────────────────────┬────────────────────────────────────┤
│   Ley Estatutaria 1581 de 2012    │    HIPAA Security & Privacy Rule   │
│            (Colombia)             │         (45 CFR Parte 164)         │
├───────────────────────────────────┼────────────────────────────────────┤
│ • Art. 5: Datos sensibles (salud) │ • §164.308: Salvaguardas admin.    │
│ • Art. 4: Principios rectores     │ • §164.312(a): Control de acceso   │
│ • Art. 17/18: Deberes seguridad   │ • §164.312(b): Auditoría y logs    │
│ • Cifrado, no repudio y reserva   │ • §164.312(c): Integridad de datos │
└───────────────────────────────────┴────────────────────────────────────┘
                                     │
                                     ▼
        ┌────────────────────────────────────────────────────────┐
        │            ISO/IEC 27001:2022 (Anexo A)                │
        │ • A.5.15: Control de acceso basado en roles (RBAC)     │
        │ • A.8.15: Registro y supervisión de eventos (Logging)  │
        │ • A.8.24: Uso de criptografía y gestión de llaves      │
        └────────────────────────────────────────────────────────┘
```

### 2.1. Principios Rectores Obligatorios
* **Principio de Finalidad y Libertad (Ley 1581, Art. 4 lit. a y b):** Los datos clínicos solo pueden procesarse con autorización previa y expresa del titular o bajo causales legales de salud pública e investigación biomédica autorizada.
* **Principio de Necesidad Mínima / Minimum Necessary (HIPAA §164.502(b)):** Los científicos de datos solo deben acceder a las columnas y registros estrictamente necesarios para el objetivo analítico específico.
* **Principio de Veracidad y Calidad (Ley 1581, Art. 4 lit. c):** La información procesada debe ser completa, exacta y trazable.
* **Principio de Responsabilidad Demostrada / Accountability:** La institución debe ser capaz de demostrar mediante pruebas criptográficas inmutables que los datos han sido custodiados según la norma.

---

## 3. Políticas de Manejo y Protección de Datos Sensibles (CA1 / PDGTRAZDSA-88)

### 3.1. Clasificación y Manejo de Datos de Salud
Según el Artículo 5 de la Ley 1581 de 2012 y la regla Privacy Rule de HIPAA (§164.514), los datos de salud son **datos sensibles** y constituyen Información Médica Protegida (PHI). Su tratamiento está sujeto a prohibición general salvo autorización explícita o necesidad médica/científica amparada por ley.

#### Clasificación Operativa en Proyectos de Analítica:
1. **Nivel 1 — Datos Restringidos / PHI Directo:** Nombres, documentos de identidad, números de historia clínica, teléfonos, correos o direcciones.
   * *Directriz:* **Prohibida su carga directa en entornos de experimentación.** Deben eliminarse o sustituirse antes de ingresar a los pipelines de machine learning.
2. **Nivel 2 — Datos Seudonimizados / Sensibles:** Registros clínicos con identificador sintético (ej. `PAC_84729`), diagnósticos CIE-10, variables fisiológicas, medicación.
   * *Directriz:* Permitido para análisis siempre que el diccionario de correspondencia permanezca aislado y cifrado bajo custodia del Oficial de Seguridad.
3. **Nivel 3 — Datos Agregados / Anonimizados:** Métricas globales, cohortes agrupadas ($k$-anonymity $\ge 5$, $l$-diversity) donde ningún registro individual sea reidentificable.
   * *Directriz:* Autorizado para investigación y reportes institucionales.

### 3.2. Buenas Prácticas en el Almacenamiento Local y Estaciones de Trabajo
* **Cifrado en Reposo (At-Rest Encryption):** Toda estación de trabajo o servidor donde resida temporalmente un dataset clínico debe tener activo cifrado de disco completo (BitLocker en Windows con XTS-AES 256, LUKS en Linux o FileVault en macOS).
* **Directorio de Trabajo Temporal Aislado:**
  * No almacenar archivos `.csv`, `.parquet` o `.xlsx` clínicos en directorios sincronizados automáticamente con servicios en la nube comercial (Dropbox personal, Google Drive público o carpetas compartidas sin cifrar).
  * Los archivos temporales generados por transformaciones intermedias deben eliminarse inmediatamente al finalizar la sesión de análisis.
* **Protección del Almacenamiento Local de Auditoría (`~/.audit_tracer/`):**
  * La base SQLite local (`audit_trail.db`) almacena la cola de eventos firmados. Sus permisos deben configurarse en modo restrictivo (`chmod 600 audit_trail.db` en sistemas tipo Unix).

### 3.3. Políticas para la Transformación y Exportación de Datos
1. **Prohibición de Sobreescritura Destructiva de Datasets Maestros:**
   * Nunca sobreescribir el dataset fuente original. El sistema registra el indicador `sobrescritura = 1` y dispara una advertencia visual en el dashboard para prevenir pérdidas de trazabilidad en el linaje.
2. **Control de Exportación Masiva:**
   * Toda exportación que supere el umbral de **1,000 registros clínicos** es categorizada automáticamente como `nivel_alerta = CRITICO` (o `ANOMALIA` si supera el volumen histórico habitual del usuario). Requiere justificación documentada en la bitácora del proyecto de investigación.
3. **Mantenimiento del Linaje (HU-7.1):**
   * Cada función de transformación (`dropna`, `fillna`, `rename`, `merge`, `apply`) debe mantener coherencia en las columnas de enlace para permitir la reconstrucción del grafo de linaje de datos en caso de una auditoría regulatoria.

---

## 4. Recomendaciones de Seguridad y Prevención de Accesos No Autorizados (CA2 / PDGTRAZDSA-89)

```
┌────────────────────────────────────────────────────────────────────────┐
│                CAPAS DE SEGURIDAD EN AUDIT TRACER                      │
├───────────────────────────────────┬────────────────────────────────────┤
│        Nivel de Usuario           │         Nivel de Red / API         │
├───────────────────────────────────┼────────────────────────────────────┤
│ • Identidad única obligatoria     │ • Forzado estricto de HTTPS (TLS)  │
│ • Tokens personales acotados      │ • Control de acceso por rol (RBAC) │
│ • Login por dispositivo (Colab)   │ • Bloqueo tras 5 fallos (5 min)    │
│ • Llaves privadas Ed25519 (locales│ • Rate limiting e idempotencia     │
└───────────────────────────────────┴────────────────────────────────────┘
```

### 4.1. Principio de Identidad Única (No Repudio e HIPAA §164.312(a)(2)(i))
> [!CAUTION]
> **Prohibición estricta de usuarios genéricos.**
> Está terminantemente prohibido utilizar credenciales compartidas (ej. `admin@institucion.org`, `lab_general`, `investigador_generico`). Todo evento ejecutado bajo un identificador no autenticado o nulo es forzado por el sistema a `usuario_id = 'DESCONOCIDO'` y marcado irreversiblemente con severidad `CRITICO` (HU-2.5).

### 4.2. Gestión de Credenciales y Tokens de Acceso Personal (HU-5.5)
* **Uso Exclusivo de Tokens para Scripts y Pipelines:** En scripts batch o automatizaciones, nunca introducir contraseñas maestras. Generar un **Token de Acceso Personal** desde el dashboard administrativo con fecha de expiración acotada (máximo 30 a 90 días).
* **Gestión Segura de Secretos:**
  * Almacenar el token en variables de entorno del sistema operativo (`AUDIT_TRACER_TOKEN`) o en administradores de secretos (HashiCorp Vault, AWS Secrets Manager, GitHub Secrets).
  * **Nunca incluir tokens en texto plano dentro de notebooks `.ipynb`, scripts `.py` ni comitearlos en repositorios Git.**
* **Revocación Inmediata:** Si un token es sospechoso de compromiso o un investigador culmina su vinculación al proyecto, el administrador debe revocar el token inmediatamente desde `/admin/tokens`. El token dejará de operar en tiempo real en la siguiente solicitud HTTP.

### 4.3. Autenticación en Entornos Interactivos y Nube (Device Code — HU-5.7)
Para sesiones en Google Colab, JupyterHub o servidores remotos donde abrir un navegador no es viable:
* Utilizar `audit_tracer.device_login()`. Este mecanismo presenta un código corto seguro de 8 caracteres y una URL de confirmación en el servidor institucional.
* El investigador confirma su identidad en el navegador con su sesión ya autenticada en el Dashboard, evitando escribir su contraseña en entornos compartidos en la nube.

### 4.4. Control de Acceso Basado en Roles (RBAC — HU-1.4)
Audit Tracer aplica el principio de mínimo privilegio mediante cuatro roles estrictamente segregados:

| Rol | Alcance de Permisos | Restricciones de Seguridad |
| :--- | :--- | :--- |
| **INVESTIGADOR / CIENTÍFICO** | Ejecución de scripts locales, captura de eventos de su propia sesión, generación de reportes propios. | No puede ver eventos ajenos, no puede acceder a `/admin/*`, no revoca tokens. |
| **ANALISTA** | Visualización de registros de auditoría, linaje de datos, explicabilidad contextual de eventos. | Sin permisos administrativos de gestión de usuarios o emisión masiva de tokens. |
| **AUDITOR / CUMPLIMIENTO** | Consulta total de auditoría, reportes de integridad Merkle, filtros de anomalías, descarga de reportes normativos CSV. | Solo lectura. No puede alterar configuraciones de usuarios ni ejecutar código clínico. |
| **ADMIN** | Configuración del sistema, asignación de roles, gestión de llaves públicas, diagnóstico de colas de sincronización. | Sujeto a auditoría forzada de todas sus operaciones administrativas (`CAMBIO_ROL`, `CREACION_USUARIO`). |

### 4.5. Bloqueo Automático ante Intentos Fallidos (HU-2.4)
* El sistema monitorea ráfagas de accesos fallidos.
* Si se registran **5 o más fallos en una ventana de 5 minutos**, la cuenta o el recurso quedan bloqueados temporalmente y la alerta escala a nivel `CRITICO`, notificando al Oficial de Seguridad sobre un posible intento de fuerza bruta o escaneo de archivos.

---

## 5. Lineamientos para la Auditoría, Trazabilidad e Integridad (CA3 / PDGTRAZDSA-90)

```
┌────────────────────────────────────────────────────────────────────────┐
│                    CADENA DE INTEGRIDAD CRIPTOGRÁFICA                  │
├────────────────────────────────────────────────────────────────────────┤
│ 1. Intercepción local en Pandas (sin modificar código del script)      │
│    │                                                                   │
│ 2. Hash SHA-256 sobre 13 campos funcionales (hash_integridad)          │
│    │                                                                   │
│ 3. Firma asimétrica con llave privada local Ed25519 (firma_digital)    │
│    │                                                                   │
│ 4. Transmisión segura idempotente (POST /api/eventos/sincronizar)       │
│    │                                                                   │
│ 5. Triggers SQL de inmutabilidad: UPDATE y DELETE bloqueados a nivel BD│
│    │                                                                   │
│ 6. Agrupación por lotes horarios en Árbol de Merkle (raíz SHA-256)     │
│    │                                                                   │
│ 7. Anclaje externo inmutable (RFC 3161 Timestamping / Ledger externo)  │
└────────────────────────────────────────────────────────────────────────┘
```

### 5.1. Principio de Inmutabilidad de los Registros (HU-5.4)
* La base de datos central de auditoría cuenta con **triggers SQL activos a nivel de motor**:
  * Cualquier sentencia `UPDATE` o `DELETE` sobre la tabla `audit_log` es inmediatamente abortada por un trigger `BEFORE UPDATE/DELETE`.
  * La base de datos inserta automáticamente una fila de severidad `CRITICO` en `audit_intentos_bloqueados`, registrando el usuario, timestamp y evento que se intentó adulterar.
* **Directriz:** Bajo ninguna circunstancia los administradores o DBAs deben desactivar los triggers de inmutabilidad en ambientes de producción.

### 5.2. Verificación de Integridad Campo a Campo y Hash Criptográfico
* Cada registro de auditoría calcula un hash SHA-256 sobre los 13 campos funcionales canónicos (`usuario_id`, `sesion_id`, `timestamp`, `tipo_accion`, `dataset_nombre`, etc.).
* La función `verify_integrity(conn)` recalcula periódicamente los hashes de todos los eventos almacenados. Si un registro sufre alteración física en disco, el sistema lo señala de inmediato como `registro_corrupto` en el Dashboard.

### 5.3. Firma Digital Asimétrica Ed25519 (HU-6.1)
* Cada evento capturado por la librería es firmado con la llave privada del usuario emisor (`firma_digital`).
* El servidor central valida la firma con la llave pública registrada del usuario. Esto previene que un atacante suplante la identidad del investigador o inyecte eventos ficticios en la base central.
* **Custodia de la Llave Privada:** La llave privada nunca viaja al servidor; reside en `~/.audit_keys/user_ed25519.key`. Debe protegerse contra lectura por otros usuarios del sistema operativo.

### 5.4. Árboles de Merkle y Anclaje Externo (HU-6.2)
* Los eventos centralizados se empaquetan en lotes temporales horarios construyendo un **Árbol de Merkle**.
* La raíz de Merkle resultante se ancla a un proveedor externo confiable (RFC 3161 / Ledger). Esto permite demostrar de manera matemáticamente irrefutable ($O(\log n)$) que un evento existía exactamente en ese estado y momento en el tiempo, sin revelar los datos clínicos subyacentes.

### 5.5. Detección Temprana y Monitoreo de Anomalías (HU-6.3)
El Oficial de Cumplimiento debe revisar diariamente el panel de anomalías (`/eventos?solo_anomalias=1`). Las anomalías se disparan ante tres condiciones objetivas:
1. **Volumen Anómalo:** Si las filas exportadas o el total diario de operaciones supera $3\times$ el promedio histórico del usuario.
2. **Horario Inusual:** Actividad registrada fuera de la ventana operativa habitual del usuario o fuera de la jornada estándar (07:00 – 19:00).
3. **Alerta de Correlación:** Si un mismo archivo de datos sensible es accedido concurrentemente por múltiples usuarios en una ventana de 15 minutos.

---

## 6. Procedimientos Operativos y Protocolos ante Incidentes

```
┌────────────────────────────────────────────────────────────────────────┐
│            FLUJO DE RESPUESTA ANTE ALERTAS Y ANOMALÍAS                 │
├────────────────────────────────────────────────────────────────────────┤
│   Detección (Alerta CRITICA o ANOMALIA en Dashboard de Auditoría)      │
│                                  │                                     │
│                                  ▼                                     │
│   Paso 1: Triaje Forense (/eventos/<id> con Explicador Contextual)     │
│                                  │                                     │
│                                  ▼                                     │
│   Paso 2: Validación de Integridad y Firma (verify_event_signature)     │
│                                  │                                     │
│                                  ▼                                     │
│   Paso 3: Inspección del Linaje de Datos (/linaje?dataset=...)         │
│                                  │                                     │
│                                  ▼                                     │
│   Paso 4: Acción Correctiva (Revocación de Token / Notificación Oficial)│
│                                  │                                     │
│                                  ▼                                     │
│   Paso 5: Exportación de Evidencia Normativa (/reportes/exportar CSV)   │
└────────────────────────────────────────────────────────────────────────┘
```

### 6.1. Protocolo ante Alerta de Integridad Comprometida (`registros_corruptos > 0`)
1. **Contención Inmediata:** El administrador debe aislar la base de datos central y ponerla en modo solo lectura para evitar propagación de datos no verificados.
2. **Identificación Forense:** Ejecutar la verificación de pruebas Merkle (`/merkle/verificar`) para determinar el rango exacto de eventos o el bloque temporal comprometido.
3. **Auditoría de Intentos Bloqueados:** Consultar `audit_intentos_bloqueados` para verificar si existió una instrucción manual directa (`UPDATE` o `DELETE`) ejecutada por un usuario administrativo o mediante inyección SQL.
4. **Restauración y Conciliación:** Recuperar el segmento afectado a partir del respaldo inmutable y de las colas de sincronización locales (`audit_sync_queue`) de los clientes.

### 6.2. Protocolo ante Desconexión de Red o Trabajo en Campo (HU-5.8)
* Cuando un científico de datos trabaja en una locación sin conectividad o con fallas en el servidor central:
  1. La librería almacena los eventos en la base SQLite local (`audit_trail.db`) en la tabla `audit_sync_queue` con estado `PENDIENTE`.
  2. No interrumpir la ejecución del script: la librería garantiza que la analítica médica continúe sin bloqueos.
  3. Al restablecer la red, ejecutar `audit_tracer.sync_now()` para vaciar la cola hacia el servidor central de forma idempotente (sin duplicar filas gracias a la restricción `evento_uuid UNIQUE`).

---

## 7. Ejemplos Prácticos en Escenarios Reales (CA5)

### Escenario 1: Uso Seguro de la Librería en Jupyter Notebook / Google Colab
*Un científico de datos analiza un dataset de pacientes oncológicos aplicando buenas prácticas de autenticación, supresión de identificadores y captura no invasiva.*

```python
import os
import pandas as pd
import audit_tracer

# 1. Configuración de credenciales seguras mediante variable de entorno o login interactivo
# NUNCA hardcodear contraseñas en el notebook
if "AUDIT_TRACER_TOKEN" in os.environ:
    audit_tracer.login(token=os.environ["AUDIT_TRACER_TOKEN"])
else:
    # Autenticación segura por dispositivo en Colab (sin ingresar password en la celda)
    audit_tracer.device_login()

# 2. Ingesta segura de datos clínicos seudonimizados (captura automática del evento CARGA)
df_pacientes = pd.read_csv("datos/cohortes/pacientes_oncologia_anonimizados.csv")

# 3. Aplicación del principio de Necesidad Mínima: conservar solo variables clínicas del estudio
columnas_requeridas = ["edad", "estadio_tumoral", "biomarcador_kras", "supervivencia_meses"]
df_analisis = df_pacientes[columnas_requeridas]

# 4. Transformaciones clínicas (captura automática del evento TRANSFORMACION con linaje)
df_limpio = df_analisis.dropna(subset=["estadio_tumoral"]).fillna({"biomarcador_kras": "NO_EVALUADO"})

# 5. Exportación controlada del resultado analítico (captura automática del evento EXPORTACION)
df_limpio.to_csv("datos/resultados/resumen_oncologia_agregado.csv", index=False)

# 6. Sincronización explícita al terminar la sesión de trabajo
audit_tracer.sync_now()
audit_tracer.logout()
```

---

### Escenario 2: Detección y Mitigación de una Exportación Masiva Sospechosa
*Un script no autorizado intenta extraer 50.000 historias clínicas completas hacia una ruta externa fuera del horario laboral.*

1. **Evento Registrado en la Ingesta Central:**
   * `timestamp`: `2026-11-04T02:15:30` (02:15 AM).
   * `tipo_accion`: `EXPORTACION`.
   * `dataset_nombre`: `HISTORIAS_CLINICAS_COMPLETAS.csv`.
   * `filas_exportadas`: `50,000`.
   * `usuario_id`: `dr_investigador_4`.
2. **Comportamiento del Motor de Detección (HU-6.3):**
   * Regla de horario inusual (CA3): dispara alerta por actividad a las 02:15 AM fuera del rango habitual.
   * Regla de volumen anómalo (CA2): 50.000 filas supera en más de $10\times$ el promedio histórico del usuario (promedio habitual: 250 filas).
   * Asignación automática: `nivel_alerta = 'ANOMALIA'` con motivo explicativo detallado.
3. **Respuesta del Oficial de Cumplimiento en el Dashboard:**
   * El Oficial ingresa a `/eventos?solo_anomalias=1` y detecta la fila resaltada en violeta.
   * Clic en **Ver Detalle** (`/eventos/482`): el explicador contextual (HU-7.4) señala: *"Riesgo potencial de exfiltración masiva de historias clínicas fuera del horario habitual"*.
   * Clic en **Ver Linaje** (`/linaje?event_id=482`): visualiza desde qué archivo origen se construyó la exportación.
   * Acción: Revocar inmediatamente el token del usuario desde `/admin/tokens` y requerir informe justificativo al investigador.

---

### Escenario 3: Generación de Reporte Normativo para Auditoría Externa HIPAA / Ley 1581
*La Superintendencia de Industria y Comercio (SIC) o un auditor externo solicita evidenciar el acceso a datos médicos durante el último trimestre.*

1. El Auditor ingresa al módulo de **Reportes** (`/reportes`).
2. Aplica los filtros de auditoría (HU-4.5):
   * `Rango de fechas`: `2026-08-01` a `2026-10-31`.
   * `Dataset`: `REGISTRO_DIABETES_NACIONAL.csv`.
3. El sistema genera el reporte cronológico enriquecido con la columna `referencia_normativa` (HU-7.3):
   * Cada fila de `CONSULTA` se mapea a: `HIPAA §164.312(b) / Ley 1581 Art. 17 lit. a`.
   * Cada fila de `EXPORTACION` se mapea a: `HIPAA §164.312(a)(2)(iv) / Ley 1581 Art. 18 lit. b`.
4. El Auditor hace clic en **Exportar Reporte (CSV)** (`/reportes/exportar`), obteniendo un archivo verificable, íntegro y debidamente foliado con los hashes de cada evento.

---

