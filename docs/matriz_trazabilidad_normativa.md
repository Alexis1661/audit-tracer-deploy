# Anexo — Matriz de trazabilidad normativa (HU-6.6)

| | |
|---|---|
| **Sistema** | Audit Tracer — trazabilidad y auditoría de datos clínicos |
| **Versión de la matriz** | 1.0 |
| **Fecha** | 26/10/2026 |
| **Código evaluado** | rama `main`, commit `deb9034` (incluye hasta HU-6.2) |
| **Normas** | HIPAA Security Rule y Privacy Rule (45 CFR Parte 164) · Ley Estatutaria 1581 de 2012 (Colombia) |
| **Versión para máquinas** | [`matriz_trazabilidad_normativa.csv`](matriz_trazabilidad_normativa.csv) (la reutiliza HU-7.3) |
| **Estado** | Pendiente de revisión del equipo (ver sección 7) |

## 1. Propósito y alcance

Esta matriz le permite a un auditor externo verificar, control por control, qué exigencia de HIPAA o de la Ley 1581 de 2012 cubre el sistema, en qué parte del código está y qué prueba lo demuestra.

**Qué incluye.** Los 32 controles técnicos implementados en el repositorio hasta la fecha: autenticación, control de acceso por rol, registro de auditoría, integridad, transmisión y monitoreo.

**Qué no incluye.** Las obligaciones organizacionales, que no se resuelven con software y le corresponden a la institución que use el sistema:

- **HIPAA:** salvaguardas administrativas y físicas (análisis de riesgos, capacitación, contratos con asociados de negocio §164.308(b), control de instalaciones §164.310).
- **Ley 1581:** autorización del titular (art. 9), aviso de privacidad, atención de consultas y reclamos (arts. 14 y 15), manual interno de políticas (art. 17 lit. k).

**Rol del sistema.** Audit Tracer no almacena la historia clínica: registra quién cargó, consultó, transformó o exportó un dataset clínico, y protege ese registro. Por eso la mayoría de los controles responden a los requisitos de auditoría e integridad. Los datos de salud son *datos sensibles* según el art. 5 de la Ley 1581, lo que obliga a una protección reforzada de su tratamiento.

## 2. Cómo usar la matriz

1. **Por control** (sección 4): cada fila indica el control, el componente que lo implementa, las cláusulas que satisface y la evidencia, que siempre incluye la HU y al menos una prueba automatizada.
2. **Por cláusula** (sección 5): parte de la norma y lista los controles que la cubren. Es la vista más rápida para un auditor.
3. **Reproducir la evidencia:**

   ```bash
   python -m pytest tests/ -v                         # suite completa
   python -m pytest tests/test_ataques_simulados.py   # ataques simulados (HU-6.5)
   python -m pytest tests/test_matriz_normativa.py    # coherencia de esta matriz
   ```

   **Ejecución registrada:** 26/10/2026, Python 3.12.3, Windows 11. Resultado: 533 pruebas superadas, 1 omitida (antes de agregar `test_matriz_normativa.py`).

4. **La matriz no se desactualiza sola.** `tests/test_matriz_normativa.py` falla si un archivo o una prueba citados como evidencia se renombran o desaparecen, si una fila queda sin cláusula HIPAA o Ley 1581, o si un control del CSV no aparece en este anexo.

**Convenciones.**

- **(R) / (D):** especificación *requerida* o *direccionable* (*addressable*) en HIPAA. Una direccionable obliga a evaluar si es razonable implementarla y a documentar la decisión.
- **(apoyo):** el control contribuye a la cláusula pero no la satisface por sí solo.
- **Eventos:** valores de `tipo_accion` que el control escribe en `audit_log`. Sirven para que HU-7.3 asocie cada evento de un reporte con su norma.

## 3. Marco normativo citado

### HIPAA — 45 CFR Parte 164

| Cláusula | Exigencia | Tipo |
|---|---|---|
| §164.306(a)(1) | Garantizar la confidencialidad, integridad y disponibilidad de la información de salud electrónica (ePHI) | Requisito general |
| §164.308(a)(1)(ii)(D) | Revisión periódica de la actividad del sistema: registros de auditoría, reportes de acceso e incidentes | R |
| §164.308(a)(3)(ii)(B) | Verificar que el acceso de cada persona sea apropiado (*workforce clearance*) | D |
| §164.308(a)(3)(ii)(C) | Terminar el acceso cuando ya no corresponde | D |
| §164.308(a)(4)(ii)(B) | Autorización de acceso a la ePHI | D |
| §164.308(a)(4)(ii)(C) | Establecer, documentar, revisar y modificar el derecho de acceso de un usuario | D |
| §164.308(a)(5)(ii)(C) | Monitorear los intentos de inicio de sesión y reportar discrepancias | D |
| §164.308(a)(5)(ii)(D) | Procedimientos para crear, cambiar y proteger contraseñas | D |
| §164.308(a)(6)(ii) | Identificar, responder y documentar incidentes de seguridad | R |
| §164.308(a)(7)(ii)(A) | Plan de respaldo para obtener copias exactas recuperables | R |
| §164.308(a)(8) | Evaluación técnica periódica de las salvaguardas | R |
| §164.312(a)(1) | Control de acceso: solo personas o programas autorizados acceden a la ePHI | Estándar |
| §164.312(a)(2)(i) | Identificador único para cada usuario | R |
| §164.312(b) | Controles de auditoría: registrar y examinar la actividad en sistemas con ePHI | R |
| §164.312(c)(1) | Integridad: proteger la ePHI de alteración o destrucción indebida | Estándar |
| §164.312(c)(2) | Mecanismo para corroborar que la ePHI no fue alterada ni destruida | D |
| §164.312(d) | Autenticar que quien accede es quien dice ser | R |
| §164.312(e)(1) | Seguridad de la transmisión por redes electrónicas | Estándar |
| §164.312(e)(2)(i) | Controles de integridad de la información transmitida | D |
| §164.312(e)(2)(ii) | Cifrado de la información transmitida | D |
| §164.316(b)(1) | Documentar políticas, acciones, actividades y evaluaciones | R |
| §164.502(b) | Mínimo necesario: limitar el acceso a lo necesario para la tarea (Privacy Rule) | Estándar |
| §164.528 | Rendición de cuentas de las divulgaciones de PHI (Privacy Rule) | Estándar |

### Ley 1581 de 2012 — Protección de datos personales

| Cláusula | Exigencia |
|---|---|
| Art. 4 lit. d | **Veracidad o calidad:** la información tratada debe ser veraz, completa, exacta y comprobable |
| Art. 4 lit. f | **Acceso y circulación restringida:** solo personas autorizadas acceden a los datos |
| Art. 4 lit. g | **Seguridad:** medidas técnicas para evitar adulteración, pérdida, consulta, uso o acceso no autorizado o fraudulento |
| Art. 4 lit. h | **Confidencialidad:** reserva de la información por parte de quienes intervienen en el tratamiento |
| Art. 17 lit. d | Deber del Responsable: conservar la información en condiciones de seguridad que impidan su adulteración, pérdida, consulta, uso o acceso no autorizado o fraudulento |
| Art. 17 lit. m | Deber del Responsable: informar al titular, si lo solicita, sobre el uso dado a sus datos |
| Art. 17 lit. n | Deber del Responsable: informar a la autoridad de protección de datos (SIC) cuando haya violaciones a los códigos de seguridad |
| Art. 18 lit. b | Deber del Encargado: conservar la información en condiciones de seguridad (mismo alcance que el art. 17 lit. d) |
| Art. 18 lit. j | Deber del Encargado: permitir el acceso solo a quienes pueden tenerlo |

Además, el Decreto 1377 de 2013, art. 26 (compilado en el Decreto 1074 de 2015), exige que el Responsable pueda **demostrar** las medidas que implementó (responsabilidad demostrada). Esta matriz, junto con la suite de pruebas, es parte de esa demostración.

## 4. Matriz de controles

### Identificación y autenticación

| ID | Control técnico | Componente del sistema | HIPAA (45 CFR) | Ley 1581/2012 | Evidencia (HU · prueba automatizada) |
|---|---|---|---|---|---|
| CT-01 | Contraseñas almacenadas con bcrypt y sal aleatoria por usuario | `audit_tracer/utils/hashing.py` (hash_password; verify_password)<br>`audit_tracer/models/usuarios.py` (create_user) | §164.308(a)(5)(ii)(D)<br>§164.312(d) | Art. 4 lit. g<br>Art. 17 lit. d | **HU-1.1, HU-1.3**<br>`test_registro.py` → `test_register_user_success`<br>`test_autenticacion.py` → `test_login_success` |
| CT-02 | Identificador único por usuario (UUID4) y correo no repetible<br>*Eventos:* `CREACION_USUARIO` | `audit_tracer/models/usuarios.py` (create_user)<br>`audit_tracer/schema/usuarios.sql` | §164.312(a)(2)(i) | Art. 4 lit. g<br>Art. 17 lit. d | **HU-1.1**<br>`test_registro.py` → `test_register_user_success`<br>`test_registro.py` → `test_register_duplicate_email` |
| CT-03 | Mensaje genérico ante credenciales inválidas (no revela si el correo existe)<br>*Eventos:* `ACCESO_FALLIDO` | `audit_tracer/auth/autenticacion.py` (login) | §164.312(d) | Art. 4 lit. g<br>Art. 4 lit. h | **HU-1.3**<br>`test_autenticacion.py` → `test_login_invalid_credentials`<br>`test_autenticacion.py` → `test_login_email_no_registrado_se_marca_desconocido_y_critico` |
| CT-04 | Bloqueo de cuenta tras 5 intentos fallidos consecutivos; una cuenta bloqueada no inicia sesión ni valida tokens<br>*Eventos:* `ACCESO_FALLIDO` | `audit_tracer/auth/autenticacion.py` (login)<br>`audit_tracer/models/usuarios.py` (block_user)<br>`audit_tracer/auth/tokens.py` (validar_token) | §164.308(a)(5)(ii)(C)<br>§164.312(a)(1)<br>§164.312(d) | Art. 4 lit. g<br>Art. 17 lit. d | **HU-1.3**<br>`test_autenticacion.py` → `test_user_blocking`<br>`test_tokens.py` → `test_validar_token_usuario_bloqueado_es_rechazado` |
| CT-05 | Monitoreo de inicios de sesión fallidos: ADVERTENCIA desde 3 intentos y CRITICO con más de 3 en 5 minutos<br>*Eventos:* `ACCESO_FALLIDO` | `audit_tracer/auth/autenticacion.py` (login)<br>`audit_tracer/models/audit_log.py` (contar_intentos_fallidos_recientes) | §164.308(a)(5)(ii)(C)<br>§164.308(a)(6)(ii) | Art. 17 lit. d<br>Art. 17 lit. n | **HU-1.3, HU-4.4**<br>`test_autenticacion.py` → `test_intentos_fallidos_en_ventana_de_tiempo_genera_critico`<br>`test_audit_log.py` → `test_no_cuenta_otros_usuarios_ni_otros_tipos` |
| CT-06 | Tokens personales de acceso: 256 bits de secrets; vencen a los 30 días; revocación inmediata; estados ACTIVO/REVOCADO/EXPIRADO<br>*Eventos:* `GENERACION_TOKEN`, `REVOCACION_TOKEN` | `audit_tracer/auth/tokens.py` (generar_token; validar_token; revocar_token)<br>`audit_tracer/models/tokens.py`<br>`app.py` (/admin/tokens; /api/tokens/*) | §164.312(d)<br>§164.312(a)(1)<br>§164.308(a)(3)(ii)(C) | Art. 4 lit. g<br>Art. 17 lit. d<br>Art. 18 lit. j | **HU-5.5**<br>`test_tokens.py` → `test_generar_token_seguro_formato`<br>`test_tokens.py` → `test_generar_token_exitoso_expiracion_default_30_dias`<br>`test_tokens.py` → `test_revocar_token_por_id_inmediato`<br>`test_ataques_simulados.py` → `test_token_revocado_deja_de_funcionar_de_inmediato`<br>`test_ataques_simulados.py` → `test_token_expirado_es_rechazado`<br>`test_ataques_simulados.py` → `test_token_falso_o_ausente_es_rechazado` |
| CT-07 | Login de la librería por código de dispositivo: código corto de 10 minutos y un solo uso; device_code no adivinable; confirmación con sesión del dashboard<br>*Eventos:* `CONFIRMACION_LOGIN_DISPOSITIVO` | `audit_tracer/auth/device_codes.py`<br>`audit_tracer/device_login.py`<br>`app.py` (/api/auth/dispositivo/*; /auth/dispositivo) | §164.312(d) | Art. 4 lit. g<br>Art. 17 lit. d | **HU-5.7**<br>`test_device_login.py` → `test_device_code_es_largo_y_no_adivinable_desde_el_codigo_corto`<br>`test_device_login.py` → `test_confirmar_codigo_ya_confirmado_no_se_puede_reconfirmar`<br>`test_device_login.py` → `test_confirmar_codigo_expirado_falla_y_lo_marca_expirado`<br>`test_device_login.py` → `test_estado_confirmado_entrega_el_token_una_sola_vez` |
| CT-08 | Clave de firma de la cookie de sesión tomada de SECRET_KEY (o aleatoria por proceso) y no del código fuente | `app.py` (app.secret_key) | §164.312(d)<br>§164.312(a)(1) | Art. 4 lit. g<br>Art. 17 lit. d | **HU-6.5**<br>`test_ataques_simulados.py` → `test_cookie_de_sesion_forjada_con_la_clave_antigua_no_da_acceso` |

### Control de acceso

| ID | Control técnico | Componente del sistema | HIPAA (45 CFR) | Ley 1581/2012 | Evidencia (HU · prueba automatizada) |
|---|---|---|---|---|---|
| CT-09 | Matriz de permisos rol × módulo (4 roles; 5 módulos) validada en cada llamada<br>*Eventos:* `ACCESO_DENEGADO` | `audit_tracer/auth/control_acceso.py` (PERMISSION_MATRIX; has_permission; requires_role)<br>`app.py` (login_required; modulo_required; admin_required) | §164.312(a)(1)<br>§164.308(a)(4)(ii)(B)<br>§164.502(b) | Art. 4 lit. f<br>Art. 18 lit. j | **HU-1.4**<br>`test_control_acceso.py` → `test_permission_combination`<br>`test_control_acceso.py` → `test_role_check_is_per_call_not_once`<br>`test_ataques_simulados.py` → `test_cientifico_de_datos_no_puede_consultar_eventos`<br>`test_ataques_simulados.py` → `test_sin_sesion_no_se_llega_a_la_administracion` |
| CT-10 | Alta de usuarios y cambio de rol solo por ADMIN; protección del último administrador activo<br>*Eventos:* `CREACION_USUARIO`, `MODIFICACION_ROL` | `audit_tracer/auth/registro.py` (register_user)<br>`audit_tracer/auth/gestion_roles.py` (assign_role)<br>`app.py` (/admin/usuarios/*) | §164.308(a)(4)(ii)(C)<br>§164.308(a)(3)(ii)(B) | Art. 17 lit. d<br>Art. 18 lit. j | **HU-1.1, HU-1.2**<br>`test_registro.py` → `test_register_invalid_rol`<br>`test_ataques_simulados.py` → `test_analista_no_puede_crearse_un_usuario_admin` |
| CT-11 | Registro de todo acceso bloqueado por rol (módulo; ruta; método HTTP)<br>*Eventos:* `ACCESO_DENEGADO` | `audit_tracer/auth/control_acceso.py` (_log_denied_access)<br>`app.py` (_registrar_acceso_denegado; admin_required) | §164.312(b)<br>§164.308(a)(1)(ii)(D) | Art. 17 lit. d | **HU-1.4, HU-6.5**<br>`test_control_acceso.py` → `test_denied_access_logged_in_audit_log`<br>`test_ataques_simulados.py` → `test_analista_no_puede_generar_tokens_para_otro_usuario` |

### Registro de auditoría

| ID | Control técnico | Componente del sistema | HIPAA (45 CFR) | Ley 1581/2012 | Evidencia (HU · prueba automatizada) |
|---|---|---|---|---|---|
| CT-12 | Captura automática de cargas y consultas de datos clínicos con import audit_tracer<br>*Eventos:* `CARGA`, `CONSULTA` | `audit_tracer/__init__.py`<br>`audit_tracer/data_capture.py` | §164.312(b) | Art. 17 lit. m | **HU-2.1, HU-5.1**<br>`test_data_capture.py` → `test_read_csv_genera_evento_carga`<br>`test_data_capture.py` → `test_evento_tiene_todos_los_campos_requeridos`<br>`test_integracion_automatica.py` → `test_import_activa_todos_los_interceptores_sin_llamar_nada_mas` |
| CT-13 | Registro de transformaciones (fillna; dropna; drop; rename; apply; merge) con columnas afectadas<br>*Eventos:* `TRANSFORMACION` | `audit_tracer/transform_capture.py` | §164.312(b)<br>§164.312(c)(1) | Art. 4 lit. d<br>Art. 17 lit. m | **HU-2.2**<br>`test_transform_capture.py` → `test_fillna_contiene_usuario_id`<br>`test_integracion_automatica.py` → `test_flujo_sin_wraps_registra_todos_los_tipos_de_evento` |
| CT-14 | Registro de exportaciones (filas; ruta destino; sobrescritura); CRITICO si superan 1000 filas<br>*Eventos:* `EXPORTACION` | `audit_tracer/export_capture.py` (UMBRAL_EXPORTACION_MASIVA; audited_open) | §164.312(b)<br>§164.308(a)(1)(ii)(D)<br>§164.528 (apoyo) | Art. 4 lit. f<br>Art. 17 lit. m | **HU-2.3**<br>`test_export_capture.py` → `test_to_csv_registra_filas_exportadas`<br>`test_export_capture.py` → `test_to_csv_registra_ruta_destino`<br>`test_export_capture.py` → `test_exportacion_masiva_genera_nivel_alerta_critico` |
| CT-15 | Registro de intentos fallidos de acceso a datasets (archivo inexistente o sin permiso); CRITICO con más de 3 en 5 minutos<br>*Eventos:* `ACCESO_FALLIDO` | `audit_tracer/failed_access.py` | §164.308(a)(1)(ii)(D)<br>§164.308(a)(6)(ii)<br>§164.312(b) | Art. 17 lit. d<br>Art. 17 lit. n | **HU-2.4**<br>`test_failed_access.py` → `test_permission_error_genera_acceso_fallido`<br>`test_failed_access.py` → `test_cuatro_intentos_genera_critico`<br>`test_failed_access.py` → `test_intentos_fuera_de_ventana_no_generan_critico` |
| CT-16 | Cada evento queda asociado a un usuario único; sin identificación se registra como DESCONOCIDO con nivel CRITICO; el login tardío liga la sesión sin modificar eventos<br>*Eventos:* `ATRIBUCION_SESION` | `audit_tracer/models/audit_log.py` (_prepare_event)<br>`audit_tracer/session_tracker.py` | §164.312(a)(2)(i)<br>§164.312(b) | Art. 17 lit. m | **HU-2.5, HU-5.1**<br>`test_audit_log.py` → `test_usuario_autenticado_queda_asociado_al_evento`<br>`test_audit_log.py` → `test_usuario_no_identificado_se_marca_desconocido_y_critico`<br>`test_integracion_automatica.py` → `test_login_tardio_registra_atribucion_sin_modificar_eventos` |
| CT-17 | Sesiones de trabajo con sesion_id UUID; inicio y cierre registrados con entorno y host<br>*Eventos:* `INICIO_SESION`, `CIERRE_SESION`, `SESION_INTERRUMPIDA` | `audit_tracer/session_tracker.py`<br>`audit_tracer/utils/contexto.py`<br>`audit_tracer/auth/autenticacion.py` (logout) | §164.312(b) | Art. 17 lit. m | **HU-3.2, HU-2.5**<br>`test_session_tracker.py` → `test_login_reutiliza_la_misma_sesion_id`<br>`test_data_capture.py` → `test_todos_los_eventos_tienen_mismo_sesion_id`<br>`test_integracion_automatica.py` → `test_detecta_google_colab` |
| CT-18 | Apagar la captura deja un evento CRITICO (no se puede desactivar sin rastro)<br>*Eventos:* `AUDITORIA_DESACTIVADA` | `audit_tracer/data_capture.py` (log_deactivation) | §164.312(b)<br>§164.308(a)(1)(ii)(D) | Art. 17 lit. d | **HU-5.1**<br>`test_integracion_automatica.py` → `test_desactivar_la_captura_queda_registrado_como_critico` |
| CT-19 | Aislamiento de errores internos: la auditoría nunca interrumpe al usuario y sus fallos van a un log de sistema separado | `audit_tracer/utils/error_log.py` (guard; log_internal_error) | §164.306(a)(1)<br>§164.312(b) | Art. 4 lit. g | **HU-5.1**<br>`test_integracion_automatica.py` → `test_error_interno_no_interrumpe_pandas_y_va_al_log_de_errores`<br>`test_integracion_automatica.py` → `test_error_del_usuario_llega_intacto_aunque_la_auditoria_falle` |

### Integridad

| ID | Control técnico | Componente del sistema | HIPAA (45 CFR) | Ley 1581/2012 | Evidencia (HU · prueba automatizada) |
|---|---|---|---|---|---|
| CT-20 | Hash SHA-256 por evento y verificación de integridad (verify_integrity) sobre la base local o la central | `audit_tracer/utils/hashing.py` (hash_event)<br>`audit_tracer/models/audit_log.py` (verify_integrity)<br>`app.py` (/verificar-integridad) | §164.312(c)(1)<br>§164.312(c)(2) | Art. 17 lit. d<br>Art. 18 lit. b | **HU-3.2, HU-3.3**<br>`test_audit_log.py` → `test_verify_integrity`<br>`test_central_db.py` → `test_verify_integrity_funciona_sobre_la_base_central`<br>`test_ataques_simulados.py` → `test_alteracion_saltandose_los_triggers_la_detecta_verify_integrity` |
| CT-21 | Inmutabilidad de audit_log: triggers que rechazan UPDATE y DELETE y registran el intento<br>*Eventos:* `INTENTO_MODIFICACION`, `INTENTO_ELIMINACION (tabla audit_intentos_bloqueados)` | `audit_tracer/schema/audit_log.sql`<br>`audit_tracer/schema/audit_log_central.sql` (trg_audit_log_no_update; trg_audit_log_no_delete; audit_intentos_bloqueados) | §164.312(c)(1)<br>§164.312(b) | Art. 17 lit. d<br>Art. 18 lit. b | **HU-3.3, HU-5.4**<br>`test_central_db.py` → `test_bloquea_update`<br>`test_central_db.py` → `test_bloquea_delete`<br>`test_central_db.py` → `test_intento_de_update_queda_registrado`<br>`test_ataques_simulados.py` → `test_update_directo_es_bloqueado_y_queda_registrado` |
| CT-22 | Firma digital Ed25519 de cada evento (no repudio); el servidor rechaza firmas inválidas y exige firma si el usuario registró llave<br>*Eventos:* `FIRMA_INVALIDA` | `audit_tracer/digital_signatures.py`<br>`app.py` (/api/eventos/sincronizar; /api/usuarios/llave-publica; /eventos/<id>) | §164.312(c)(2)<br>§164.312(e)(2)(i)<br>§164.312(d) | Art. 17 lit. d<br>Art. 18 lit. b | **HU-6.1, HU-6.5**<br>`test_digital_signatures.py` → `test_evento_manipulado_tras_firma`<br>`test_digital_signatures.py` → `test_firma_invalida_llave_incorrecta`<br>`test_ataques_simulados.py` → `test_hash_recalculado_lo_detecta_la_firma_digital`<br>`test_ataques_simulados.py` → `test_quitar_la_firma_no_salta_la_verificacion` |
| CT-23 | Árbol de Merkle por lote horario; prueba O(log n) por evento; raíz firmada y anclada fuera de la base | `audit_tracer/merkle.py`<br>`audit_tracer/merkle_scheduler.py`<br>`app.py` (/merkle/*) | §164.312(c)(1)<br>§164.312(c)(2) | Art. 17 lit. d<br>Art. 18 lit. b | **HU-6.2**<br>`test_merkle.py` → `test_generar_y_verificar_prueba_valida`<br>`test_merkle.py` → `test_detecta_modificacion_de_evento_en_bd`<br>`test_merkle.py` → `test_detecta_eliminacion_de_evento_en_bd` |

### Transmisión

| ID | Control técnico | Componente del sistema | HIPAA (45 CFR) | Ley 1581/2012 | Evidencia (HU · prueba automatizada) |
|---|---|---|---|---|---|
| CT-24 | HTTPS obligatorio para enviar eventos (cliente y servidor responden 426 fuera de localhost); encabezados de proxy solo con TRUST_PROXY_HEADERS=1 | `audit_tracer/sync_client.py` (_validar_https)<br>`app.py` (_peticion_es_segura; ProxyFix) | §164.312(e)(1)<br>§164.312(e)(2)(ii) | Art. 4 lit. g<br>Art. 17 lit. d | **HU-5.6**<br>`test_sync_events.py` → `test_url_no_https_es_rechazada`<br>`test_sync_events.py` → `test_peticion_no_https_fuera_de_localhost_responde_426`<br>`test_sync_events.py` → `test_peticion_no_https_se_rechaza_incluso_sin_token` |
| CT-25 | El endpoint receptor autentica al emisor con token personal y registra los rechazos sin exponer el token<br>*Eventos:* `SINCRONIZACION_RECHAZADA` | `app.py` (/api/eventos/sincronizar)<br>`audit_tracer/auth/tokens.py` (validar_token) | §164.312(d)<br>§164.312(e)(1) | Art. 4 lit. h<br>Art. 17 lit. d | **HU-5.6, HU-5.8**<br>`test_sync_events.py` → `test_token_inexistente_responde_401_y_no_inserta`<br>`test_sync_events.py` → `test_rechazo_por_token_invalido_queda_registrado_sin_exponer_el_token`<br>`test_sync_events.py` → `test_pagina_no_expone_el_valor_de_un_token_rechazado` |
| CT-26 | Idempotencia por evento_uuid: reintentos y reenvíos (replay) no duplican eventos | `audit_tracer/models/audit_log.py` (insert_event_if_new)<br>`audit_tracer/schema/audit_log_central.sql` (evento_uuid UNIQUE) | §164.312(c)(1)<br>§164.312(e)(2)(i) | Art. 4 lit. d | **HU-5.4, HU-5.6, HU-5.8**<br>`test_sync_events.py` → `test_mismo_evento_dos_veces_no_duplica_en_la_central`<br>`test_central_db.py` → `test_evento_uuid_sigue_siendo_unico_bajo_concurrencia`<br>`test_ataques_simulados.py` → `test_reenviar_un_evento_valido_no_lo_duplica` |
| CT-27 | Base central consolidada y cola local de sincronización: sin conexión los eventos se guardan y se envían después | `audit_tracer/db.py`<br>`audit_tracer/sync_client.py`<br>`audit_tracer/schema/audit_log.sql` (audit_sync_queue) | §164.312(b)<br>§164.308(a)(7)(ii)(A) (apoyo) | Art. 17 lit. d<br>Art. 18 lit. b | **HU-5.4, HU-5.8**<br>`test_central_db.py` → `test_mismo_hash_y_uuid_en_ambas_bases`<br>`test_sync_events.py` → `test_evento_uuid_no_se_regenera_entre_reintentos`<br>`test_sync_events.py` → `test_token_invalido_no_reintenta_y_no_elimina_el_evento`<br>`test_integracion_automatica.py` → `test_sincronizacion_nunca_hace_red_en_el_hilo_del_usuario` |

### Monitoreo y revisión

| ID | Control técnico | Componente del sistema | HIPAA (45 CFR) | Ley 1581/2012 | Evidencia (HU · prueba automatizada) |
|---|---|---|---|---|---|
| CT-28 | Clasificación de alertas NORMAL/ADVERTENCIA/CRITICO; incluye accesos fuera del horario laboral configurable | `audit_tracer/data_capture.py`<br>`audit_tracer/utils/horario.py`<br>`app.py` (/dashboard; /eventos/criticos/exportar) | §164.308(a)(1)(ii)(D)<br>§164.308(a)(6)(ii) | Art. 17 lit. n | **HU-4.4**<br>`test_data_capture.py` → `test_acceso_fuera_de_horario_genera_nivel_alerta_critico`<br>`test_audit_log.py` → `test_get_critical_events_solo_devuelve_criticos`<br>`test_audit_log.py` → `test_evento_critico_incluye_contexto_ca4` |
| CT-29 | Consulta y filtrado de eventos; detalle con verificación de firma y explicación del evento | `app.py` (/eventos; /eventos/<id>)<br>`audit_tracer/models/audit_log.py`<br>`audit_tracer/event_explainer.py` | §164.308(a)(1)(ii)(D) | Art. 17 lit. m | **HU-4.1, HU-4.2, HU-4.3, HU-7.4**<br>`test_consulta_eventos.py` → `test_ca2_eventos_incluyen_campos_minimos_requeridos`<br>`test_audit_log.py` → `test_combina_usuario_fecha_y_tipo_accion`<br>`test_detalle_evento.py` → `test_endpoint_detalle_evento_existente_status_200`<br>`test_detalle_evento.py` → `test_diagnostico_evento_critico_accesos_fallidos` |
| CT-30 | Reportes por fecha y usuario con exportación CSV; exportación de eventos críticos | `app.py` (/reportes; /reportes/exportar; /eventos/criticos/exportar)<br>`audit_tracer/models/audit_log.py` | §164.308(a)(1)(ii)(D)<br>§164.316(b)(1) | Art. 17 lit. m | **HU-4.5, HU-4.4**<br>`test_audit_log.py` → `test_columnas_del_reporte_son_exactamente_las_de_ca2`<br>`test_audit_log.py` → `test_csv_respeta_orden_cronologico_y_solo_incluye_eventos_filtrados`<br>`test_audit_log.py` → `test_exporta_respetando_filtros` |
| CT-31 | Linaje del dato en grafo (origen; transformaciones; exportaciones) por dataset o por evento | `audit_tracer/lineage.py`<br>`app.py` (/linaje; /api/linaje) | §164.312(b)<br>§164.312(c)(1) | Art. 4 lit. d<br>Art. 17 lit. m | **HU-7.1**<br>`test_lineage.py` → `test_sesiones_distintas_no_se_enlazan`<br>`test_lineage.py` → `test_rol_sin_permiso_de_reportes_es_rechazado` |

### Evaluación

| ID | Control técnico | Componente del sistema | HIPAA (45 CFR) | Ley 1581/2012 | Evidencia (HU · prueba automatizada) |
|---|---|---|---|---|---|
| CT-32 | Pruebas automáticas de ataque simulado contra los controles anteriores | `tests/test_ataques_simulados.py`<br>`docs/validacion_resultados.md` | §164.308(a)(8) | Art. 17 lit. d | **HU-6.5**<br>`test_ataques_simulados.py` → `test_delete_directo_es_bloqueado_y_queda_registrado`<br>`test_ataques_simulados.py` → `test_evento_firmado_con_otra_llave_es_rechazado` |


## 5. Cobertura por cláusula

El asterisco (*) marca un control de apoyo, que contribuye a la cláusula pero no la satisface por sí solo.

| Cláusula | Controles que la cubren |
|---|---|
| §164.306(a)(1) | CT-19 |
| §164.308(a)(1)(ii)(D) | CT-11, CT-14, CT-15, CT-18, CT-28, CT-29, CT-30 |
| §164.308(a)(3)(ii)(B) | CT-10 |
| §164.308(a)(3)(ii)(C) | CT-06 |
| §164.308(a)(4)(ii)(B) | CT-09 |
| §164.308(a)(4)(ii)(C) | CT-10 |
| §164.308(a)(5)(ii)(C) | CT-04, CT-05 |
| §164.308(a)(5)(ii)(D) | CT-01 (parcial, ver brecha B5) |
| §164.308(a)(6)(ii) | CT-05, CT-15, CT-28 |
| §164.308(a)(7)(ii)(A) | CT-27* |
| §164.308(a)(8) | CT-32 |
| §164.312(a)(1) | CT-04, CT-06, CT-08, CT-09 |
| §164.312(a)(2)(i) | CT-02, CT-16 |
| §164.312(a)(2)(iii) | **Sin control**: ver brecha B1 |
| §164.312(a)(2)(iv) | **Sin control**: ver brecha B2 |
| §164.312(b) | CT-11, CT-12, CT-13, CT-14, CT-15, CT-16, CT-17, CT-18, CT-19, CT-21, CT-27, CT-31 |
| §164.312(c)(1) | CT-13, CT-20, CT-21, CT-23, CT-26, CT-31 |
| §164.312(c)(2) | CT-20, CT-22, CT-23 |
| §164.312(d) | CT-01, CT-03, CT-04, CT-06, CT-07, CT-08, CT-22, CT-25 |
| §164.312(e)(1) | CT-24, CT-25 |
| §164.312(e)(2)(i) | CT-22, CT-26 |
| §164.312(e)(2)(ii) | CT-24 |
| §164.316(b)(1) | CT-30 |
| §164.502(b) | CT-09 |
| §164.528 | CT-14* |
| Ley 1581 Art. 4 lit. d | CT-13, CT-26, CT-31 |
| Ley 1581 Art. 4 lit. f | CT-09, CT-14 |
| Ley 1581 Art. 4 lit. g | CT-01, CT-02, CT-03, CT-04, CT-06, CT-07, CT-08, CT-19, CT-24 |
| Ley 1581 Art. 4 lit. h | CT-03, CT-25 |
| Ley 1581 Art. 17 lit. d | CT-01, CT-02, CT-04, CT-05, CT-06, CT-07, CT-08, CT-10, CT-11, CT-15, CT-18, CT-20, CT-21, CT-22, CT-23, CT-24, CT-25, CT-27, CT-32 |
| Ley 1581 Art. 17 lit. m | CT-12, CT-13, CT-14, CT-16, CT-17, CT-29, CT-30, CT-31 |
| Ley 1581 Art. 17 lit. n | CT-05, CT-15, CT-28 (detección; el reporte a la SIC es un procedimiento de la institución) |
| Ley 1581 Art. 18 lit. b | CT-20, CT-21, CT-22, CT-23, CT-27 |
| Ley 1581 Art. 18 lit. j | CT-06, CT-09, CT-10 |

## 6. Brechas y recomendaciones

El levantamiento encontró las siguientes brechas. Ninguna invalida los controles de la sección 4, pero un auditor debe conocerlas. Para las especificaciones direccionables de HIPAA, esta tabla es además la documentación de la decisión que exige la norma.

| ID | Brecha | Cláusula afectada | Recomendación |
|---|---|---|---|
| B1 | El dashboard no cierra la sesión por inactividad: la cookie dura hasta que se cierra el navegador (no hay `PERMANENT_SESSION_LIFETIME`). | §164.312(a)(2)(iii) (D) | Marcar la sesión como permanente con una vigencia corta (p. ej. 15 minutos) y renovarla con cada petición. |
| B2 | Las bases SQLite local y central no están cifradas en reposo. | §164.312(a)(2)(iv) (D); Art. 4 lit. g | Cifrar el volumen del servidor o usar SQLCipher. Tiene menor urgencia porque la bitácora no guarda valores clínicos, solo metadatos. |
| B3 | Los tokens personales se guardan en claro en `tokens_acceso.token`. Quien lea la base central puede suplantar a cualquier usuario hasta que el token venza. | §164.312(d); Art. 17 lit. d | Guardar solo el SHA-256 del token y comparar contra ese hash, como se hace con las contraseñas. |
| B4 | La llave privada `.audit_keys/private_key.pem` está versionada en el repositorio desde el commit `0a78971` (HU-6.1) y el espejo de GitHub es público. El código actual no la usa (las llaves viven en `~/.audit_tracer/keys`). | §164.312(c)(2); Art. 17 lit. d | Retirarla del repositorio, agregar `.audit_keys/` a `.gitignore` y tratarla como comprometida: ninguna firma hecha con ella prueba autoría. |
| B5 | La única regla de contraseñas es una longitud mínima de 8 caracteres, y solo en el formulario del dashboard (`app.py`); `register_user()` no valida nada. No hay rotación ni historial. | §164.308(a)(5)(ii)(D) (D) | Validar la política en `register_user()` para que aplique a cualquier origen, y definir complejidad mínima. |
| B6 | No hay un procedimiento para desbloquear una cuenta (CT-04): una cuenta bloqueada solo se reactiva editando la base. | §164.308(a)(4)(ii)(C) | Agregar el desbloqueo en la administración de usuarios, restringido a ADMIN y registrado en `audit_log`. |
| B7 | No hay una política de retención ni de archivado de `audit_log`. Los triggers impiden borrar, pero no se definió un plazo de conservación. | §164.316(b)(2)(i); Art. 17 lit. d | Definir el plazo con la institución (HIPAA conserva la documentación 6 años) y un procedimiento de archivado que preserve hashes y anclajes Merkle. |
| B8 | La gestión de roles (`assign_role`, incluida la protección del último ADMIN) no tiene pruebas automatizadas propias: la evidencia de CT-10 cubre solo el alta y el bloqueo de escalada. | §164.308(a)(4)(ii)(C) | Agregar pruebas de `assign_role` en `tests/` y citarlas en CT-10. |
| B9 | El hash por evento no tiene clave: quien controla la máquina puede alterar un evento local, recalcular el hash y volver a firmar con la llave local (HU-6.5). | §164.312(c)(1) | Riesgo residual. Lo mitigan la copia en la base central (CT-27) y el anclaje Merkle externo (CT-23), que detecta modificaciones y eliminaciones después de publicar el lote. |
| B10 | Las cuentas de demostración (`SEED_DEMO_DATA=1`) tienen contraseñas publicadas en el repositorio. | §164.312(d) | No activar el seed en un despliegue que reciba datos reales. |

## 7. Revisión del equipo

La DoD exige que el equipo revise la matriz. Cada integrante verifica que las filas de sus HU sean correctas, que las pruebas citadas demuestren el control y que las brechas sean conocidas.

| Integrante | HU revisadas | Fecha | Aprobado / Observaciones |
|---|---|---|---|
| | | | |
| | | | |
| | | | |

## 8. Reutilización en HU-7.3

HU-7.3 debe leer la matriz desde [`matriz_trazabilidad_normativa.csv`](matriz_trazabilidad_normativa.csv), no desde este documento. El CSV usa UTF-8, separa columnas con coma y separa los valores de una misma celda con `;`.

| Columna | Contenido |
|---|---|
| `id` | Identificador estable del control (`CT-01` … `CT-32`) |
| `categoria` | Agrupación de la sección 4 |
| `control_tecnico` | Descripción del control |
| `componente` | Archivos (y funciones o rutas) que lo implementan |
| `hipaa` | Cláusulas de 45 CFR Parte 164 |
| `ley_1581` | Artículos y literales de la Ley 1581 de 2012 |
| `hu` | Historias de usuario que lo implementaron |
| `eventos_audit_log` | Valores de `tipo_accion` que el control genera |
| `evidencia` | Pruebas, con el formato `archivo::Clase::prueba` de pytest |

Para anotar un reporte con su base normativa, HU-7.3 puede cruzar el `tipo_accion` de cada evento con `eventos_audit_log`. Por ejemplo, un `ACCESO_FALLIDO` lleva a CT-03, CT-04, CT-05 y CT-15, y de ahí a §164.308(a)(5)(ii)(C), §164.308(a)(6)(ii) y Art. 17 lit. d.

Si se agrega un control, hay que actualizar el CSV y este anexo en el mismo cambio. `tests/test_matriz_normativa.py` verifica que ambos queden sincronizados.
