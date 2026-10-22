# Validación y Resultados Obtenidos — Pruebas de ataque simulado (HU-6.5)

## Objetivo

Comprobar que los mecanismos de seguridad funcionan ante un atacante, no solo en el caso ideal. Cada prueba actúa como un atacante:

- escribe directo en el archivo SQLite,
- se salta la interfaz web,
- forja cookies de sesión,
- reutiliza tokens dados de baja, o
- envía eventos con la firma alterada.

Cada prueba verifica que el sistema **detecta o bloquea** el intento y que deja constancia en `audit_log`.

## Cómo reproducirlo

```bash
python -m pytest tests/test_ataques_simulados.py -v
```

Las pruebas son automáticas y se ejecutan con el resto de la suite. Usan una base central temporal y el dashboard Flask real (cliente de pruebas de Flask), sin datos de producción.

**Ejecución registrada:**

- **Fecha:** 22/10/2026
- **Entorno:** Python 3.12, Flask 3.1.0, pandas 3.0.2, Windows 11
- **Resultado:** 32 de 32 casos superados; suite completa 491/491

## Resultados por criterio

| CA | Ataque simulado | Mecanismo que responde | Resultado esperado | Resultado obtenido |
|---|---|---|---|---|
| CA1 | `UPDATE` directo sobre `audit_log` con `sqlite3`, sin pasar por la aplicación | Trigger `trg_audit_log_no_update` (HU-5.4/3.3) | Rechazado y registrado | Rechazado ("INMUTABILIDAD"); queda `INTENTO_MODIFICACION` en `audit_intentos_bloqueados`; el valor no cambia |
| CA1 | `DELETE` directo | Trigger `trg_audit_log_no_delete` | Rechazado y registrado | Rechazado; queda `INTENTO_ELIMINACION`; no se borra ninguna fila |
| CA1 | El atacante borra los triggers y altera `usuario_id`, `nivel_alerta`, `filas_exportadas`, `timestamp`, `tipo_accion` o `ruta_destino` (6 casos) | `verify_integrity()` (SHA-256 por evento) | Detectado | Detectado en los 6 casos: solo el evento alterado aparece, con hash guardado ≠ hash recalculado |
| CA1 | El atacante altera el evento **y recalcula el SHA-256** | Firma Ed25519 (`verify_signature()`, HU-6.1) | Detectado | `verify_integrity()` no lo detecta (límite, ver abajo); la firma sí: `firma_valida = False` |
| CA2 | `CIENTIFICO_DATOS` entra a `/eventos` (módulo `consulta_reportes`) | `modulo_required` (HU-1.4) | Bloqueado y registrado | HTTP 403; `ACCESO_DENEGADO` en `audit_log` |
| CA2 | `ANALISTA` hace POST a `/admin/usuarios/nuevo` para crearse un `ADMIN` | `admin_required` | Bloqueado y registrado | Redirección al dashboard; el usuario no se crea; `ACCESO_DENEGADO` con `Método: POST` *(antes no se registraba, corregido)* |
| CA2 | `ANALISTA` genera un token a nombre de otro usuario (`/admin/tokens/nuevo`) | `admin_required` | Bloqueado y registrado | No se crea el token; `ACCESO_DENEGADO` *(corregido)* |
| CA2 | Cookie de sesión forjada con `rol=ADMIN` | Clave de sesión de Flask | Rechazada | Tratada como sesión inexistente: redirige a `/login` *(antes era explotable, corregido)* |
| CA2 | Acceso a administración sin sesión | `login_required` | Bloqueado | Redirige a `/login` |
| CA3 | Reutilizar un token después de revocarlo | `validar_token()` (HU-5.5) | Rechazado | El mismo token funciona (201) y, tras revocarlo, la siguiente petición da HTTP 401 "Token revocado"; el evento no se guarda; queda `SINCRONIZACION_RECHAZADA` |
| CA3 | Token expirado | `validar_token()` | Rechazado | HTTP 401 "Token expirado"; el token queda marcado `EXPIRADO` |
| CA3 | Token alterado en un carácter, inventado o ausente (3 casos) | `validar_token()` | Rechazado | HTTP 401 en los 3 casos; queda registrado el rechazo |
| CA3 | Consultar `/api/tokens/validar` con un token revocado | `validar_token()` | Inválido | HTTP 401, `valido = false` |
| CA4 | Firmar un evento y luego alterar `filas_exportadas`, `nivel_alerta`, `dataset_nombre`, `timestamp` o `ruta_destino` (5 casos) | Verificación de firma en `/api/eventos/sincronizar` (HU-6.1) | Rechazado | HTTP 422 en los 5 casos; no se guarda; `FIRMA_INVALIDA` (CRITICO) |
| CA4 | Evento firmado con la llave del atacante | Verificación de firma | Rechazado | HTTP 422; `FIRMA_INVALIDA` |
| CA4 | Firma basura (3 formatos) | Verificación de firma | Rechazado | HTTP 422 en los 3 casos |
| CA4 | Quitarle la firma a un evento manipulado (degradación) | Firma obligatoria si el usuario tiene llave registrada | Rechazado | HTTP 422; `FIRMA_INVALIDA` "evento sin firma" *(antes se aceptaba, corregido)* |
| CA4 | Reenviar (replay) un evento válido capturado en tránsito | Idempotencia por `evento_uuid` (HU-5.6) | Sin duplicado | HTTP 200 "duplicado"; una sola fila |
| — | Control: evento firmado correctamente | — | Aceptado | HTTP 201 |

## Vulnerabilidades encontradas y corregidas

Las pruebas encontraron tres fallas reales. Para confirmar que las pruebas detectan cada falla, se ejecutaron contra el código anterior a las correcciones: fallan exactamente los 4 casos correspondientes. Con las correcciones, los 32 casos pasan.

1. **Clave de sesión fija en el código (crítica).**
   - **Problema:** `app.secret_key` era una constante en `app.py`, y el repositorio espejo de GitHub es público. Con esa clave cualquiera podía firmar una cookie con `rol=ADMIN` y entrar a la administración del dashboard desplegado.
   - **Corrección:** la clave se lee de la variable de entorno `SECRET_KEY`. Si no está definida, se genera una aleatoria por proceso.
   - **Acción pendiente en el despliegue:** definir `SECRET_KEY` en Railway (ver recomendaciones).
2. **Intentos de escalada de privilegios sin rastro.**
   - **Problema:** `admin_required` bloqueaba el acceso pero no registraba nada. Un analista podía intentar crear un ADMIN o emitir tokens ajenos sin dejar evidencia.
   - **Corrección:** ahora registra `ACCESO_DENEGADO`, con el módulo, la ruta y el método HTTP.
3. **Degradación de firma.**
   - **Problema:** el servidor aceptaba eventos sin firma por compatibilidad. Bastaba con quitarle la firma a un evento manipulado para que se aceptara.
   - **Corrección:** si el usuario dueño del token tiene una llave pública registrada, todos sus eventos deben venir firmados.

## Límites conocidos y recomendaciones

- **Hash recalculado.** `hash_integridad` es un SHA-256 sin clave: un atacante que conoce el algoritmo puede alterar un evento y recalcular el hash. La alteración la detecta la firma Ed25519 si el atacante no tiene la llave privada. Sin embargo, la llave vive en el mismo equipo (`~/.audit_tracer/keys` o `.audit_keys`), así que un atacante con control total de la máquina podría también volver a firmar.
  - **Defensa efectiva hoy:** la copia sincronizada en la base central, que el cliente no puede modificar.
  - **Recomendación:** comparar periódicamente la base local con la central por `evento_uuid` y `hash_integridad`, o encadenar los hashes (cada evento incluye el hash del anterior).
- **Eliminación sin triggers.** Si el atacante borra los triggers y luego elimina filas, `verify_integrity()` no lo nota, porque solo revisa las filas que existen. La misma comparación con la base central, o la cadena de hashes, lo cubriría.
- **Despliegue de demostración.** Las cuentas de demo (`SEED_DEMO_DATA=1`) tienen contraseñas publicadas en el repositorio. Sirven para la demo, pero ese despliegue no debe recibir datos reales.
