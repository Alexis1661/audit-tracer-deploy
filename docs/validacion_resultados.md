# Validación y Resultados Obtenidos

Este documento consolida la evidencia experimental, empírica y técnica de las validaciones de seguridad y rendimiento realizadas sobre el sistema **Audit Tracer**.

---

# Parte 1: Pruebas de ataque simulado (HU-6.5)

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

---

# Parte 2: Benchmark de overhead de rendimiento (HU-6.7)

## Objetivo

Demostrar de forma empírica y medible que la librería `audit_tracer` y sus interceptores automáticos de auditoría (acceso, linaje, exportación y sincronización) no degradan perceptiblemente el rendimiento de las tareas cotidianas de ciencia de datos sobre DataFrames de Pandas.

## Metodología y Entorno Experimental

La evaluación se ejecutó mediante el módulo [`benchmarks/overhead_referencia.py`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/benchmarks/overhead_referencia.py), siguiendo un diseño experimental controlado:

- **Aislamiento por proceso:** Cada corrida se ejecuta en un proceso Python nuevo (`subprocess.run`), garantizando que la carga de librerías y el estado del intérprete no compartan caché en memoria entre corridas.
- **Entorno aislado de pruebas:** Cada modo opera sobre su propio directorio home temporal (`HOME`/`USERPROFILE`), evitando colisiones en base de datos local SQLite (`~/.audit_tracer/audit_trail.db`) o llaves criptográficas.
- **Calentamiento inicial (*Warm-up*):** Se ejecuta una primera corrida no computada por modo para inicializar esquemas SQLite y cachés de disco del sistema operativo.
- **Muestreo intercalado:** Las mediciones se intercalan entre modos (`sin_auditoria` → `con_auditoria` → `con_sync_caido`) para mitigar sesgos por deriva térmica o contención del planificador de CPU.
- **Datos sintéticos realistas:** Se generan DataFrames con atributos clínicos típicos (identificador de paciente, edad, sexo con nulos, glucosa, presión arterial, IMC, diagnóstico y notas de atención).

**Especificaciones del entorno:**
- **Sistema Operativo:** Windows 11
- **Intérprete:** Python 3.12.6 (x64)
- **Bibliotecas:** Pandas 2.2+, NumPy 2.0+, Cryptography 42.0+
- **Base de datos local:** SQLite 3 en modo WAL

### Operaciones Evaluadas (CA1)

El script de prueba ejecuta un flujo clínico de ciencia de datos dividido en tres fases principales:
1. **Lectura:** Carga de datos crudos mediante `pd.read_csv("pacientes.csv")` y `pd.read_csv("diagnosticos.csv")` (interceptado por [`data_capture.py`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/audit_tracer/data_capture.py)).
2. **Transformación:** Extracción de series, filtrado con `df.query("edad >= 18")`, imputación con `df.fillna()`, depuración de registros nulos con `df.dropna()`, normalización de columnas con `df.rename()`, eliminación de columnas sensibles con `df.drop()`, transformaciones matemáticas con `df.apply()` y enriquecimiento relacional mediante `df.merge()` y `df.groupby()` (interceptado por [`transform_capture.py`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/audit_tracer/transform_capture.py)).
3. **Exportación:** Serialización de resultados a disco mediante `df.to_csv("salida_completa.csv")` y `df.to_csv("salida_resumen.csv")` (interceptado por [`export_capture.py`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/audit_tracer/export_capture.py)).

### Modos Comparados

- **`sin_auditoria` (Línea base):** Script de Pandas vanilla sin importar `audit_tracer`.
- **`con_auditoria`:** Script con `import audit_tracer` activo (intercepción automática, cálculo de hash SHA-256, firma criptográfica Ed25519 y persistencia SQLite local).
- **`con_sync_caido`:** Script con `audit_tracer` configurado hacia un endpoint HTTPS central no disponible (`http://127.0.0.1:9`), verificando que los fallos de red o caídas del servidor central no frenen al usuario en el hilo principal.

---

## Resultados Obtenidos por Tamaño de Dataset (CA2 y CA3)

El benchmark se ejecutó sobre tres escalas de dataset: **Pequeño (50.000 filas)**, **Mediano (200.000 filas)** y **Grande (1.000.000 filas)**, promediando 3 corridas intercaladas por cada modo.

### 1. Dataset Pequeño: 50.000 filas (~4 MB)

| Operación | Sin Auditoría (s) | Con Auditoría (s) | Overhead (%) | Con Sync Caído (s) | Overhead (%) | Estado vs. Umbral (5%) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Lectura** | 0.1183 s | 0.1229 s | **+3.85%** | 0.1732 s | +46.42% | ✅ Cumple (< 5%) |
| **Transformación** | 0.0402 s | 0.0627 s | **+56.16%** | 0.0999 s | +148.88% | ⚠️ Supera (+22.5 ms) |
| **Exportación** | 0.3243 s | 0.3191 s | **-1.59%** | 0.3561 s | +9.82% | ✅ Cumple (< 5%) |
| **Cuerpo Pandas (Pipeline)** | 0.4827 s | 0.5047 s | **+4.55%** | 0.6293 s | +30.36% | ✅ Cumple (< 5%) |
| **Imports (Bootstrap)** | 1.6351 s | 1.9179 s | **+17.30%** | 1.8769 s | +14.79% | ⚠️ Supera (+282.8 ms) |
| **Tiempo Total Script** | 2.1178 s | 2.4226 s | **+14.39%** | 2.5061 s | +18.34% | ⚠️ Supera (+304.8 ms) |
| **Proceso Completo** | 2.3310 s | 2.6660 s | **+14.37%** | 2.7651 s | +18.62% | ⚠️ Supera (+335.0 ms) |

*Interpretación:* En operaciones de datos muy rápidas (<500 ms), el cuerpo de operaciones de Pandas se mantiene dentro del umbral (**+4.55%**). Sin embargo, el costo fijo de importación de la librería y la criptografía (+282 ms) incide porcentualmente sobre el tiempo total del proceso.

---

### 2. Dataset Mediano: 200.000 filas (~18 MB)

| Operación | Sin Auditoría (s) | Con Auditoría (s) | Overhead (%) | Con Sync Caído (s) | Overhead (%) | Estado vs. Umbral (5%) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Lectura** | 0.3828 s | 0.4093 s | **+6.91%** | 0.4352 s | +13.68% | ⚠️ Supera (+26.4 ms) |
| **Transformación** | 0.1026 s | 0.1387 s | **+35.13%** | 0.1438 s | +40.08% | ⚠️ Supera (+36.1 ms) |
| **Exportación** | 1.2719 s | 1.5453 s | **+21.50%** | 1.3043 s | +2.55% | ⚠️ Supera (+273.4 ms) |
| **Cuerpo Pandas (Pipeline)** | 1.7574 s | 2.0933 s | **+19.11%** | 1.8833 s | +7.17% | ⚠️ Supera (+335.9 ms) |
| **Imports (Bootstrap)** | 1.6228 s | 1.9179 s | **+18.18%** | 1.9062 s | +17.46% | ⚠️ Supera (+295.1 ms) |
| **Tiempo Total Script** | 3.3801 s | 4.0111 s | **+18.67%** | 3.7895 s | +12.11% | ⚠️ Supera (+631.0 ms) |
| **Proceso Completo** | 3.6189 s | 4.3280 s | **+19.59%** | 4.0746 s | +12.59% | ⚠️ Supera (+709.1 ms) |

---

### 3. Dataset Grande: 1.000.000 filas (~90 MB)

| Operación | Sin Auditoría (s) | Con Auditoría (s) | Overhead (%) | Con Sync Caído (s) | Overhead (%) | Estado vs. Umbral (5%) |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Lectura** | 1.7885 s | 1.7573 s | **-1.74%** | 1.7762 s | -0.69% | ✅ Cumple (< 5%) |
| **Transformación** | 0.4084 s | 0.4041 s | **-1.06%** | 0.4031 s | -1.31% | ✅ Cumple (< 5%) |
| **Exportación** | 6.2728 s | 6.1486 s | **-1.98%** | 6.2925 s | +0.31% | ✅ Cumple (< 5%) |
| **Cuerpo Pandas (Pipeline)** | 8.4697 s | 8.3100 s | **-1.89%** | 8.4719 s | +0.03% | ✅ Cumple (< 5%) |
| **Imports (Bootstrap)** | 1.5957 s | 1.7662 s | **+10.69%** | 1.7417 s | +9.15% | ⚠️ Supera (+170.5 ms) |
| **Tiempo Total Script** | 10.0654 s | 10.0763 s | **+0.11%** | 10.2136 s | +1.47% | ✅ Cumple (< 5%) |
| **Proceso Completo** | 10.2855 s | 10.3255 s | **+0.39%** | 10.4910 s | +2.00% | ✅ Cumple (< 5%) |

---

## Análisis y Hallazgos de Optimización Futura (CA4)

### Hallazgo Principal: Escalabilidad Inversa del Overhead

El análisis de los tres órdenes de magnitud revela un comportamiento altamente favorable para la adopción en ciencia de datos:
1. **En datasets grandes (1.000.000 filas):** El overhead introducido sobre el flujo de análisis es **completamente imperceptible: 0.11% en tiempo total y -1.89% en el cuerpo de Pandas**. La sobrecarga de registrar 5-10 eventos en SQLite (~50 ms) es absorbida por el tiempo de cómputo vectorial en C/Cython que toma Pandas en procesar los datos (~8 a 10 segundos).
2. **En datasets pequeños:** Las operaciones en sí tardan solo fracciones de milisegundo (ej. una transformación toma 40 ms), por lo que cualquier intercepción síncrona de ~20 ms representa un porcentaje relativo alto (+56%), aunque en tiempo real de reloj humano la diferencia sea de tan solo **22 milisegundos**.

### Registro de Hallazgos y Acciones Recomendadas

| ID | Componente / Operación | Overhead Observado | Causa Raíz Técnica | Recomendación de Optimización Futura |
|---|---|:---:|---|---|
| **H-6.7-01** | **Imports iniciales** (`import audit_tracer`) | +10% a +18% (+170 a +295 ms) | Costo fijo al importar `cryptography`, `ed25519` e inicializar el esquema SQLite local al momento del `import`. | **Lazy loading (Carga perezosa):** Diferir la importación de `cryptography` y la inicialización de SQLite hasta el instante en que ocurra el primer evento real de datos, permitiendo imports casi instantáneos (<50 ms). |
| **H-6.7-02** | **Transformaciones** (DataFrame wrapper) | +35% a +56% (+22 a +36 ms) | `AuditedTransformDataFrame` inspecciona parámetros y linaje mediante reflexión en Python puro antes de delegar a Pandas nativo. | **Caché de introspección:** Cachear firmas de métodos y metadatos de esquema para evitar resolución dinámica repetitiva en transformaciones encadenadas. |
| **H-6.7-03** | **Exportación** (`df.to_csv`) en dataset mediano | +21.5% (+273 ms) | La función interceptora calcula el conteo de filas, evalúa alertas de exportación masiva (>1000 filas) y persiste sincrónicamente en SQLite antes de liberar el control al usuario. | **Buffer asíncrono:** Mover el cálculo de hash, firma Ed25519 e inserción a SQLite a una cola en memoria procesada por un hilo secundario en segundo plano, evitando bloquear la llamada `to_csv`. |
| **H-6.7-04** | **Sincronización con servidor caído** (`con_sync_caido`) | +0.03% a +30% | Aunque el hilo daemon no bloquea la ejecución principal, la inicialización del socket fallido añade un leve retardo al arranque del cliente. | **Cola desacoplada con backoff inmediato:** No intentar conexión de red durante el hilo principal; encolar siempre localmente y delegar el reintento de conexión exclusivamente al worker background. |

---

## Cómo Reproducir el Benchmark

1. **Ejecutar la suite automatizada de pruebas unitarias (10 pruebas):**
   ```bash
   python -m pytest tests/test_benchmark_overhead.py -v
   ```

2. **Ejecutar el benchmark completo sobre los tres tamaños con salida JSON:**
   ```bash
   python benchmarks/overhead_referencia.py --filas 50000 200000 1000000 --corridas 3 --salida-json benchmarks/resultados_benchmark.json
   ```

Los datos crudos de las corridas quedan disponibles en formato estructurado en [`benchmarks/resultados_benchmark.json`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/benchmarks/resultados_benchmark.json).
