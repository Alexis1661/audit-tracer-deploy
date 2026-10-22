# Audit Tracer — Guía de instalación y uso

Audit Tracer registra automáticamente qué datos clínicos se cargan, consultan, transforman y exportan en un notebook o script de Python, y quién lo hizo. **No tienes que modificar tu código: basta con una línea al inicio.**

## 1. Instalación

En Google Colab o en tu máquina:

```bash
pip install "git+https://github.com/Alexis1661/audit-tracer-deploy.git"
```

Esa es la copia pública que se usa para las demos. Desde el repositorio del proyecto en Bitbucket (requiere credenciales):

```bash
pip install "git+https://<usuario>@pi2tools.icesi.edu.co/bitbucket/scm/pdgtrazdsa/trazauditdsalud.git"
```

Para leer o escribir Excel o Parquet, agrega los extras: `pip install "audit-tracer[excel,parquet] @ git+https://..."`.

## 2. Activación: una sola línea

Pon esto como **primera línea** del notebook o script, antes de cualquier otro import:

```python
import audit_tracer
```

Con eso queda activa toda la captura. El resto del código sigue igual: `pd.read_csv`, `df["columna"]`, `df.query`, `fillna`, `dropna`, `drop`, `rename`, `apply`, `merge`, `to_csv`, etc.

> Ponlo antes de `from pandas import read_csv`. Una función importada por nombre *antes* de `audit_tracer` no queda interceptada.

## 3. Identificarte (una vez)

```python
audit_tracer.login(api_url="https://audit-tracer-production.up.railway.app")
```

1. Se imprime un código y una URL. Ábrela, inicia sesión en el dashboard y confirma el código.
2. El token queda guardado. Los siguientes `import audit_tracer` te identifican solos, sin pedir nada ni usar la red.

**Dónde queda guardado el token:**

- **Colab:** monta Drive **antes** del import (`from google.colab import drive; drive.mount('/content/drive')`). El token se guarda en Drive y sobrevive al cierre de la sesión. Sin Drive, hay que repetir el login en cada sesión nueva.
- **Scripts `.py`:** ejecuta el login una vez de forma interactiva. Desde ahí los scripts se identifican solos:

  ```bash
  python -c "import audit_tracer; audit_tracer.login(api_url='https://...')"
  ```

**Si no te identificas,** todo se registra igual, pero como `DESCONOCIDO` y con nivel CRITICO. Verás este aviso:

> `[AuditTracer] La auditoría está activa, pero no hay un usuario identificado...`

Si haces `login()` más tarde en la misma sesión, se agrega un evento `ATRIBUCION_SESION` que liga esos eventos previos a tu usuario. Los registros originales no se modifican: la bitácora es inmutable.

## 4. Verificar que está auditando

```python
audit_tracer.sync_status()
# [AuditTracer] Sincronización: 12 sincronizados · 0 pendientes · 0 con error
```

- Los eventos aparecen en el dashboard, en **Eventos**. Cada uno indica script o celda, entorno (`Script (.py)`, `Jupyter` o `Google Colab`) y host.
- Si no hay conexión, los eventos se guardan localmente (`~/.audit_tracer/audit_trail.db`). Se envían solos cuando vuelve la conexión, o en la próxima sesión. `audit_tracer.sync_now()` fuerza el envío.

| Operación | Evento |
|---|---|
| `pd.read_csv`, `pd.read_excel` | `CARGA` |
| `df["col"]`, `df.query(...)` | `CONSULTA` |
| `fillna`, `dropna`, `drop`, `rename`, `apply`, `merge`, `pd.merge` | `TRANSFORMACION` |
| `to_csv`, `to_excel`, `to_json`, `to_parquet` | `EXPORTACION` (> 1000 filas: CRITICO) |
| Archivo inexistente o sin permiso | `ACCESO_FALLIDO` (> 3 en 5 min: CRITICO) |
| Inicio y fin del notebook o script | `INICIO_SESION`, `CIERRE_SESION` |

## 5. Garantías y límites

- **Tu código nunca se detiene por la auditoría.** Si la librería falla internamente, tu operación de pandas se ejecuta igual. El error queda en `~/.audit_tracer/errores_sistema.log`, nunca en la bitácora.
- **Tus propios errores te llegan intactos.** Un archivo inexistente lanza el mismo `FileNotFoundError` de siempre, y además queda registrado como intento fallido.
- **No se espera al servidor.** El envío ocurre en segundo plano. Con el servidor caído, el script no se frena. Al cerrar, como máximo espera 2 s a que se envíe lo pendiente, y nada si el servidor no respondió en toda la sesión.
- **No hay interruptor para apagarla.** Desactivar un interceptor queda registrado como evento CRITICO `AUDITORIA_DESACTIVADA`.
- **Qué no se audita:**
  - Los DataFrames construidos a mano (`pd.DataFrame(...)`) sí registran sus exportaciones, pero no sus consultas ni transformaciones. Envuélvelos con `audit_tracer.data_capture.wrap_audited(df, "nombre")` si deben auditarse.
  - Los datos leídos por fuera de pandas (por ejemplo, con `open()` directamente) no se registran.
