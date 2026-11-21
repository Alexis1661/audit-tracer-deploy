---
titulo: Guía de instalación y despliegue
anexo: Anexo 16 · HU-5.3
fecha: 2026-11-21
---

[TOC]

# 0. Procedencia y verificación

Parte de `docs/guia_instalacion.md` (commit `b13459e`, 03/11/2026, HU-5.3) y `docs/guia_instalacion_uso.md` (commit `2311330`, 22/10/2026). Se revisó contra el código del commit `31361a3` el 21/11/2026.

| Sección | Verificación del 21/11/2026 | Resultado |
|---|---|---|
| Instalación local (sección 3) | Copia limpia del commit (`git archive`), `python scratch/seed_admin.py`, `python app.py`, login como admin, `/dashboard` y `/reportes/exportar/pdf` | **Funciona.** El seed imprime un UUID, no `usr_…` como decía la guía. |
| Ejemplo mínimo (sección 7) | Se ejecutó el script de la guía original en un HOME aislado | **No coincidía**: la guía mostraba 4 eventos NORMAL y una consulta a `audit_trail.db` en la carpeta actual. La salida real es de 8 eventos, todos CRITICO por usuario no identificado, y la base está en `~/.audit_tracer/` (el comando del Paso 4 original falla con `no such table: audit_log`). Corregido abajo con la salida real. |
| Render (sección 5.1) | Es el despliegue que se usó en la validación externa del 20/11/2026 (`render.yaml`, plan gratuito) | Funciona; disco efímero (ver advertencias). |
| Railway (sección 5.1) | No se verificó: el periodo de prueba de la cuenta terminó antes de la migración a Render. | [PENDIENTE: verificación en Railway] |
| Linux con Nginx y systemd (sección 4) | No se ejecutó en esta revisión (el equipo de verificación es Windows) | [PENDIENTE: prueba en un servidor Linux]. Se corrigieron dos problemas visibles en el código (siembra y job de Merkle bajo Gunicorn). |

# 1. Arquitectura

* **Librería `audit_tracer`** (equipo del científico de datos: Jupyter, Colab o scripts). Intercepta pandas, guarda cada evento firmado en `~/.audit_tracer/audit_trail.db` y lo sincroniza por HTTPS en un hilo de fondo.
* **Servidor central** (`app.py`, Flask): API de ingesta `POST /api/eventos/sincronizar` (token Bearer, verificación de firma, idempotencia por `evento_uuid`), dashboard web y base `audit_central.db` (SQLite WAL con disparadores de inmutabilidad), creada junto a `app.py`.

# 2. Dependencias

Python ≥ 3.10 (verificado con 3.12.6). SQLite viene con Python.

| Paquete | Versión mínima | Para qué | Dónde se declara |
|---|---|---|---|
| pandas | 2.0 | Interceptores (verificado con 3.0.2) | `requirements.txt`, `pyproject.toml` (núcleo) |
| requests | 2.31 | Sincronización y login por dispositivo | ambos (núcleo) |
| cryptography | 42.0 | Firmas Ed25519 | ambos (núcleo) |
| bcrypt | 4.0 | Contraseñas | ambos (núcleo) |
| Flask | 2.3 | Servidor y dashboard (verificado con 3.1.0) | `requirements.txt`; extra `servidor` |
| reportlab | 4.0 | Reporte en PDF (agregado el 21/11/2026) | `requirements.txt`; extra `servidor` |
| openpyxl | 3.1 | Leer y exportar Excel | `requirements.txt`; extra `excel` |
| pyarrow | 14.0 | Exportar Parquet | `requirements.txt`; extra `parquet` |
| pytest, nbclient, nbformat, ipykernel, pypdf | — | Pruebas | `requirements.txt`; extra `dev` |
| APScheduler | — | Publicación horaria automática de raíces Merkle | **No está declarada.** Sin ella `start_scheduler()` no arranca y las anclas solo se publican a mano (sección 6.3). |
| gunicorn | — | Servidor WSGI en Linux | No está declarada; se instala aparte (sección 4) |

# 3. Instalación local

```bash
git clone https://pi2tools.icesi.edu.co/bitbucket/scm/pdgtrazdsa/trazauditdsalud.git
cd trazauditdsalud
python -m venv venv
# Windows: venv\Scripts\activate      Linux/macOS: source venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt          # servidor + librería + pruebas
# o, como paquete editable:  pip install -e ".[servidor,dev]"
```

Crear el administrador inicial en la base central (`audit_central.db`, junto a `app.py`):

```bash
python scratch/seed_admin.py
```

Salida real (21/11/2026):

```text
Intentando crear usuario admin: admin@audit.com...
¡Éxito! Usuario admin creado con ID: 00ecb12c-4679-4bd1-b457-4da081de13a9
Credenciales:
  Email: admin@audit.com
  Password: Admin123*
```

Arrancar el servidor:

```bash
python app.py            # http://localhost:5000  (FLASK_DEBUG=1 por defecto: no usar así en un servidor público)
```

Cambiar la contraseña de `admin@audit.com` antes de cualquier uso real: está publicada en el repositorio.

# 4. Servidor Linux con Nginx y systemd

> No probado en esta revisión. Los ajustes respecto a la guía original se derivan del código.

```bash
sudo mkdir -p /opt/audit-tracer && sudo chown $USER /opt/audit-tracer
git clone <repositorio> /opt/audit-tracer && cd /opt/audit-tracer
python3 -m venv venv && venv/bin/pip install -r requirements.txt gunicorn
venv/bin/python scratch/seed_admin.py
sudo chown -R www-data:www-data /opt/audit-tracer     # audit_central.db y merkle_anchors/ se escriben aquí
```

`/etc/systemd/system/audit-tracer.service`:

```ini
[Unit]
Description=Audit Tracer - servidor central
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/audit-tracer
Environment="SECRET_KEY=<cadena aleatoria larga, p. ej. openssl rand -hex 32>"
Environment="TRUST_PROXY_HEADERS=1"
Environment="FLASK_DEBUG=0"
Environment="AUDIT_DASHBOARD_URL=https://audit.institucion.edu.co"
Environment="AUDIT_SMTP_HOST=smtp.institucion.edu.co"
Environment="AUDIT_SMTP_USER=audit-tracer@institucion.edu.co"
Environment="AUDIT_SMTP_PASSWORD=<secreto>"
ExecStart=/opt/audit-tracer/venv/bin/gunicorn -w 2 -b 127.0.0.1:5000 --timeout 60 app:app
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now audit-tracer
```

**Diferencias con `python app.py` que hay que cubrir bajo Gunicorn** (el bloque `if __name__ == '__main__'` de `app.py` no se ejecuta):

* `SEED_USUARIOS` y `SEED_DEMO_DATA` no tienen efecto: crear las cuentas con `scratch/seed_admin.py` y desde el dashboard.
* El job horario de Merkle no arranca: programarlo con un temporizador (ver 6.3).
* `SECRET_KEY` es obligatoria: sin ella cada proceso de Gunicorn genera una clave distinta y las sesiones se pierden entre procesos.

`/etc/nginx/sites-available/audit-tracer` (HTTPS obligatorio: la API rechaza peticiones no seguras con 426):

```nginx
server {
    listen 80;
    server_name audit.institucion.edu.co;
    return 301 https://$host$request_uri;
}
server {
    listen 443 ssl http2;
    server_name audit.institucion.edu.co;
    ssl_certificate     /etc/letsencrypt/live/audit.institucion.edu.co/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/audit.institucion.edu.co/privkey.pem;
    client_max_body_size 2M;          # la app no limita el tamaño de petición (riesgo SRV-D1)
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;   # TRUST_PROXY_HEADERS=1 lo lee
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/audit-tracer /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload nginx
```

# 5. Plataformas en la nube

## 5.1 Render (usado en la validación externa)

`render.yaml` define un servicio web Python: `pip install -r requirements.txt`, arranque `python app.py`, chequeo de salud `/login`, `FLASK_DEBUG=0`, `TRUST_PROXY_HEADERS=1`, `SECRET_KEY` generada por Render y `SEED_DEMO_DATA=1`.

1. Render › New › Blueprint › conectar el repositorio (o el espejo de GitHub).
2. Agregar en Environment las variables de la sección 6 que se necesiten (`SEED_USUARIOS`, SMTP).
3. Cada push a la rama conectada redespliega.

**Advertencias.** En el plan gratuito el disco es efímero y el servicio se duerme tras unos 15 minutos sin tráfico: al reiniciar se pierden `audit_central.db` y `merkle_anchors/`. Sirve para demostraciones, no para conservar evidencia. `SEED_DEMO_DATA=1` crea cuentas con contraseñas publicadas (brecha B10): quitarla en cualquier despliegue con datos reales.

## 5.2 Railway

El `Procfile` (`web: python app.py`) permite desplegar en Railway con las mismas variables. Railway asigna `PORT`. [PENDIENTE: no verificado; la cuenta de prueba expiró en noviembre de 2026.]

## 5.3 Google Colab (científico de datos)

```python
from google.colab import drive
drive.mount("/content/drive")      # conserva token y llaves entre sesiones
!pip install --quiet "git+https://github.com/Alexis1661/audit-tracer-deploy.git"
import audit_tracer, pandas as pd
audit_tracer.login(api_url="https://<servidor>")   # código de dispositivo; solo la primera vez
```

# 6. Configuración

## 6.1 Variables de entorno del servidor

Lista completa de las que lee el código (`os.environ` / `os.getenv` en `app.py` y `audit_tracer/`):

| Variable | Valor por defecto | Para qué |
|---|---|---|
| `SECRET_KEY` | Aleatoria por proceso | Firma de la cookie de sesión. Obligatoria en producción. |
| `FLASK_DEBUG` | `1` | `0` en cualquier servidor accesible. |
| `PORT` | `5000` | Puerto de `python app.py`. |
| `TRUST_PROXY_HEADERS` | — | `1` detrás de un proxy con TLS (Nginx, Render) para aceptar `X-Forwarded-Proto`. |
| `SEED_DEMO_DATA` | — | `1` crea cuentas y datos de demostración al arrancar (`python app.py`). |
| `SEED_USUARIOS` | — | JSON `[{"email","password","rol"}]`: crea esas cuentas al arrancar (`python app.py`). |
| `START_MERKLE_SCHEDULER` | `1` | Intenta iniciar el job horario de Merkle (requiere APScheduler). |
| `AUDIT_MERKLE_ANCHORS_DIR` | `merkle_anchors/` junto al paquete | Carpeta de las anclas Merkle. |
| `AUDIT_DASHBOARD_URL` | URL de la primera petición | Base de los enlaces en los correos de alerta. |
| `AUDIT_SMTP_HOST`, `AUDIT_SMTP_PORT`, `AUDIT_SMTP_USER`, `AUDIT_SMTP_PASSWORD`, `AUDIT_SMTP_FROM` | — / 587 | Servidor de correo de las alertas (HU-7.2). |
| `AUDIT_SMTP_SSL`, `AUDIT_SMTP_STARTTLS`, `AUDIT_SMTP_TIMEOUT` | `0` / `1` / `10` | Opciones del canal SMTP. |
| `AUDIT_SMTP_TLS` | — | `implicit` para el comando `flask audit-email` (avisos del espacio de auditoría). |
| `AUDIT_ALERTAS_OUTBOX` | — | Sin SMTP: guarda cada correo como `.eml` en esa carpeta. |
| `AUDIT_ALERTAS_DESACTIVADAS` | — | `1` apaga el despachador de alertas (lo usan las pruebas). |
| `AUDIT_HORARIO_INICIO`, `AUDIT_HORARIO_FIN` | `8`, `18` | Horario laboral (hora Colombia) para marcar CRITICO las cargas fuera de horario. |

## 6.2 Variables de la librería

| Variable | Para qué |
|---|---|
| `AUDIT_TRACER_API_URL` | URL del servidor si no se pasa `api_url` a `audit_tracer.login()`. |
| `AUDIT_HORARIO_INICIO`, `AUDIT_HORARIO_FIN` | Las mismas del servidor: la regla de horario se evalúa en el equipo del analista. |

## 6.3 Publicación de anclas Merkle

Sin APScheduler, las raíces se publican a mano: dashboard › Integridad Merkle (ADMIN o AUDITOR) o por línea de comandos, que publica todos los lotes pendientes:

```bash
python -m audit_tracer.merkle_scheduler audit_central.db merkle_anchors
# cron cada hora:  5 * * * *  cd /opt/audit-tracer && venv/bin/python -m audit_tracer.merkle_scheduler audit_central.db merkle_anchors
```

Para que el ancla sea externa, copiar `merkle_anchors/` a un medio que el administrador del servidor no controle.

# 7. Ejemplo mínimo

```python
# ejemplo_auditoria.py
import audit_tracer          # activa la captura
import pandas as pd

pd.DataFrame({
    "paciente_id": [101, 102, 103, 104, 105],
    "edad": [45, 17, 62, 34, 15],
    "glucosa": [110, 85, 160, 95, None],
}).to_csv("pacientes_demo.csv", index=False)

df = pd.read_csv("pacientes_demo.csv")                              # CARGA
adultos = df.query("edad >= 18")                                     # CONSULTA
limpios = adultos.fillna({"glucosa": adultos["glucosa"].mean()})     # CONSULTA (glucosa) + TRANSFORMACION
limpios.to_csv("reporte_adultos.csv", index=False)                   # EXPORTACION
audit_tracer.sync_status()
```

**Sin servidor ni login** (salida real del 21/11/2026, con un HOME vacío):

```text
[AuditTracer] La auditoría está activa, pero no hay un usuario identificado: los eventos se registran como DESCONOCIDO (nivel CRITICO). Ejecuta audit_tracer.login(api_url=...) para identificarte.
[AuditTracer] Sincronización: 0 sincronizados · 7 pendientes · 0 con error
```

Eventos en `~/.audit_tracer/audit_trail.db`:

```bash
python -c "import sqlite3, os; c = sqlite3.connect(os.path.expanduser('~/.audit_tracer/audit_trail.db')); print(*c.execute('SELECT event_id, tipo_accion, dataset_nombre, nivel_alerta, usuario_id FROM audit_log'), sep='\n')"
```

```text
(1, 'INICIO_SESION', None, 'CRITICO', 'DESCONOCIDO')
(2, 'EXPORTACION', 'dataset_desconocido', 'CRITICO', 'DESCONOCIDO')   ← el to_csv que crea el archivo de prueba
(3, 'CARGA', 'pacientes_demo.csv', 'CRITICO', 'DESCONOCIDO')
(4, 'CONSULTA', 'pacientes_demo.csv', 'CRITICO', 'DESCONOCIDO')
(5, 'CONSULTA', 'pacientes_demo.csv', 'CRITICO', 'DESCONOCIDO')
(6, 'TRANSFORMACION', 'pacientes_demo.csv', 'CRITICO', 'DESCONOCIDO')
(7, 'EXPORTACION', 'pacientes_demo.csv', 'CRITICO', 'DESCONOCIDO')
(8, 'CIERRE_SESION', None, 'CRITICO', 'DESCONOCIDO')
```

**Con servidor e identidad:** con `python app.py` corriendo, ejecutar una vez `python -c "import audit_tracer; audit_tracer.login(api_url='http://localhost:5000')"`, abrir la dirección que imprime, entrar con una cuenta y confirmar el código. A partir de ahí el mismo script queda atribuido al usuario, los eventos pasan a NORMAL (si se ejecuta entre 8:00 y 18:00 hora Colombia) y se sincronizan solos. Así se ejecutó la validación con MIMIC-III (Anexo 13).

# 8. Pruebas tras instalar

```bash
python -m pytest                                    # suite completa (1 006 pruebas el 21/11/2026)
python -m pytest tests/test_ataques_simulados.py    # 32 ataques simulados
python validacion/descargar_mimic.py                # datos para la validación MIMIC-III
python -m pytest tests/test_validacion_mimic.py     # tres casos de uso
python benchmarks/overhead_referencia.py --filas 50000 200000 1000000 --corridas 5 --salida-json benchmarks/resultados.json
```
