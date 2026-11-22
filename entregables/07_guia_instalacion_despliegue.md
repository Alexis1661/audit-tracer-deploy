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
| Railway | No se verificó: el periodo de prueba de la cuenta terminó antes de la migración a Render. | Retirado de la guía (sección 5.2): las plataformas probadas son Render y un servidor Linux propio. |
| Segunda ronda (21/11/2026, noche) | Gunicorn con `wsgi.py`, depuración apagada por defecto, cookie Secure, CSRF, límites de peticiones, política de contraseñas, sello de tiempo RFC 3161 y retención | La suite completa pasa en Windows con `python app.py`. El arranque con `gunicorn wsgi:app` no se pudo ejecutar en Windows (Gunicorn solo corre en Linux/macOS): **probar en el servidor Linux o en Render antes de la sustentación**. |
| Linux con Nginx y systemd (sección 4) | **Probado el 21/11/2026** en WSL2 con Ubuntu 24.04 (Python 3.12.3, Nginx 1.24, Gunicorn 27, systemd real) siguiendo esta sección con un certificado autofirmado en lugar de Let's Encrypt: HTTP→HTTPS 301; login, dashboard y PDF por HTTPS; sesión válida entre los 2 workers (10/10 peticiones 200); la API responde 426 sin HTTPS y 401 sin token; `kill -9` del proceso maestro y systemd lo reinicia; el CLI de Merkle corre como `www-data`. | Funciona. La prueba destapó un fallo real: la librería interceptaba SIGTERM/SIGINT también dentro de Gunicorn y `systemctl restart` tardaba 30 s con `KeyboardInterrupt`; corregido (`session_tracker.py`): reinicio en 0,6 s. |

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
| APScheduler | 3.10 (< 4) | Publicación horaria automática de raíces Merkle (solo lotes completos) | `requirements.txt`; extra `servidor` (agregada el 21/11/2026). Solo corre con `python app.py`; bajo Gunicorn se programa con cron (sección 6.3). |
| gunicorn | 22 o superior | Servidor WSGI de producción (Linux/macOS) | `requirements.txt` (solo fuera de Windows) y extra `servidor` (segunda ronda) |
| keyring | 24 o superior | Opcional, en el equipo del analista: guarda la frase que cifra la llave de firma en el llavero del sistema | Extra `seguridad` |

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

Desde la segunda ronda (21/11/2026) la contraseña no está en el script: se toma de `AUDIT_ADMIN_PASSWORD` o se pide por teclado, y debe cumplir la política (al menos 8 caracteres y tres de: minúsculas, mayúsculas, números y símbolos; no una contraseña común). Sin teclado, el script genera una y la muestra una sola vez.

```text
Intentando crear usuario admin: admin@audit.com...
¡Éxito! Usuario admin creado con ID: 00ecb12c-4679-4bd1-b457-4da081de13a9
```

Arrancar el servidor:

```bash
python app.py            # http://localhost:5000  (servidor de desarrollo; FLASK_DEBUG=0 por defecto)
```

**Desarrollo por `http://`.** La cookie de sesión es `Secure`: Chrome y Edge la aceptan en `http://localhost`; si un navegador o un cliente (p. ej. `requests`) no la guarda y el login vuelve a pedir credenciales, arrancar con `AUDIT_COOKIE_SEGURA=0` solo en el equipo de desarrollo.

# 4. Servidor Linux con Nginx y systemd

> Probado el 21/11/2026 en Ubuntu 24.04 (WSL2) con systemd. Con Nginx ≥ 1.25.1 `http2` pasa a ser la directiva `http2 on;` y `listen 443 ssl http2;` queda obsoleto (Ubuntu 24.04 trae 1.24, donde la forma de abajo es la válida).

```bash
sudo mkdir -p /opt/audit-tracer && sudo chown $USER /opt/audit-tracer
git clone <repositorio> /opt/audit-tracer && cd /opt/audit-tracer
python3 -m venv venv && venv/bin/pip install -r requirements.txt   # incluye gunicorn en Linux
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
Environment="AUDIT_EXIGIR_FIRMA=1"
Environment="AUDIT_TSA_URL=https://<autoridad de sellado de tiempo>"
Environment="AUDIT_DASHBOARD_URL=https://audit.institucion.edu.co"
Environment="AUDIT_SMTP_HOST=smtp.institucion.edu.co"
Environment="AUDIT_SMTP_USER=audit-tracer@institucion.edu.co"
Environment="AUDIT_SMTP_PASSWORD=<secreto>"
ExecStart=/opt/audit-tracer/venv/bin/gunicorn wsgi:app --workers 1 --threads 8 -b 127.0.0.1:5000 --timeout 60
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now audit-tracer
```

**Gunicorn con `wsgi.py` (segunda ronda).** `wsgi.py` ejecuta las mismas tareas de arranque que `python app.py` (cuentas de `SEED_USUARIOS` y `SEED_DEMO_DATA`, limpieza de códigos de dispositivo vencidos y publicador horario de Merkle). Se usa **un solo proceso con varios hilos** (`--workers 1 --threads 8`): la base central es SQLite, el publicador de Merkle debe correr una sola vez y el límite de peticiones se cuenta en memoria. `SECRET_KEY` sigue siendo obligatoria: sin ella cada reinicio invalida las sesiones.

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
    client_max_body_size 2M;          # igual que MAX_CONTENT_LENGTH de la app (SRV-D1)
    limit_req zone=audit burst=20 nodelay;   # límite también en el proxy (definir la zona en http {})
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;   # TRUST_PROXY_HEADERS=1 lo lee
    }
}
```

En `/etc/nginx/nginx.conf`, dentro de `http { }`: `limit_req_zone $binary_remote_addr zone=audit:10m rate=20r/s;`

```bash
sudo ln -s /etc/nginx/sites-available/audit-tracer /etc/nginx/sites-enabled/ && sudo nginx -t && sudo systemctl reload nginx
```

**Cifrado en reposo (brecha B2).** La aplicación no cifra la base SQLite: se cifra el volumen donde viven `audit_central.db` y `merkle_anchors/` (LUKS en Linux, BitLocker en Windows Server). Es la decisión documentada para la especificación direccionable §164.312(a)(2)(iv); la base se crea además con permisos de solo-dueño para el usuario del servicio.

**Respaldos.** Copiar a diario `audit_central.db` con `sqlite3 audit_central.db ".backup respaldo.db"` (consistente aunque el servidor esté escribiendo) y verificar la copia con `verify_integrity` antes de rotar respaldos viejos.

# 5. Plataformas en la nube

## 5.1 Render (usado en la validación externa)

`render.yaml` define un servicio web Python: `pip install -r requirements.txt`, arranque `gunicorn wsgi:app --workers 1 --threads 8` (segunda ronda; antes `python app.py`), chequeo de salud `/login`, `FLASK_DEBUG=0`, `TRUST_PROXY_HEADERS=1`, `AUDIT_EXIGIR_FIRMA=1`, `SECRET_KEY` generada por Render y `SEED_DEMO_DATA=1` con `SEED_DEMO_PASSWORD` definida en el panel.

1. Render › New › Blueprint › conectar el repositorio (o el espejo de GitHub).
2. Agregar en Environment las variables de la sección 6 que se necesiten (`SEED_USUARIOS`, SMTP).
3. Cada push a la rama conectada redespliega.

**Advertencias.** En el plan gratuito el disco es efímero y el servicio se duerme tras unos 15 minutos sin tráfico: al reiniciar se pierden `audit_central.db` y `merkle_anchors/`. Sirve para demostraciones, no para conservar evidencia. `SEED_DEMO_DATA=1` crea cuentas de demostración: sus contraseñas ya no están en el repositorio (B10); se toman de `SEED_DEMO_PASSWORD` o se generan y se imprimen una vez en el log de Render. Quitarla en cualquier despliegue con datos reales. Las cuentas de `SEED_USUARIOS` deben cumplir la política de contraseñas: las que no la cumplan se omiten y el log lo dice.

## 5.2 Otras plataformas con Procfile

El `Procfile` arranca `gunicorn wsgi:app --workers 1 --threads 8 --timeout 60 --bind 0.0.0.0:$PORT`, el formato que entienden plataformas como Heroku o Railway, con las mismas variables de la sección 6. No se probó en ellas (la cuenta de Railway expiró antes de la migración a Render): las referencias verificadas son Render (5.1) y el servidor Linux (4).

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
| `FLASK_DEBUG` | `0` | `1` solo en desarrollo: muestra trazas y la consola de Werkzeug. |
| `PORT` | `5000` | Puerto de `python app.py`. |
| `TRUST_PROXY_HEADERS` | — | `1` detrás de un proxy con TLS (Nginx, Render) para aceptar `X-Forwarded-Proto`. |
| `SEED_DEMO_DATA` | — | `1` crea cuentas de demostración al arrancar (`python app.py` o `wsgi.py`). |
| `SEED_DEMO_PASSWORD` | — | Contraseña de las cuentas de demostración; sin ella se generan y se imprimen una vez. |
| `SEED_USUARIOS` | — | JSON `[{"email","password","rol"}]`: crea esas cuentas al arrancar (deben cumplir la política de contraseñas). |
| `START_MERKLE_SCHEDULER` | `1` | Intenta iniciar el job horario de Merkle (requiere APScheduler). |
| `AUDIT_MERKLE_ANCHORS_DIR` | `merkle_anchors/` junto al paquete | Carpeta de las anclas Merkle. |
| `AUDIT_DASHBOARD_URL` | URL de la primera petición | Base de los enlaces en los correos de alerta. |
| `AUDIT_SMTP_HOST`, `AUDIT_SMTP_PORT`, `AUDIT_SMTP_USER`, `AUDIT_SMTP_PASSWORD`, `AUDIT_SMTP_FROM` | — / 587 | Servidor de correo de las alertas (HU-7.2). |
| `AUDIT_SMTP_SSL`, `AUDIT_SMTP_STARTTLS`, `AUDIT_SMTP_TIMEOUT` | `0` / `1` / `10` | Opciones del canal SMTP. |
| `AUDIT_SMTP_TLS` | — | `implicit` para el comando `flask audit-email` (avisos del espacio de auditoría). |
| `AUDIT_ALERTAS_OUTBOX` | — | Sin SMTP: guarda cada correo como `.eml` en esa carpeta. |
| `AUDIT_ALERTAS_DESACTIVADAS` | — | `1` apaga el despachador de alertas (lo usan las pruebas). |
| `AUDIT_HORARIO_INICIO`, `AUDIT_HORARIO_FIN` | `8`, `18` | Horario laboral (hora Colombia) para marcar CRITICO las cargas fuera de horario (también lo aplica el servidor). |
| `AUDIT_COOKIE_SEGURA` | `1` | `0` solo para desarrollo por `http://` con un cliente que no acepte cookies `Secure`. |
| `AUDIT_SESION_INACTIVIDAD_MIN` | `15` | Minutos sin actividad tras los que se cierra la sesión del dashboard. |
| `AUDIT_BLOQUEO_MINUTOS` | `15` | Duración del bloqueo tras 5 intentos fallidos. |
| `AUDIT_PASSWORD_MIN` | `8` | Longitud mínima de las contraseñas. |
| `AUDIT_EXIGIR_FIRMA` | — | `1` rechaza todo evento sin firma digital, también de usuarios sin llave registrada. |
| `AUDIT_DESFASE_MAX_HORAS` | `72` | Un evento recibido más de estas horas después de su timestamp queda en ADVERTENCIA. |
| `AUDIT_LIMITE_LOGIN_MIN`, `AUDIT_LIMITE_SYNC_MIN`, `AUDIT_LIMITE_SYNC_IP_MIN` | `10`, `1200`, `3000` | Peticiones por minuto: login por IP; sincronización por token y por IP. |
| `AUDIT_MAX_PETICION_BYTES` | `2097152` | Tamaño máximo de una petición (2 MB). |
| `AUDIT_TSA_URL` | — | Autoridad de sellado de tiempo RFC 3161 para las raíces de Merkle. |
| `AUDIT_TSA_CERT_SHA256` | — | Huella del certificado de la TSA en que se confía (opcional). |
| `AUDIT_RETENCION_ANIOS` | `6` | Plazo mínimo de conservación de los eventos (comandos `flask retencion-*`). |
| `AUDIT_HORAS_SESION_SIN_CIERRE` | `24` | Horas sin eventos tras las que una sesión de la librería aparece en el panel de sincronización. |

## 6.2 Variables de la librería

| Variable | Para qué |
|---|---|
| `AUDIT_TRACER_API_URL` | URL del servidor si no se pasa `api_url` a `audit_tracer.login()`. |
| `AUDIT_HORARIO_INICIO`, `AUDIT_HORARIO_FIN` | Las mismas del servidor: la regla de horario se evalúa en el equipo del analista (y el servidor la vuelve a aplicar). |
| `AUDIT_TRACER_KEY_PASSPHRASE` | Frase que cifra la llave de firma local; útil en Colab, donde no hay llavero del sistema. |
| `AUDIT_TRACER_KEYRING` | `0` desactiva el uso del llavero del sistema operativo. |
| `AUDIT_TRACER_MODELADO` | `0` desactiva la captura del modelado con scikit-learn. |

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
