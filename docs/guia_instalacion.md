# Guía de Instalación y Despliegue del Sistema (HU-5.3)

Esta guía técnica detalla los procedimientos necesarios para instalar, configurar y desplegar el sistema de auditoría clínica **Audit Tracer** en distintos entornos: local (desarrollo/pruebas), servidores de producción Linux, contenedores y plataformas en la nube (PaaS y Google Colab).

---

## 1. Arquitectura del Sistema y Componentes

Audit Tracer está compuesto por dos núcleos principales:

1. **Servidor Central y Dashboard Web (`app.py`):**
   * Aplicación Flask que expone el panel administrativo de trazabilidad, el módulo de explicabilidad clínica y reportes normativos.
   * API REST de ingesta segura (`POST /api/eventos/sincronizar`) con autenticación Bearer Token, forzado de HTTPS, verificación de firmas Ed25519 e idempotencia por UUID.
   * Base de datos central consolidada en SQLite operando en modo WAL (`audit_central.db`) con triggers de inmutabilidad que bloquean y registran cualquier `UPDATE` o `DELETE`.

2. **Librería Cliente de Intercepción (`audit_tracer`):**
   * Módulo Python no invasivo para científicos de datos en Jupyter Notebooks, Google Colab o scripts `.py`.
   * Intercepta automáticamente operaciones de Pandas (`read_csv`, `read_excel`, consultas `query`/filtros, transformaciones y exportaciones `to_csv`/`to_excel`).
   * Firma digitalmente cada evento con Ed25519, calcula hashes SHA-256 de integridad, almacena localmente en SQLite (`audit_trail.db`) y sincroniza en segundo plano mediante colas con reintentos exponenciales.

```
┌──────────────────────────────────────────────┐
│        Entorno de Ciencia de Datos           │
│   (Jupyter Notebook / Google Colab / Script) │
│                                              │
│  • pandas (lectura / transformación / exp.)  │
│  • Interceptores automáticos de auditoría    │
│  • Criptografía local (Ed25519 + SHA-256)    │
│  • SQLite local (~/.audit_tracer) + Sync     │
└──────────────────────┬───────────────────────┘
                       │ HTTPS (Bearer Token / Idempotente)
                       ▼
┌──────────────────────────────────────────────┐
│           Servidor Central Flask             │
│                 (app.py)                     │
│                                              │
│  • Ingesta y validación criptográfica        │
│  • BD Central WAL (audit_central.db)         │
│  • Triggers de inmutabilidad SQL             │
│  • Dashboard de Auditoría & Explicabilidad   │
└──────────────────────────────────────────────┘
```

---

## 2. Requisitos y Dependencias del Sistema (CA3)

### Requisitos de Hardware y Software
* **Sistema Operativo:** Linux (Ubuntu 20.04+, Debian 11+, RHEL 8+), macOS (12+) o Windows (10/11 x64).
* **Versión de Python:** Python >= 3.10 (recomendado **Python 3.12**).
* **Motor de Base de Datos:** SQLite 3 (incluido en Python estándar con soporte WAL).

### Dependencias Obligatorias del Núcleo (Core)
Definidas en [`requirements.txt`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/requirements.txt) y [`pyproject.toml`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/pyproject.toml):

| Dependencia | Versión Mínima | Propósito en el Sistema |
|---|:---:|---|
| **`Flask`** | `>= 2.3.0` | Servidor web WSGI, rutas de API REST de ingesta y dashboard administrativo. |
| **`pandas`** | `>= 2.0.0` | Librería principal de manipulación de datos sobre la cual actúan los interceptores. |
| **`cryptography`** | `>= 42.0.0` | Generación de pares de llaves y firmas digitales Ed25519 para no repudio (HU-6.1). |
| **`bcrypt`** | `>= 4.0.0` | Hashing unidireccional con salt de contraseñas de usuarios del dashboard. |
| **`requests`** | `>= 2.31.0` | Cliente HTTP con backoff exponencial para sincronización y autenticación device-flow. |

### Dependencias Opcionales por Formato
* **`openpyxl >= 3.1.0`:** Requerido para auditar lecturas y exportaciones a archivos Excel (`.xlsx`).
* **`pyarrow >= 14.0.0`:** Requerido para auditar lecturas y exportaciones en formato Parquet (`.parquet`).

### Dependencias de Desarrollo y Pruebas
* **`pytest >= 7.0.0`:** Ejecutor de la suite de pruebas unitarias, de integración y de ataque simulado.
* **`nbclient >= 0.10.0`** y **`ipykernel >= 6.29.0`:** Ejecución de pruebas automatizadas sobre notebooks de Jupyter.

---

## 3. Instalación en Entorno Local (CA1)

Sigue estos pasos para instalar y ejecutar el sistema completo en una máquina local de desarrollo o estación de auditoría.

### Paso 1: Clonar el repositorio
```bash
git clone https://pi2tools.icesi.edu.co/bitbucket/scm/pdgtrazdsa/trazauditdsalud.git
cd trazauditdsalud
```

### Paso 2: Crear y activar un entorno virtual
Se recomienda aislar las dependencias del proyecto:

* **En Linux / macOS:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```

* **En Windows (PowerShell):**
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```

### Paso 3: Instalar dependencias
Instala todas las dependencias del sistema:
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
```

Si deseas instalar la librería en modo editable para desarrollo:
```bash
pip install -e ".[dev,servidor]"
```

### Paso 4: Inicializar la base de datos central y sembrar el administrador inicial
El sistema utiliza SQLite en modo WAL. Para crear la base de datos central e insertar el primer usuario administrador:
```bash
python scratch/seed_admin.py
```
*Salida esperada:*
```text
Intentando crear usuario admin: admin@audit.com...
¡Éxito! Usuario admin creado con ID: usr_...
Credenciales:
  Email: admin@audit.com
  Password: Admin123*
```

*(Opcional)* Si requieres poblar el dashboard con datos clínicos y analistas de demostración:
```bash
python scratch/seed_demo_data.py
```

### Paso 5: Ejecutar el servidor web local
```bash
python app.py
```
El servidor quedará disponible en `http://localhost:5000`. Puedes ingresar al dashboard con las credenciales creadas:
* **Usuario:** `admin@audit.com`
* **Contraseña:** `Admin123*`

---

## 4. Instalación en Entornos de Servidor o Cloud (CA2)

### Opción A: Despliegue en PaaS Cloud (Render / Railway)

El proyecto incluye el manifiesto de infraestructura como código [`render.yaml`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/render.yaml) y [`Procfile`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/Procfile) listos para despliegue automatizado.

1. **Conectar el repositorio a Render:**
   * En el panel de Render, selecciona **New > Blueprint**.
   * Conecta tu repositorio de GitHub o Bitbucket.
2. **Configuración automática vía `render.yaml`:**
   El archivo configura el runtime Python 3.12, instala `requirements.txt` y arranca con `python app.py`.
3. **Variables de entorno indispensables en la nube:**
   * `FLASK_DEBUG=0`
   * `SECRET_KEY`: Llave criptográfica secreta generada automáticamente por Render.
   * `TRUST_PROXY_HEADERS=1`: **Mandatorio.** Como Render termina HTTPS en su balanceador perimetral, esta variable permite a Flask confiar en `X-Forwarded-Proto`, garantizando que `/api/eventos/sincronizar` valide el transporte HTTPS legítimo (HU-5.6).
   * `SEED_DEMO_DATA=1`: Inicializa automáticamente la base central con datos al arrancar contenedores con disco efímero.

### Opción B: Despliegue en Servidor Linux (VPS / Bare-Metal) con Nginx y Gunicorn

Para servidores de producción dedicados (Ubuntu/Debian):

#### 1. Instalar Gunicorn en el entorno virtual:
```bash
pip install gunicorn
```

#### 2. Configurar el servicio Systemd (`/etc/systemd/system/audit-tracer.service`):
```ini
[Unit]
Description=Audit Tracer Central Server
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/audit-tracer
Environment="PATH=/opt/audit-tracer/venv/bin"
Environment="SECRET_KEY=clave_secreta_fuerte_de_produccion_generada_con_openssl"
Environment="TRUST_PROXY_HEADERS=1"
Environment="FLASK_DEBUG=0"
ExecStart=/opt/audit-tracer/venv/bin/gunicorn -w 4 -b 127.0.0.1:5000 --timeout 60 app:app

[Install]
WantedBy=multi-user.target
```
Habilitar y arrancar el servicio:
```bash
sudo systemctl daemon-reload
sudo systemctl enable audit-tracer
sudo systemctl start audit-tracer
```

#### 3. Configurar Nginx como Proxy Inverso con SSL/TLS (`/etc/nginx/sites-available/audit-tracer`):
```nginx
server {
    listen 80;
    server_name audit.tudominio.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name audit.tudominio.com;

    ssl_certificate /etc/letsencrypt/live/audit.tudominio.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/audit.tudominio.com/privkey.pem;

    client_max_body_size 25M;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Opción C: Entorno Cloud para Científicos de Datos (Google Colab)

En Google Colab, la librería se instala directamente mediante `pip` desde el repositorio:

```python
# Celda 1: Montar Google Drive para persistencia de identidad y llaves (Recomendado)
from google.colab import drive
drive.mount('/content/drive')

# Celda 2: Instalar la librería cliente
!pip install --quiet "git+https://github.com/Alexis1661/audit-tracer-deploy.git"

# Celda 3: Activar la auditoría al inicio del análisis
import audit_tracer
import pandas as pd

# Celda 4: Identificación por Device-Flow (OAuth 2.0 RFC 8628)
audit_tracer.login(api_url="https://audit-tracer-production.up.railway.app")
```
El token de autenticación se almacena automáticamente en `/content/drive/MyDrive/.audit_tracer`, sobreviviendo a los reinicios del runtime de Colab.

---

## 5. Configuración Inicial del Sistema (CA4)

### Matriz de Variables de Entorno

| Variable | Tipo / Valor | Requerida | Descripción |
|---|:---:|:---:|---|
| **`SECRET_KEY`** | String seguro | Producción | Clave de firma para sesiones y cookies de Flask. Si no se provee, el servidor genera una llave aleatoria por proceso al iniciar (HU-6.5). |
| **`TRUST_PROXY_HEADERS`** | `1` o `0` | Producción Cloud | Habilita `ProxyFix` para interpretar cabeceras `X-Forwarded-*`. Obligatorio detrás de proxies inversos con terminación TLS. |
| **`PORT`** | Entero (`5000`) | Opcional | Puerto de enlace del servidor Flask. Determinado automáticamente por PaaS como Render o Railway. |
| **`FLASK_DEBUG`** | `0` o `1` | Opcional | `1` en desarrollo para auto-recarga; `0` en servidores públicos o producción. |
| **`SEED_DEMO_DATA`** | `1` o `0` | Opcional | Si es `1`, ejecuta automáticamente el sembrado de analistas, datasets y registros clínicos de prueba al arrancar el servidor. |
| **`AUDIT_TRACER_API_URL`** | URL HTTPS | Clientes | URL base del servidor central hacia donde la librería cliente sincroniza los eventos auditados. |

### Configuración de la Base de Datos Central
El archivo de base de datos central se genera en `audit_central.db` en la raíz del backend. Al abrirse mediante [`audit_tracer.db.get_central_connection()`](file:///c:/Users/alexd/Universidad/OctavoSemestre/PDG/PDG-Code/audit_tracer/db.py), se configuran automáticamente los siguientes pragmas de concurrencia e inmutabilidad:
* `PRAGMA journal_mode = WAL`: Habilita el modo Write-Ahead Logging para lecturas y escrituras simultáneas sin bloqueos.
* `PRAGMA busy_timeout = 5000`: Espera hasta 5 segundos para que los hilos concurrentes completen escrituras.
* Triggers `trg_audit_log_no_update` y `trg_audit_log_no_delete`: Bloquean y registran cualquier intento de alteración en la tabla `audit_intentos_bloqueados`.

---

## 6. Ejemplo Funcional Mínimo Reproducible (CA5)

Este ejemplo demuestra el ciclo de vida completo: ejecución de un pipeline de datos con auditoría automática y verificación de persistencia e integridad.

### Paso 1: Crear el script de prueba (`ejemplo_auditoria.py`)

Crea un archivo local `ejemplo_auditoria.py` con el siguiente contenido:

```python
"""
ejemplo_auditoria.py — Ejemplo funcional mínimo de Audit Tracer.
Demuestra la captura transparente de CARGA, CONSULTA, TRANSFORMACIÓN y EXPORTACIÓN.
"""
import os

# 1. IMPORTANTE: audit_tracer debe importarse antes de cualquier operación con datos
import audit_tracer
import pandas as pd

print("\n--- 1. Preparando datos clínicos sintéticos ---")
df_pacientes = pd.DataFrame({
    "paciente_id": [101, 102, 103, 104, 105],
    "edad": [45, 17, 62, 34, 15],
    "sexo": ["M", "F", "F", "M", None],
    "diagnostico": ["Hipertensión", "Control", "Diabetes", "Cardiopatía", "Control"],
    "glucosa": [110, 85, 160, 95, None],
})
df_pacientes.to_csv("pacientes_demo.csv", index=False)

print("\n--- 2. Ejecutando pipeline auditado con pandas ---")
# Operación 1: CARGA (auditada automáticamente)
df = pd.read_csv("pacientes_demo.csv")

# Operación 2: CONSULTA (auditada automáticamente)
adultos = df.query("edad >= 18")

# Operación 3: TRANSFORMACIÓN (auditada automáticamente)
adultos_limpios = adultos.fillna({"glucosa": adultos["glucosa"].mean()})

# Operación 4: EXPORTACIÓN (auditada automáticamente)
adultos_limpios.to_csv("reporte_adultos.csv", index=False)

print("\n--- 3. Verificando estado de auditoría local ---")
audit_tracer.sync_status()

# Limpiar archivos temporales de demo
for f in ("pacientes_demo.csv", "reporte_adultos.csv"):
    if os.path.exists(f):
        os.remove(f)

print("\n¡Ejemplo completado exitosamente! Los eventos quedaron registrados en audit_trail.db.")
```

### Paso 2: Ejecutar el ejemplo
Ejecuta el script desde tu terminal:
```bash
python ejemplo_auditoria.py
```

### Paso 3: Salida esperada en consola
```text
--- 1. Preparando datos clínicos sintéticos ---

--- 2. Ejecutando pipeline auditado con pandas ---

--- 3. Verificando estado de auditoría local ---
[AuditTracer] Sincronización: 0 sincronizados · 4 pendientes · 0 con error

¡Ejemplo completado exitosamente! Los eventos quedaron registrados en audit_trail.db.
```

### Paso 4: Validar la evidencia en la base de datos SQLite
Puedes verificar directamente los eventos capturados en la base de datos local:
```bash
python -c "import sqlite3; conn = sqlite3.connect(r'audit_trail.db'); cur = conn.cursor(); cur.execute('SELECT event_id, tipo_accion, dataset_nombre, nivel_alerta FROM audit_log ORDER BY event_id DESC LIMIT 5'); print(cur.fetchall())"
```
*Salida:*
```python
[(4, 'EXPORTACION', 'reporte_adultos.csv', 'NORMAL'),
 (3, 'TRANSFORMACION', 'pacientes_demo.csv', 'NORMAL'),
 (2, 'CONSULTA', 'pacientes_demo.csv', 'NORMAL'),
 (1, 'CARGA', 'pacientes_demo.csv', 'NORMAL')]
```

Cada evento incluye su firma digital Ed25519, su hash SHA-256 inmutable y los metadatos de sesión y entorno del analista.

---

## 7. Verificación de la Suite de Pruebas

Para comprobar la integridad de todos los módulos del sistema tras la instalación:

```bash
# Ejecutar todas las pruebas unitarias y de integración del proyecto
python -m pytest tests/ -v

# Ejecutar específicamente las pruebas de ataques simulados (HU-6.5)
python -m pytest tests/test_ataques_simulados.py -v

# Ejecutar las pruebas de integración automática de scripts (HU-5.1)
python -m pytest tests/test_integracion_automatica.py -v

# Ejecutar las pruebas de benchmark de overhead (HU-6.7)
python -m pytest tests/test_benchmark_overhead.py -v
```
