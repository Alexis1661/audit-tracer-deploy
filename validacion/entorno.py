"""
validacion/entorno.py
=====================
Infraestructura de la validación con MIMIC-III Demo (sección 7.4).

Levanta el sistema tal como se despliega, sin atajos:

  * Servidor central: una copia del código (app.py, templates, static,
    audit_tracer) en una carpeta temporal, ejecutada con `python app.py` en
    su propio proceso, con su propia base central, sus cuentas creadas por
    SEED_USUARIOS y el correo de alertas entregado en una carpeta (outbox),
    que es el modo sin servidor SMTP que trae el propio sistema.
  * Científico de datos: cada script del analista corre en un proceso Python
    nuevo, con su propio HOME (base local, llaves Ed25519, token cacheado),
    autenticado una sola vez con el flujo de código de dispositivo y
    sincronizando contra el servidor por HTTP.
  * Auditor y administrador: usan el dashboard por HTTP con una sesión de
    navegador (requests.Session), igual que un usuario real.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
import shutil
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from contextlib import closing
from pathlib import Path
from typing import Dict, List, Optional

import requests

RAIZ = Path(__file__).resolve().parent.parent
CARPETA_VALIDACION = Path(__file__).resolve().parent
RELOJ = CARPETA_VALIDACION / "reloj.py"
SCRIPTS = CARPETA_VALIDACION / "scripts"

CUENTAS = [
    {"email": "admin@mimic.validacion", "password": "Adm1n-Valid4cion*", "rol": "ADMIN"},
    {"email": "auditor@mimic.validacion", "password": "Aud1t-Valid4cion*", "rol": "AUDITOR"},
    {"email": "cientifica@mimic.validacion", "password": "C1ent-Valid4cion*", "rol": "CIENTIFICO_DATOS"},
]
CORREO_OFICIAL = "oficial.cumplimiento@mimic.validacion"


def cuenta(rol: str) -> Dict:
    return next(c for c in CUENTAS if c["rol"] == rol)


def _puerto_libre() -> int:
    with closing(socket.socket()) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _entorno_base(home: Path) -> Dict[str, str]:
    env = dict(os.environ)
    for var in ("AUDIT_TRACER_API_URL", "AUDIT_ALERTAS_DESACTIVADAS", "AUDIT_SMTP_HOST",
                "AUDIT_ALERTAS_OUTBOX", "AUDIT_DASHBOARD_URL", "PYTEST_CURRENT_TEST"):
        env.pop(var, None)
    env.update(HOME=str(home), USERPROFILE=str(home), PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
    return env


# ──────────────────────────────────────────────────────────────
# SERVIDOR CENTRAL
# ──────────────────────────────────────────────────────────────

class ServidorCentral:
    """El servidor central (app.py) en un proceso propio y una carpeta propia."""

    def __init__(self, base: Path):
        self.base = Path(base)
        self.codigo = self.base / "servidor"
        self.outbox = self.base / "outbox_correo"
        self.anclas = self.base / "merkle_anchors"
        self.log_path = self.base / "servidor.log"
        self.puerto = _puerto_libre()
        self.url = f"http://127.0.0.1:{self.puerto}"
        self.proceso: Optional[subprocess.Popen] = None

    @property
    def db_path(self) -> Path:
        return self.codigo / "audit_central.db"

    def iniciar(self, timeout: float = 90) -> "ServidorCentral":
        self.codigo.mkdir(parents=True, exist_ok=True)
        shutil.copy2(RAIZ / "app.py", self.codigo / "app.py")
        ignorar = shutil.ignore_patterns("__pycache__", "*.pyc", "*.db")
        for carpeta in ("audit_tracer", "templates", "static"):
            shutil.copytree(RAIZ / carpeta, self.codigo / carpeta, ignore=ignorar)
        self.outbox.mkdir(parents=True, exist_ok=True)
        home = self.base / "home_servidor"
        home.mkdir(exist_ok=True)
        env = _entorno_base(home)
        env.update(
            # Servidor local por http://: la cookie no puede ser Secure (requests,
            # como el estándar de cookies, no envía cookies Secure por http).
            AUDIT_COOKIE_SEGURA="0",
            PORT=str(self.puerto), FLASK_DEBUG="0", SECRET_KEY="clave-validacion-mimic",
            SEED_USUARIOS=json.dumps(CUENTAS), START_MERKLE_SCHEDULER="0",
            AUDIT_ALERTAS_OUTBOX=str(self.outbox), AUDIT_SMTP_FROM="audit-tracer@mimic.validacion",
            AUDIT_MERKLE_ANCHORS_DIR=str(self.anclas), AUDIT_DASHBOARD_URL=self.url,
        )
        self._log = open(self.log_path, "w", encoding="utf-8")
        self.proceso = subprocess.Popen(
            [sys.executable, "app.py"], cwd=self.codigo, env=env,
            stdout=self._log, stderr=subprocess.STDOUT,
        )
        limite = time.monotonic() + timeout
        while time.monotonic() < limite:
            if self.proceso.poll() is not None:
                raise RuntimeError(f"El servidor terminó al arrancar:\n{self.log_path.read_text(encoding='utf-8')}")
            try:
                if requests.get(f"{self.url}/login", timeout=2).status_code == 200:
                    return self
            except requests.RequestException:
                time.sleep(0.5)
        raise RuntimeError("El servidor central no respondió a tiempo")

    def detener(self) -> None:
        if self.proceso and self.proceso.poll() is None:
            self.proceso.terminate()
            try:
                self.proceso.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.proceso.kill()
        if getattr(self, "_log", None):
            self._log.close()

    def consultar(self, sql: str, params=()) -> List[Dict]:
        """Lectura directa de la base central (solo lectura, para la evidencia)."""
        uri = f"file:{self.db_path.as_posix()}?mode=ro"
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(r) for r in conn.execute(sql, params).fetchall()]


# ──────────────────────────────────────────────────────────────
# DASHBOARD (navegador)
# ──────────────────────────────────────────────────────────────

def _token_csrf(html: str) -> str:
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    if not m:
        raise RuntimeError("La página no trae el token CSRF del formulario")
    return m.group(1)


class Navegador:
    """Una sesión de navegador sobre el dashboard."""

    def __init__(self, servidor: ServidorCentral, rol: str):
        self.servidor = servidor
        self.cuenta = cuenta(rol)
        self.s = requests.Session()
        # Como un navegador: el formulario de login trae su token CSRF (DSH-T1).
        token = _token_csrf(self.s.get(f"{servidor.url}/login", timeout=30).text)
        r = self.s.post(f"{servidor.url}/login",
                        data={"email": self.cuenta["email"], "password": self.cuenta["password"],
                              "csrf_token": token},
                        allow_redirects=False, timeout=30)
        if r.status_code not in (302, 303):
            raise RuntimeError(f"No se pudo iniciar sesión como {rol}: HTTP {r.status_code}")
        # El login renueva la sesión: el token CSRF vigente sale de cualquier formulario.
        self.csrf = _token_csrf(self.get("/auth/dispositivo").text)

    def get(self, ruta: str, **kw) -> requests.Response:
        return self.s.get(f"{self.servidor.url}{ruta}", timeout=60, **kw)

    def post(self, ruta: str, **kw) -> requests.Response:
        cabeceras = {"X-CSRF-Token": self.csrf, **kw.pop("headers", {})}
        return self.s.post(f"{self.servidor.url}{ruta}", timeout=60, headers=cabeceras, **kw)

    def csv(self, ruta: str, **params) -> tuple[str, List[Dict], List[str]]:
        r = self.get(ruta, params=params)
        r.raise_for_status()
        texto = r.text
        lector = csv.DictReader(io.StringIO(texto))
        filas = list(lector)
        return texto, filas, list(lector.fieldnames or [])


# ──────────────────────────────────────────────────────────────
# CIENTÍFICO DE DATOS (procesos de la librería)
# ──────────────────────────────────────────────────────────────

class Analista:
    """Un científico de datos con su propio equipo (HOME) y su propia identidad."""

    def __init__(self, servidor: ServidorCentral, home: Path):
        self.servidor = servidor
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.cuenta = cuenta("CIENTIFICO_DATOS")

    def _env(self) -> Dict[str, str]:
        env = _entorno_base(self.home)
        env["PYTHONPATH"] = str(RAIZ) + os.pathsep + env.get("PYTHONPATH", "")
        return env

    def iniciar_sesion_por_dispositivo(self, timeout: float = 120) -> Dict:
        """
        HU-5.7: el analista ejecuta audit_tracer.login(api_url=...) una vez.
        La librería muestra un código; la analista lo confirma en el dashboard
        con su sesión de navegador. El token queda cacheado en su HOME y los
        scripts siguientes la identifican solo con `import audit_tracer`.
        """
        codigo_py = (
            "import audit_tracer, json\n"
            f"r = audit_tracer.login(api_url={self.servidor.url!r})\n"
            "print('RESULTADO=' + json.dumps({k: r.get(k) for k in ('success','usuario_id','origen')}))\n"
        )
        proc = subprocess.Popen([sys.executable, "-u", "-c", codigo_py], cwd=self.home, env=self._env(),
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                encoding="utf-8", errors="replace")
        salida: List[str] = []
        codigo = None
        confirmado = threading.Event()

        def confirmar(cod: str) -> None:
            nav = Navegador(self.servidor, "CIENTIFICO_DATOS")
            nav.get(f"/auth/dispositivo?codigo={cod}")
            nav.post("/auth/dispositivo", data={"codigo": cod})
            confirmado.set()

        vigilante = threading.Timer(timeout, proc.kill)  # nunca colgar la prueba
        vigilante.start()
        try:
            for linea in proc.stdout:
                salida.append(linea)
                m = re.search(r"Confirma el código: (\S+)", linea)
                if m and codigo is None:
                    codigo = m.group(1)
                    threading.Thread(target=confirmar, args=(codigo,), daemon=True).start()
            proc.wait(timeout=30)
        finally:
            vigilante.cancel()
        texto = "".join(salida)
        m = re.search(r"RESULTADO=(\{.*\})", texto)
        resultado = json.loads(m.group(1)) if m else {"success": False}
        resultado.update(codigo_mostrado=codigo, confirmado_en_dashboard=confirmado.is_set(), salida=texto)
        return resultado

    def ejecutar(self, script: str, *args: str, reloj_utc: Optional[str] = None,
                 cwd: Optional[Path] = None, timeout: float = 300) -> subprocess.CompletedProcess:
        """Corre un script del analista en un proceso nuevo (opcionalmente con reloj simulado)."""
        ruta = str(SCRIPTS / script)
        comando = [sys.executable, str(RELOJ), reloj_utc, ruta, *args] if reloj_utc else [sys.executable, ruta, *args]
        r = subprocess.run(comando, cwd=cwd or self.home, env=self._env(), capture_output=True,
                           text=True, encoding="utf-8", errors="replace", timeout=timeout)
        if r.returncode != 0:
            raise RuntimeError(f"El script {script} falló ({r.returncode}):\n{r.stdout}\n{r.stderr}")
        return r

    def base_local(self) -> Path:
        return self.home / ".audit_tracer" / "audit_trail.db"

    def cola_local(self) -> Dict[str, int]:
        with closing(sqlite3.connect(self.base_local())) as conn:
            return dict(conn.execute(
                "SELECT estado, COUNT(*) FROM audit_sync_queue GROUP BY estado").fetchall())


def esperar(condicion, timeout: float = 60, intervalo: float = 0.5, descripcion: str = "condición"):
    limite = time.monotonic() + timeout
    while time.monotonic() < limite:
        valor = condicion()
        if valor:
            return valor
        time.sleep(intervalo)
    raise TimeoutError(f"No se cumplió a tiempo: {descripcion}")
