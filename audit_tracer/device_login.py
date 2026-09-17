"""
audit_tracer/device_login.py
==============================
HU-5.7 — Autenticación de la librería mediante login por código de
dispositivo ("device flow"): un solo comando desde el notebook, sin
copiar/pegar tokens a mano.

CA1 — Genera (vía el servidor) un código corto y una URL de activación,
      y los imprime en la salida del notebook.
CA2 — El usuario confirma el código en el dashboard web (fuera de este
      módulo: ver app.py::confirmar_dispositivo_post).
CA3 — Este módulo hace polling del estado hasta recibir un token válido,
      sin intervención adicional del usuario.
CA4 — El token se cachea en disco (por defecto, la carpeta de Google
      Drive montada si existe — patrón estándar de Colab) para no pedir
      login en cada sesión nueva.
CA5 — Si el token cacheado ya no es válido, se dispara el flujo de nuevo
      automáticamente, sin que el usuario tenga que notar la diferencia.
"""

import json
import os
import time
from datetime import datetime
from typing import Dict, Optional

import requests

DEFAULT_POLL_INTERVAL_SECONDS = 5
# Mismo valor que CODIGO_EXPIRACION_MINUTOS en auth/device_codes.py (10 min):
# no tiene sentido que el cliente siga esperando más allá de lo que el
# código ya expiró en el servidor.
DEFAULT_TIMEOUT_SECONDS = 600

_CACHE_FILENAME = "token_cache.json"
_COLAB_DRIVE_PATH = "/content/drive/MyDrive"


# ──────────────────────────────────────────────────────────────
# CACHÉ LOCAL DEL TOKEN (CA4)
# ──────────────────────────────────────────────────────────────

def _default_cache_dir() -> str:
    """
    Prioriza la carpeta de Google Drive montada (patrón estándar de
    Colab: `drive.mount('/content/drive')`) si existe, porque sobrevive
    al cierre de la sesión de Colab — que es exactamente el problema que
    motiva HU-5.4/5.7 (el filesystem de Colab es efímero). Si no existe
    (entorno local, script, etc.), cae a un directorio en el home del
    usuario.
    """
    if os.path.isdir(_COLAB_DRIVE_PATH):
        return os.path.join(_COLAB_DRIVE_PATH, ".audit_tracer")
    return os.path.join(os.path.expanduser("~"), ".audit_tracer")


def _cache_file_path(cache_dir: Optional[str]) -> str:
    return os.path.join(cache_dir or _default_cache_dir(), _CACHE_FILENAME)


def _load_cached_token(cache_dir: Optional[str]) -> Optional[Dict]:
    path = _cache_file_path(cache_dir)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def _save_cached_token(cache_dir: Optional[str], data: Dict) -> None:
    path = _cache_file_path(cache_dir)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _clear_cached_token(cache_dir: Optional[str]) -> None:
    try:
        os.remove(_cache_file_path(cache_dir))
    except OSError:
        pass


# ──────────────────────────────────────────────────────────────
# LLAMADAS HTTP AL SERVIDOR CENTRAL
# ──────────────────────────────────────────────────────────────

def _validar_token_remoto(api_url: str, token: str) -> Optional[Dict]:
    """CA5 — Reutiliza /api/tokens/validar (HU-5.5) para saber si el token cacheado sigue vivo."""
    try:
        resp = requests.post(f"{api_url}/api/tokens/validar", json={"token": token}, timeout=5)
    except requests.exceptions.RequestException:
        return None
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    return data if data.get("valido") else None


def _iniciar_codigo(api_url: str) -> Dict:
    resp = requests.post(f"{api_url}/api/auth/dispositivo/iniciar", timeout=10)
    resp.raise_for_status()
    return resp.json()


def _consultar_estado(api_url: str, device_code: str) -> Dict:
    resp = requests.get(
        f"{api_url}/api/auth/dispositivo/estado",
        params={"device_code": device_code},
        timeout=10,
    )
    try:
        return resp.json()
    except ValueError:
        return {"estado": "ERROR"}


# ──────────────────────────────────────────────────────────────
# API PRINCIPAL (CA1-CA5)
# ──────────────────────────────────────────────────────────────

def device_login(
    api_url: str,
    cache_dir: Optional[str] = None,
    poll_interval: int = DEFAULT_POLL_INTERVAL_SECONDS,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    force: bool = False,
) -> Dict:
    """
    Punto de entrada de HU-5.7.

    1. CA4/CA5: intenta reusar un token cacheado y todavía válido — si lo
       encuentra, retorna de inmediato sin imprimir ningún código.
    2. CA1: si no hay token reusable, pide al servidor un código corto +
       URL de activación, y los imprime en la salida del notebook.
    3. CA3: hace polling del estado cada `poll_interval` segundos hasta
       que el código se confirme, expire, o se agote `timeout_seconds`.
    4. CA4: al confirmarse, cachea el token para la próxima sesión.

    Args:
        api_url: Base URL del servidor central (ej. 'https://audit.miorg.com').
        cache_dir: Carpeta donde cachear el token. Por defecto, la carpeta
            de Drive montada en Colab si existe, o ~/.audit_tracer.
        poll_interval: Segundos entre cada consulta de estado (CA3).
        timeout_seconds: Tiempo máximo de espera por la confirmación.
        force: Si True, ignora cualquier token cacheado y fuerza el flujo
            de código nuevo (por ejemplo, para cambiar de cuenta).

    Returns:
        Dict: en éxito, {'success': True, 'usuario_id', 'token', 'origen'
        ('cache'|'device_flow'), 'message'}. En fallo, {'success': False,
        'motivo', 'message'}.
    """
    api_url = api_url.rstrip("/")

    if not force:
        cache = _load_cached_token(cache_dir)
        if cache and cache.get("token"):
            info = _validar_token_remoto(api_url, cache["token"])
            if info:
                return {
                    "success": True,
                    "usuario_id": info.get("usuario_id"),
                    "token": cache["token"],
                    "origen": "cache",
                    "message": "Sesión reanudada con el token cacheado.",
                }
            # CA5: el token cacheado ya no es válido (expiró/fue revocado) ->
            # se descarta y se repite el flujo de login automáticamente.
            _clear_cached_token(cache_dir)

    try:
        datos_codigo = _iniciar_codigo(api_url)
    except requests.exceptions.RequestException as exc:
        return {
            "success": False,
            "motivo": "SIN_CONEXION",
            "message": f"No se pudo contactar al servidor central: {exc}",
        }

    codigo = datos_codigo["codigo"]
    device_code = datos_codigo["device_code"]
    url_activacion = datos_codigo["url_activacion"]
    intervalo = datos_codigo.get("intervalo_polling", poll_interval)

    print("=" * 60)
    print("[AuditTracer] Autenticación requerida")
    print(f"  1. Visita:  {url_activacion}")
    print(f"  2. Confirma el código: {codigo}")
    print(f"  (expira en {timeout_seconds // 60} minutos)")
    print("=" * 60)

    inicio = time.monotonic()
    while time.monotonic() - inicio < timeout_seconds:
        time.sleep(intervalo)
        try:
            estado = _consultar_estado(api_url, device_code)
        except requests.exceptions.RequestException:
            continue  # error transitorio de red: se reintenta en el próximo ciclo

        if estado.get("estado") == "CONFIRMADO":
            token = estado["token"]
            usuario_id = estado.get("usuario_id")
            _save_cached_token(cache_dir, {
                "token": token,
                "usuario_id": usuario_id,
                "guardado_en": datetime.utcnow().isoformat(),
            })
            print("[AuditTracer] Autenticación confirmada.")
            return {
                "success": True,
                "usuario_id": usuario_id,
                "token": token,
                "origen": "device_flow",
                "message": "Autenticación confirmada.",
            }

        if estado.get("estado") in ("EXPIRADO", "INVALIDO", "CONSUMIDO"):
            return {
                "success": False,
                "motivo": estado["estado"],
                "message": "El código expiró sin confirmarse. Ejecuta audit_tracer.login() de nuevo.",
            }
        # PENDIENTE: sigue esperando confirmación, continúa el polling.

    return {
        "success": False,
        "motivo": "TIMEOUT",
        "message": f"No se confirmó el código dentro de los {timeout_seconds} segundos esperados.",
    }
