"""
device_codes.py — Lógica de negocio del login por código de dispositivo.
HU-5.7 — Autenticación de la librería mediante token personal.

SRV-I1 (21/11/2026) — El token ya no se genera al confirmar el código sino en
el polling que lo entrega: así nunca queda guardado en claro en
codigos_dispositivo (antes esperaba ahí hasta 10 minutos).
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Optional, Tuple

from ..models.device_codes import (
    insert_device_code,
    get_by_codigo,
    get_by_device_code,
    confirmar_codigo as _confirmar_codigo_db,
    marcar_consumido_si_confirmado,
    marcar_expirado,
    marcar_expirado_por_codigo,
)
from ..models.audit_log import insert_event
from .tokens import generar_token

# CA1/CA3 — Ventana corta de vigencia del CÓDIGO (no del token, que dura 30
# días vía generar_token()). Coherente con el timeout por defecto del lado
# cliente en audit_tracer/device_login.py.
CODIGO_EXPIRACION_MINUTOS = 10
INTERVALO_POLLING_SEGUNDOS = 5
DIAS_VIGENCIA_TOKEN_DISPOSITIVO = 30


def iniciar_login_dispositivo(conn: sqlite3.Connection, origen: Optional[Dict] = None) -> Dict:
    """CA1 — Genera un código corto + device_code, persistidos como PENDIENTE."""
    fecha_expiracion = (
        datetime.utcnow() + timedelta(minutes=CODIGO_EXPIRACION_MINUTOS)
    ).isoformat()
    return insert_device_code(conn, fecha_expiracion, origen=origen)


def _expirado(registro: Dict) -> bool:
    try:
        return datetime.utcnow() > datetime.fromisoformat(registro["fecha_expiracion"])
    except (KeyError, ValueError, TypeError):
        return True


def confirmar_codigo(
    conn: sqlite3.Connection,
    codigo: str,
    usuario_id: str,
    sesion_id: str = "DEVICE_LOGIN",
) -> Tuple[bool, str]:
    """
    CA2 — Asocia el código (ya visible en el notebook) al usuario ya
    autenticado en el dashboard. El token personal se genera después, en el
    polling que lo entrega (consultar_estado).

    Returns:
        Tuple[bool, str]: (éxito, mensaje para mostrar en el dashboard).
    """
    registro = get_by_codigo(conn, codigo)
    if not registro:
        return False, "Código inválido. Verifica que lo copiaste correctamente."

    if registro["estado"] != "PENDIENTE":
        return False, "Este código ya fue usado o ya no está disponible."

    if _expirado(registro):
        marcar_expirado_por_codigo(conn, codigo)
        return False, "El código expiró. Genera uno nuevo ejecutando audit_tracer.login() de nuevo."

    if not _confirmar_codigo_db(conn, codigo, usuario_id, sesion_id):
        return False, "Este código ya fue usado o ya no está disponible."

    origen = " | ".join(
        f"{etiqueta}: {registro.get(campo)}" for etiqueta, campo in
        (("IP", "ip_origen"), ("Equipo", "host_origen"), ("Agente", "agente_origen")) if registro.get(campo)
    )
    insert_event(conn, {
        "usuario_id": usuario_id,
        "sesion_id": sesion_id,
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": "CONFIRMACION_LOGIN_DISPOSITIVO",
        "contexto_ejecucion": f"Código de dispositivo confirmado: {codigo}" + (f" | {origen}" if origen else ""),
        "nivel_alerta": "NORMAL",
    })

    return True, "Confirmado. Ya puedes volver a tu notebook."


def consultar_estado(conn: sqlite3.Connection, device_code: str) -> Dict:
    """
    CA3 — Consulta el estado de un device_code (lado del polling, sin
    autenticación: el device_code largo y secreto ES la credencial).

    Al reportar CONFIRMADO por primera vez genera el token, lo entrega y marca
    el código CONSUMIDO en la misma transición atómica: no se puede volver a
    obtener un token con el mismo device_code.
    """
    if not device_code:
        return {"estado": "INVALIDO"}
    registro = get_by_device_code(conn, device_code)
    if not registro:
        return {"estado": "INVALIDO"}

    estado_actual = registro["estado"]

    if estado_actual == "PENDIENTE" and _expirado(registro):
        marcar_expirado(conn, device_code)
        return {"estado": "EXPIRADO"}

    if estado_actual == "CONFIRMADO":
        if not marcar_consumido_si_confirmado(conn, registro["codigo"]):
            return {"estado": "CONSUMIDO"}   # otra consulta simultánea ganó la entrega
        token_info = generar_token(
            conn, registro["usuario_id"], dias_expiracion=DIAS_VIGENCIA_TOKEN_DISPOSITIVO,
            creado_por="DEVICE_CODE", sesion_id=registro.get("sesion_confirmacion") or "DEVICE_LOGIN",
        )
        return {
            "estado": "CONFIRMADO",
            "token": token_info["token"],
            "usuario_id": registro["usuario_id"],
        }

    return {"estado": estado_actual}
