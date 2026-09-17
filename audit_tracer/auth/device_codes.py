"""
device_codes.py — Lógica de negocio del login por código de dispositivo.
HU-5.7 — Autenticación de la librería mediante token personal.
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Tuple

from ..models.device_codes import (
    insert_device_code,
    get_by_codigo,
    get_by_device_code,
    confirmar_codigo as _confirmar_codigo_db,
    marcar_consumido,
    marcar_expirado,
)
from ..models.audit_log import insert_event
from .tokens import generar_token

# CA1/CA3 — Ventana corta de vigencia del CÓDIGO (no del token, que dura 30
# días vía generar_token()). Coherente con el timeout por defecto del lado
# cliente en audit_tracer/device_login.py.
CODIGO_EXPIRACION_MINUTOS = 10
INTERVALO_POLLING_SEGUNDOS = 5


def iniciar_login_dispositivo(conn: sqlite3.Connection) -> Dict:
    """CA1 — Genera un código corto + device_code, persistidos como PENDIENTE."""
    fecha_expiracion = (
        datetime.utcnow() + timedelta(minutes=CODIGO_EXPIRACION_MINUTOS)
    ).isoformat()
    return insert_device_code(conn, fecha_expiracion)


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
    autenticado en el dashboard, y genera el token personal que la
    librería recibirá por polling. Reutiliza generar_token() (HU-5.5/6.2)
    sin modificarlo.

    Returns:
        Tuple[bool, str]: (éxito, mensaje para mostrar en el dashboard).
    """
    registro = get_by_codigo(conn, codigo)
    if not registro:
        return False, "Código inválido. Verifica que lo copiaste correctamente."

    if registro["estado"] != "PENDIENTE":
        return False, "Este código ya fue usado o ya no está disponible."

    if _expirado(registro):
        marcar_expirado(conn, registro["device_code"])
        return False, "El código expiró. Genera uno nuevo ejecutando audit_tracer.login() de nuevo."

    token_info = generar_token(
        conn, usuario_id, dias_expiracion=30, creado_por="DEVICE_CODE", sesion_id=sesion_id
    )
    _confirmar_codigo_db(conn, codigo, usuario_id, token_info["token"])

    insert_event(conn, {
        "usuario_id": usuario_id,
        "sesion_id": sesion_id,
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": "CONFIRMACION_LOGIN_DISPOSITIVO",
        "contexto_ejecucion": f"Código de dispositivo confirmado: {codigo}",
        "nivel_alerta": "NORMAL",
    })

    return True, "Confirmado. Ya puedes volver a tu notebook."


def consultar_estado(conn: sqlite3.Connection, device_code: str) -> Dict:
    """
    CA3 — Consulta el estado de un device_code (lado del polling, sin
    autenticación: el device_code largo y secreto ES la credencial).

    Al reportar CONFIRMADO por primera vez, entrega el token y marca el
    código CONSUMIDO de inmediato — no se puede volver a recuperar el
    mismo token por esta vía en una consulta posterior.
    """
    registro = get_by_device_code(conn, device_code)
    if not registro:
        return {"estado": "INVALIDO"}

    estado_actual = registro["estado"]

    if estado_actual == "PENDIENTE" and _expirado(registro):
        marcar_expirado(conn, device_code)
        return {"estado": "EXPIRADO"}

    if estado_actual == "CONFIRMADO":
        resultado = {
            "estado": "CONFIRMADO",
            "token": registro["token"],
            "usuario_id": registro["usuario_id"],
        }
        marcar_consumido(conn, device_code)
        return resultado

    return {"estado": estado_actual}
