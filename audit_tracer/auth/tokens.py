"""
tokens.py — Lógica de negocio y autenticación con tokens personales de acceso.
HU-5.5 (PDGTRAZDSA-128, PDGTRAZDSA-129, PDGTRAZDSA-130).
"""

import secrets
import sqlite3
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from ..models.audit_log import insert_event
from ..models.tokens import (
    insert_token,
    get_token_by_value,
    get_token_by_id,
    get_tokens_by_user,
    get_all_tokens_with_user_info,
    update_token_status,
    revoke_token_by_id,
    revoke_token_by_value,
)
from ..models.usuarios import get_user_by_id

# CA2: Expiración por defecto de 30 días
DEFAULT_TOKEN_EXPIRATION_DAYS = 30


def generar_token_seguro(prefix: str = "tk_") -> str:
    """
    Genera un token criptográficamente seguro con prefijo identificador.

    Args:
        prefix (str): Prefijo del token (por defecto 'tk_').

    Returns:
        str: Token generado (ej. 'tk_AbCd...').
    """
    random_bytes = secrets.token_urlsafe(32)
    return f"{prefix}{random_bytes}"


def generar_token(
    conn: sqlite3.Connection,
    usuario_id: str,
    dias_expiracion: int = DEFAULT_TOKEN_EXPIRATION_DAYS,
    fecha_expiracion_custom: Optional[str] = None,
    creado_por: str = "LOGIN",
    sesion_id: str = "N/A",
    admin_id: Optional[str] = None,
) -> Dict:
    """
    CA1 & CA2 [PDGTRAZDSA-128]: Genera y almacena un token único y seguro para un usuario.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        usuario_id (str): ID del usuario receptor del token.
        dias_expiracion (int): Días de vigencia del token (por defecto 30 días).
        fecha_expiracion_custom (Optional[str]): Fecha de expiración fija en formato ISO 8601 (opcional).
        creado_por (str): Origen de generación ('LOGIN', 'ADMIN', 'API').
        sesion_id (str): ID de sesión para auditoría.
        admin_id (Optional[str]): ID del administrador si la creación es manual.

    Returns:
        Dict: Registro del token generado.

    Raises:
        ValueError: Si el usuario no existe.
    """
    user = get_user_by_id(conn, usuario_id)
    if not user:
        raise ValueError(f"Usuario con ID {usuario_id} no encontrado.")

    ahora = datetime.utcnow()
    fecha_creacion_iso = ahora.isoformat()

    if fecha_expiracion_custom:
        fecha_expiracion_iso = fecha_expiracion_custom
    else:
        expiracion_dt = ahora + timedelta(days=dias_expiracion)
        fecha_expiracion_iso = expiracion_dt.isoformat()

    token_str = generar_token_seguro()

    token_data = {
        "usuario_id": usuario_id,
        "token": token_str,
        "fecha_creacion": fecha_creacion_iso,
        "fecha_expiracion": fecha_expiracion_iso,
        "estado": "ACTIVO",
        "creado_por": creado_por,
    }

    token_id = insert_token(conn, token_data)
    token_data["token_id"] = token_id

    # Registrar evento de auditoría
    actor_id = admin_id if admin_id else usuario_id
    insert_event(conn, {
        "usuario_id": actor_id,
        "sesion_id": sesion_id,
        "timestamp": fecha_creacion_iso,
        "tipo_accion": "GENERACION_TOKEN",
        "contexto_ejecucion": (
            f"Token generado para usuario: {user.get('email', usuario_id)} | "
            f"Expiración: {fecha_expiracion_iso} | "
            f"Origen: {creado_por}"
        ),
        "nivel_alerta": "NORMAL",
    })

    return token_data


def validar_token(conn: sqlite3.Connection, token_str: str) -> Tuple[bool, str, Optional[Dict]]:
    """
    CA5 [PDGTRAZDSA-129]: Valida el estado de un token (vigente, expirado o revocado).

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        token_str (str): Cadena del token a validar.

    Returns:
        Tuple[bool, str, Optional[Dict]]:
            - bool: True si el token es válido y activo, False en caso contrario.
            - str: Motivo/descripción del estado ('Token activo y vigente', 'Token revocado', 'Token expirado', 'Token inexistente').
            - Optional[Dict]: Datos del token si existe, o None.
    """
    if not token_str or not isinstance(token_str, str):
        return False, "Token no proporcionado o formato inválido", None

    token_record = get_token_by_value(conn, token_str.strip())
    if not token_record:
        return False, "Token inexistente o inválido", None

    vigente, mensaje = _validar_vigencia(conn, token_record)
    if not vigente:
        return False, mensaje, token_record

    user = get_user_by_id(conn, token_record["usuario_id"])
    if not user or user.get("activo") == 0:
        return False, "Usuario asociado al token inactivo o bloqueado", token_record
    return True, mensaje, token_record


def validar_token_sesion(conn: sqlite3.Connection, token_id: str, usuario_id: str, rol: str) -> bool:
    """Verifica el token vinculado a una cookie firmada y los permisos actuales."""
    if not isinstance(token_id, str) or not token_id:
        return False
    token = get_token_by_id(conn, token_id)
    if not token or token["usuario_id"] != usuario_id or token["creado_por"] != "LOGIN":
        return False
    if not _validar_vigencia(conn, token)[0]:
        return False
    user = get_user_by_id(conn, usuario_id)
    return bool(user and user["activo"] == 1 and user["rol"] == rol)


def _validar_vigencia(conn: sqlite3.Connection, token_record: Dict) -> Tuple[bool, str]:
    estado_actual = token_record.get("estado", "").upper()
    if estado_actual == "REVOCADO":
        return False, "Token revocado"
    if estado_actual == "EXPIRADO":
        return False, "Token expirado"
    if estado_actual != "ACTIVO":
        return False, "Estado de token inválido"
    try:
        fecha_exp = datetime.fromisoformat(token_record["fecha_expiracion"].replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return False, "Error al verificar fecha de expiración del token"
    ahora = datetime.now(fecha_exp.tzinfo) if fecha_exp.tzinfo is not None else datetime.utcnow()
    if ahora >= fecha_exp:
        if update_token_status(conn, token_record["token_id"], "EXPIRADO", estado_anterior="ACTIVO"):
            token_record["estado"] = "EXPIRADO"
        else:
            current = get_token_by_id(conn, token_record["token_id"])
            if current and current["estado"] == "REVOCADO":
                token_record["estado"] = "REVOCADO"
                return False, "Token revocado"
        return False, "Token expirado"
    return True, "Token activo y vigente"


def revocar_token(
    conn: sqlite3.Connection,
    token_id_o_str: str,
    admin_id: Optional[str] = None,
    sesion_id: str = "N/A",
    motivo: str = "Revocación manual por administrador",
) -> Tuple[bool, str]:
    """
    CA4 & CA5 [PDGTRAZDSA-130]: Revoca un token de inmediato y registra el evento en auditoría.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        token_id_o_str (str): Token ID (UUID) o valor literal del token.
        admin_id (Optional[str]): ID del administrador o usuario que ejecuta la revocación.
        sesion_id (str): ID de sesión para auditoría.
        motivo (str): Motivo de la revocación.

    Returns:
        Tuple[bool, str]: (éxito: bool, mensaje: str).
    """
    # Buscar primero por token_id, luego por valor literal
    token_record = get_token_by_id(conn, token_id_o_str)
    if not token_record:
        token_record = get_token_by_value(conn, token_id_o_str)

    if not token_record:
        return False, f"Token no encontrado: {token_id_o_str}"

    token_id = token_record["token_id"]
    update_token_status(conn, token_id, "REVOCADO")

    # Registrar evento de auditoría
    actor_id = admin_id if admin_id else "SISTEMA"
    usuario_afectado = token_record.get("usuario_id", "DESCONOCIDO")

    insert_event(conn, {
        "usuario_id": actor_id,
        "sesion_id": sesion_id,
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": "REVOCACION_TOKEN",
        "contexto_ejecucion": (
            f"Token {token_id} revocado de inmediato para usuario: {usuario_afectado} | "
            f"Motivo: {motivo}"
        ),
        "nivel_alerta": "ADVERTENCIA",
    })

    return True, f"Token {token_id} revocado exitosamente."


def listar_tokens(
    conn: sqlite3.Connection,
    usuario_id: Optional[str] = None,
    estado: Optional[str] = None,
) -> List[Dict]:
    """
    CA3 [PDGTRAZDSA-131]: Lista tokens con información de usuario y estado de vigencia actualizado.

    Args:
        conn (sqlite3.Connection): Conexión a la BD.
        usuario_id (Optional[str]): Filtrar por usuario.
        estado (Optional[str]): Filtrar por estado.

    Returns:
        List[Dict]: Lista de tokens enriquecida.
    """
    tokens = get_all_tokens_with_user_info(conn, usuario_id=usuario_id, estado=estado)
    ahora = datetime.utcnow()

    for item in tokens:
        # Calcular días restantes o si ya expiró
        try:
            exp_str = item["fecha_expiracion"]
            exp_dt = datetime.fromisoformat(exp_str.replace("Z", "+00:00"))
            if exp_dt.tzinfo is not None:
                ahora_cmp = datetime.now(exp_dt.tzinfo)
            else:
                ahora_cmp = ahora

            if ahora_cmp > exp_dt and item["estado"] == "ACTIVO":
                # Si en BD seguía como ACTIVO pero la fecha venció, actualizar
                if update_token_status(conn, item["token_id"], "EXPIRADO", estado_anterior="ACTIVO"):
                    item["estado"] = "EXPIRADO"

            diferencia = exp_dt - ahora_cmp
            item["dias_restantes"] = max(0, diferencia.days)
        except Exception:
            item["dias_restantes"] = 0

    return tokens
