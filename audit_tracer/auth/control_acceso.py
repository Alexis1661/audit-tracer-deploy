"""
control_acceso.py
HU-1.4 — Restringir acceso a módulos por rol para proteger información clínica.

Define:
  - PERMISSION_MATRIX: matriz de roles x módulos.
  - has_permission(): validación puntual en tiempo de ejecución.
  - requires_role(): decorador que valida rol y registra ACCESO_DENEGADO.
"""

import sqlite3
import functools
from datetime import datetime
from typing import Callable, List, Optional

from ..models.audit_log import insert_event
from ..utils.session import generate_session_id

# ---------------------------------------------------------------------------
# CA1 / CA4 — Matriz de permisos: rol → conjunto de módulos permitidos
# ---------------------------------------------------------------------------
#  Módulos del sistema:
#    captura_eventos       – captura de eventos clínicos
#    consulta_reportes     – consulta y generación de reportes
#    gestion_usuarios      – alta/baja/modificación de usuarios
#    visualizacion_alertas – visualización del panel de alertas
#    exportaciones         – exportación de datos y reportes
# ---------------------------------------------------------------------------

MODULES = [
    "captura_eventos",
    "consulta_reportes",
    "gestion_usuarios",
    "visualizacion_alertas",
    "exportaciones",
]

# CA4: Roles predefinidos y sus permisos
PERMISSION_MATRIX: dict[str, set[str]] = {
    # ADMINISTRADOR: acceso total al sistema
    "ADMIN": {
        "captura_eventos",
        "consulta_reportes",
        "gestion_usuarios",
        "visualizacion_alertas",
        "exportaciones",
    },
    # ANALISTA: acceso a consultas y reportes, sin gestión de usuarios
    "ANALISTA": {
        "consulta_reportes",
        "visualizacion_alertas",
        "exportaciones",
    },
    # AUDITOR: acceso únicamente a reportes y exportaciones
    "AUDITOR": {
        "consulta_reportes",
        "exportaciones",
    },
    # CIENTIFICO_DATOS: captura de eventos, sin acceso a reportes completos
    "CIENTIFICO_DATOS": {
        "captura_eventos",
        "visualizacion_alertas",
    },
}

# ---------------------------------------------------------------------------
# CA3 — Validación en tiempo de ejecución
# ---------------------------------------------------------------------------

def has_permission(rol: str, modulo: str) -> bool:
    """
    Verifica en tiempo de ejecución si un rol tiene acceso a un módulo.

    Args:
        rol (str): Rol del usuario (ej. 'ANALISTA').
        modulo (str): Identificador del módulo (ej. 'consulta_reportes').

    Returns:
        bool: True si el acceso está permitido, False en caso contrario.
    """
    allowed = PERMISSION_MATRIX.get(rol, set())
    return modulo in allowed


def _log_denied_access(
    conn: Optional[sqlite3.Connection],
    usuario_id: str,
    sesion_id: str,
    rol: str,
    modulo: str,
    operacion: str,
) -> None:
    """
    Registra un evento ACCESO_DENEGADO en el audit_log.
    Si conn es None el registro se omite (modo sin BD).
    """
    if conn is None:
        return

    insert_event(conn, {
        "usuario_id": usuario_id,
        "sesion_id": sesion_id,
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": "ACCESO_DENEGADO",
        "contexto_ejecucion": (
            f"Rol: {rol} | Módulo: {modulo} | Operación: {operacion}"
        ),
        "motivo_fallo": f"Acceso denegado: rol '{rol}' no tiene permiso sobre '{modulo}'",
        "nivel_alerta": "ADVERTENCIA",
    })


# ---------------------------------------------------------------------------
# CA2 / CA3 — Decorador requires_role
# ---------------------------------------------------------------------------

class AccesoDenegadoError(PermissionError):
    """Lanzada cuando un usuario intenta acceder a un módulo restringido."""

    def __init__(self, rol: str, modulo: str):
        self.rol = rol
        self.modulo = modulo
        super().__init__(
            f"Acceso denegado: el rol '{rol}' no tiene permiso para acceder al módulo '{modulo}'."
        )


def requires_role(
    roles: List[str],
    modulo: str,
    get_conn: Optional[Callable] = None,
):
    """
    Decorador que valida en tiempo de ejecución si el usuario tiene el rol
    requerido para ejecutar la operación y el módulo indicados.

    Uso:
        @requires_role(roles=['ADMIN', 'ANALISTA'], modulo='consulta_reportes')
        def mi_funcion(conn, usuario_id, sesion_id, rol, ...):
            ...

    La función decorada DEBE recibir los parámetros (conn, usuario_id,
    sesion_id, rol) como los 4 primeros argumentos posicionales.

    Args:
        roles (List[str]): Roles con acceso permitido.
        modulo (str): Identificador del módulo protegido.
        get_conn (Callable, optional): Función sin args que devuelve una
            conexión a la BD, para registrar el evento cuando la función
            decorada no recibe conn como primer argumento. Normalmente
            no se necesita.

    Raises:
        AccesoDenegadoError: Si el rol no tiene permiso.
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extraer parámetros de sesión del primer grupo de args o kwargs
            conn       = args[0] if len(args) > 0 else kwargs.get("conn")
            usuario_id = args[1] if len(args) > 1 else kwargs.get("usuario_id", "DESCONOCIDO")
            sesion_id  = args[2] if len(args) > 2 else kwargs.get("sesion_id", generate_session_id())
            rol        = args[3] if len(args) > 3 else kwargs.get("rol", "")

            # Normalizar rol a mayúsculas para comparación robusta
            rol_upper = rol.upper() if rol else ""

            if rol_upper not in [r.upper() for r in roles]:
                _log_denied_access(
                    conn=conn if isinstance(conn, sqlite3.Connection) else None,
                    usuario_id=str(usuario_id),
                    sesion_id=str(sesion_id),
                    rol=rol,
                    modulo=modulo,
                    operacion=func.__name__,
                )
                raise AccesoDenegadoError(rol=rol, modulo=modulo)

            return func(*args, **kwargs)

        # Exponer metadata del decorador para introspección / tests
        wrapper._required_roles = roles
        wrapper._modulo = modulo
        return wrapper

    return decorator
