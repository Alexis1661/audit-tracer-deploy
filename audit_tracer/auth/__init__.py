# Auth package
from .control_acceso import (  # noqa: F401  – HU-1.4
    has_permission,
    requires_role,
    AccesoDenegadoError,
    PERMISSION_MATRIX,
    MODULES,
)
from .tokens import (  # noqa: F401  – HU-5.5
    generar_token,
    validar_token,
    revocar_token,
    listar_tokens,
    generar_token_seguro,
)
