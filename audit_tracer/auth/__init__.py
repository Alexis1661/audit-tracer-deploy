# Auth package
from .control_acceso import (  # noqa: F401  – HU-1.4
    has_permission,
    requires_role,
    AccesoDenegadoError,
    PERMISSION_MATRIX,
    MODULES,
)
