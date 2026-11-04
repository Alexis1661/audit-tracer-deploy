"""
audit_tracer.alerts — HU-7.2: alertas en tiempo real de eventos críticos.

  catalogo.py       CA1  qué es un evento crítico y con qué severidad
  email_service.py  CA2/CA3  envío de correo (SMTP) y contenido del mensaje
  dispatcher.py     CA2/CA4  disparo asíncrono, desacoplado del INSERT

La configuración de destinatarios y el historial viven en
audit_tracer/models/alertas.py.
"""

from .catalogo import (
    CATALOGO_EVENTOS_CRITICOS,
    ClasificacionCritica,
    TipoEventoCritico,
    clasificar_evento,
)
from .dispatcher import (
    DespachadorAlertas,
    configurar_alertas,
    desactivar_alertas,
    obtener_despachador,
)
from .email_service import (
    ErrorEnvioCorreo,
    ServicioCorreo,
    ServicioCorreoArchivo,
    ServicioCorreoMemoria,
    ServicioCorreoSMTP,
    crear_servicio_correo_desde_entorno,
)

__all__ = [
    "CATALOGO_EVENTOS_CRITICOS",
    "ClasificacionCritica",
    "TipoEventoCritico",
    "clasificar_evento",
    "DespachadorAlertas",
    "configurar_alertas",
    "desactivar_alertas",
    "obtener_despachador",
    "ErrorEnvioCorreo",
    "ServicioCorreo",
    "ServicioCorreoArchivo",
    "ServicioCorreoMemoria",
    "ServicioCorreoSMTP",
    "crear_servicio_correo_desde_entorno",
]
