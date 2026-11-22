"""
audit_tracer/clasificacion_servidor.py
======================================
SRV-T3 (21/11/2026) — El servidor central recalcula la criticidad de cada
evento que recibe, en lugar de confiar en la que trae el cliente.

Antes, un cliente modificado podía enviar una exportación de 50 000 filas
como NORMAL o fechar un evento en 2020, y el servidor lo guardaba así: las
reglas solo se aplicaban en la librería, que controla el usuario.

Reglas (las mismas de la librería, más las del reloj del servidor):
  * EXPORTACION con más de UMBRAL_EXPORTACION_MASIVA filas  -> CRITICO
  * CARGA / CONSULTA fuera del horario laboral (por el timestamp) -> CRITICO
  * usuario DESCONOCIDO                                      -> CRITICO
  * timestamp más de TOLERANCIA_FUTURO_MIN en el futuro respecto a la
    recepción                                                 -> CRITICO
  * timestamp más de AUDIT_DESFASE_MAX_HORAS (72 h por defecto) antes de la
    recepción                                                 -> ADVERTENCIA
    (un notebook sin conexión puede sincronizar tarde; no es un ataque por
    sí mismo, pero el auditor debe verlo)

La fecha de recepción (recibido_en) la pone el servidor con su reloj y se
guarda junto al evento. Un evento sin firma se guarda ya reclasificado; uno
firmado no puede cambiarse sin invalidar la firma, así que se guarda tal como
llegó y el servidor agrega un evento RECLASIFICACION_SERVIDOR que lo
referencia (mismo patrón que ANOMALIA_DETECTADA).
"""

import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from .export_capture import UMBRAL_EXPORTACION_MASIVA
from .utils.horario import es_horario_laboral, HORA_INICIO_LABORAL, HORA_FIN_LABORAL

TIPO_EVENTO_RECLASIFICACION = "RECLASIFICACION_SERVIDOR"
TOLERANCIA_FUTURO_MIN = 5
ACCIONES_SUJETAS_A_HORARIO = ("CARGA", "CONSULTA")

_RANGO = {"NORMAL": 0, "ADVERTENCIA": 1, "ANOMALIA": 2, "CRITICO": 3}


def desfase_maximo_horas() -> float:
    try:
        return float(os.environ.get("AUDIT_DESFASE_MAX_HORAS", "72"))
    except ValueError:
        return 72.0


def rango(nivel: Optional[str]) -> int:
    return _RANGO.get((nivel or "NORMAL").upper(), 0)


def _parse(ts: Optional[str]) -> Optional[datetime]:
    if not ts or not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


def _entero(valor) -> Optional[int]:
    try:
        return int(valor)
    except (TypeError, ValueError):
        return None


def clasificar(evento: Dict, recibido_en: datetime) -> Tuple[str, List[str]]:
    """
    Nivel que el servidor asigna a `evento` y los motivos (vacío si NORMAL).
    `recibido_en` es la hora UTC (naive) del servidor.
    """
    nivel, motivos = "NORMAL", []

    def elevar(nuevo: str, motivo: str) -> None:
        nonlocal nivel
        if rango(nuevo) > rango(nivel):
            nivel = nuevo
        motivos.append(motivo)

    tipo = (evento.get("tipo_accion") or "").upper()
    if (evento.get("usuario_id") or "DESCONOCIDO") == "DESCONOCIDO":
        elevar("CRITICO", "Operación ejecutada por usuario no identificado")

    filas = _entero(evento.get("filas_exportadas"))
    if tipo == "EXPORTACION" and filas is not None and filas > UMBRAL_EXPORTACION_MASIVA:
        elevar("CRITICO", f"Exportación masiva: {filas} filas (> {UMBRAL_EXPORTACION_MASIVA})")

    momento = _parse(evento.get("timestamp"))
    if tipo in ACCIONES_SUJETAS_A_HORARIO and momento is not None and not es_horario_laboral(momento):
        elevar("CRITICO", f"Acceso fuera de horario laboral "
                          f"({HORA_INICIO_LABORAL:02d}:00-{HORA_FIN_LABORAL:02d}:00, hora de Colombia)")

    if momento is None:
        elevar("ADVERTENCIA", "Timestamp del cliente ausente o inválido")
    else:
        # Textos estables (sin cifras variables) para agrupar por sesión los
        # avisos de un mismo lote sincronizado tarde.
        if momento - recibido_en > timedelta(minutes=TOLERANCIA_FUTURO_MIN):
            elevar("CRITICO", f"Timestamp del cliente en el futuro respecto a la recepción "
                              f"(más de {TOLERANCIA_FUTURO_MIN} min)")
        if (recibido_en - momento).total_seconds() / 3600 > desfase_maximo_horas():
            elevar("ADVERTENCIA", f"Evento recibido más de {desfase_maximo_horas():.0f} h después de su timestamp")
    return nivel, motivos


def motivos_por_encima_de(evento: Dict, nivel_servidor: str, motivos: List[str]) -> List[str]:
    """Motivos del servidor que el cliente no declaró (para no repetir lo que ya viene en motivo_alerta)."""
    declarado = (evento.get("motivo_alerta") or "").lower()
    return [m for m in motivos if m.split(":")[0].lower() not in declarado]


def aplicar_a_evento_sin_firma(evento: Dict, recibido_en: datetime) -> Dict:
    """
    Devuelve una copia del evento con el nivel máximo entre el declarado y el
    del servidor, y los motivos del servidor agregados a motivo_alerta.
    """
    nivel, motivos = clasificar(evento, recibido_en)
    evento = dict(evento)
    nuevos = motivos_por_encima_de(evento, nivel, motivos)
    if rango(nivel) > rango(evento.get("nivel_alerta")):
        evento["nivel_alerta"] = nivel
    if nuevos and rango(nivel) > 0:
        previo = evento.get("motivo_alerta")
        sufijo = "Servidor: " + "; ".join(nuevos)
        evento["motivo_alerta"] = f"{previo} | {sufijo}" if previo else sufijo
    return evento


def evento_reclasificacion(evento: Dict, nivel_servidor: str, motivos: List[str], recibido_en: datetime) -> Dict:
    """Evento RECLASIFICACION_SERVIDOR para un evento firmado cuyo nivel declarado es menor que el del servidor."""
    return {
        "usuario_id": evento.get("usuario_id") or "DESCONOCIDO",
        "sesion_id": evento.get("sesion_id") or "SINCRONIZACION",
        "timestamp": recibido_en.isoformat(),
        "tipo_accion": TIPO_EVENTO_RECLASIFICACION,
        "dataset_nombre": evento.get("dataset_nombre"),
        "contexto_ejecucion": (
            f"Evento: {evento.get('evento_uuid')} | Tipo: {evento.get('tipo_accion')} | "
            f"Nivel declarado: {evento.get('nivel_alerta') or 'NORMAL'} | Nivel del servidor: {nivel_servidor}"
        ),
        "motivo_fallo": "; ".join(motivos),
        "nivel_alerta": nivel_servidor,
        "motivo_alerta": "El nivel declarado por el cliente es menor que el calculado por el servidor",
    }
