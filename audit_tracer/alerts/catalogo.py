"""
catalogo.py — HU-7.2 CA1 / Sub-tarea 1: catálogo de eventos críticos.

Define, en un solo lugar, QUÉ se considera un evento crítico que amerita
notificar de inmediato al oficial de cumplimiento, con su severidad y la
regla que lo detecta. Las reglas reutilizan las clasificaciones que ya hacen
otras HU — no se reimplementa ninguna detección:

  EXPORTACION_MASIVA           (HU-2.3)  EXPORTACION de más de
                               UMBRAL_EXPORTACION_MASIVA filas.
  ACCESOS_DENEGADOS_REPETIDOS  (HU-1.4 / HU-2.4 / HU-4.4)  el mismo usuario
                               acumula >= UMBRAL_ACCESOS_DENEGADOS eventos
                               ACCESO_DENEGADO / ACCESO_FALLIDO en
                               VENTANA_ACCESOS_DENEGADOS_MIN minutos.
  ANOMALIA_DETECTADA           (HU-6.3)  evento marcado nivel_alerta = ANOMALIA
                               por el detector de anomalías.
  FIRMA_INVALIDA               (HU-6.1 / HU-6.5)  evento rechazado por firma
                               digital inválida o ausente (posible manipulación).
  AUDITORIA_DESACTIVADA        (HU-5.1)  alguien apagó la captura de auditoría.

Las tres primeras son las que pide explícitamente CA1; las dos últimas son
eventos que el sistema ya registra como CRITICO y que tienen la misma
urgencia (integridad de la evidencia), así que se incluyen con severidad
CRITICA.

clasificar_evento() es una función pura sobre (conn, evento): no envía nada
ni escribe nada — solo responde "¿es crítico?, ¿de qué tipos?, ¿con qué
severidad?". Eso la hace fácil de probar por separado del envío.
"""

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from ..export_capture import UMBRAL_EXPORTACION_MASIVA
from ..models.alertas import SEVERIDADES, severidad_rank

# Accesos denegados repetidos: 3 o más en 10 minutos por el mismo usuario.
UMBRAL_ACCESOS_DENEGADOS = 3
VENTANA_ACCESOS_DENEGADOS_MIN = 10
ACCIONES_ACCESO_DENEGADO = ("ACCESO_DENEGADO", "ACCESO_FALLIDO")


@dataclass(frozen=True)
class TipoEventoCritico:
    codigo: str
    nombre: str
    severidad: str
    descripcion: str
    origen: str
    # Si es True, una ráfaga de eventos del mismo usuario genera UNA sola
    # notificación por ventana (ver dispatcher): sin esto, 10 accesos
    # denegados seguidos mandarían 8 correos casi idénticos.
    agrupable: bool = False
    ventana_agrupacion_min: int = 0


CATALOGO_EVENTOS_CRITICOS: Dict[str, TipoEventoCritico] = {
    t.codigo: t for t in (
        TipoEventoCritico(
            codigo="EXPORTACION_MASIVA",
            nombre="Exportación masiva",
            severidad="ALTA",
            descripcion=(
                f"Exportación de más de {UMBRAL_EXPORTACION_MASIVA:,} filas de un dataset clínico "
                "(posible extracción masiva de datos)."
            ),
            origen="HU-2.3",
        ),
        TipoEventoCritico(
            codigo="ACCESOS_DENEGADOS_REPETIDOS",
            nombre="Accesos denegados repetidos",
            severidad="ALTA",
            descripcion=(
                f"{UMBRAL_ACCESOS_DENEGADOS} o más accesos denegados o fallidos del mismo usuario "
                f"en {VENTANA_ACCESOS_DENEGADOS_MIN} minutos (posible fuerza bruta o escalamiento "
                "de privilegios)."
            ),
            origen="HU-1.4 / HU-2.4 / HU-4.4",
            agrupable=True,
            ventana_agrupacion_min=VENTANA_ACCESOS_DENEGADOS_MIN,
        ),
        TipoEventoCritico(
            codigo="ANOMALIA_DETECTADA",
            nombre="Anomalía detectada",
            severidad="MEDIA",
            descripcion=(
                "Evento marcado como ANOMALIA por el detector (volumen inusual, horario inusual "
                "o correlación entre usuarios sobre el mismo dataset)."
            ),
            origen="HU-6.3",
        ),
        TipoEventoCritico(
            codigo="FIRMA_INVALIDA",
            nombre="Firma digital inválida",
            severidad="CRITICA",
            descripcion=(
                "Evento sincronizado con firma digital inválida o ausente: posible manipulación "
                "del registro de auditoría."
            ),
            origen="HU-6.1 / HU-6.5",
        ),
        TipoEventoCritico(
            codigo="AUDITORIA_DESACTIVADA",
            nombre="Auditoría desactivada",
            severidad="CRITICA",
            descripcion="Se desactivó la captura de auditoría en un entorno de análisis.",
            origen="HU-5.1",
        ),
    )
}


@dataclass
class ClasificacionCritica:
    """Resultado de clasificar un evento como crítico."""
    tipos: List[str]
    severidad: str
    motivos: Dict[str, str] = field(default_factory=dict)

    @property
    def nombres(self) -> List[str]:
        return [CATALOGO_EVENTOS_CRITICOS[t].nombre for t in self.tipos]


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "").replace(" ", "T"))
    except ValueError:
        return None


def contar_accesos_denegados(
    conn: sqlite3.Connection,
    usuario_id: str,
    hasta: datetime,
    ventana_minutos: int = VENTANA_ACCESOS_DENEGADOS_MIN,
    hasta_event_id: Optional[int] = None,
    hasta_iso: Optional[str] = None,
) -> int:
    """
    Eventos ACCESO_DENEGADO / ACCESO_FALLIDO del usuario en (hasta - ventana, hasta].
    Con `hasta_event_id`, los eventos con el MISMO timestamp que `hasta` solo
    cuentan si su event_id es <= ese id (dos eventos seguidos pueden compartir
    timestamp: el reloj de Windows tiene ~15 ms de resolución).
    """
    desde = hasta - timedelta(minutes=ventana_minutos)
    hasta_iso = hasta_iso or hasta.isoformat()  # el string tal como está guardado, si se tiene
    row = conn.execute(
        f"""
        SELECT COUNT(*) FROM audit_log
        WHERE usuario_id = ?
          AND tipo_accion IN ({', '.join('?' for _ in ACCIONES_ACCESO_DENEGADO)})
          AND timestamp > ?
          AND (timestamp < ? OR (timestamp = ? AND event_id <= ?))
        """,
        (usuario_id, *ACCIONES_ACCESO_DENEGADO, desde.isoformat(), hasta_iso, hasta_iso,
         hasta_event_id if hasta_event_id is not None else 2**62),
    ).fetchone()
    return row[0] if row else 0


def _es_exportacion_masiva(evento: Dict) -> Optional[str]:
    if evento.get("tipo_accion") != "EXPORTACION":
        return None
    filas = evento.get("filas_exportadas")
    try:
        filas = int(filas) if filas is not None else None
    except (TypeError, ValueError):
        filas = None
    if filas is not None and filas > UMBRAL_EXPORTACION_MASIVA:
        return f"{filas:,} filas exportadas (umbral: {UMBRAL_EXPORTACION_MASIVA:,})"
    # El interceptor de HU-2.3 ya lo pudo haber clasificado como masiva.
    if "masiva" in (evento.get("motivo_alerta") or "").lower():
        return evento["motivo_alerta"]
    return None


def _es_acceso_denegado_repetido(conn: sqlite3.Connection, evento: Dict) -> Optional[str]:
    """
    Requiere que el evento ya esté insertado (el dispatcher clasifica después
    del INSERT), así el conteo lo incluye a él mismo.
    """
    if evento.get("tipo_accion") not in ACCIONES_ACCESO_DENEGADO:
        return None
    ts = _parse_ts(evento.get("timestamp"))
    usuario_id = evento.get("usuario_id")
    if not ts or not usuario_id:
        return None
    total = contar_accesos_denegados(conn, usuario_id, ts, hasta_event_id=evento.get("event_id"),
                                     hasta_iso=evento.get("timestamp"))
    if total >= UMBRAL_ACCESOS_DENEGADOS:
        return (
            f"{total} accesos denegados/fallidos en los últimos "
            f"{VENTANA_ACCESOS_DENEGADOS_MIN} minutos"
        )
    return None


def clasificar_evento(conn: sqlite3.Connection, evento: Dict) -> Optional[ClasificacionCritica]:
    """
    CA1 — Determina si `evento` (una fila de audit_log) es crítico según el
    catálogo. Devuelve None si no lo es; si coincide con varios tipos (p. ej.
    una exportación masiva que además es anómala), los reporta todos y la
    severidad es la mayor de ellos — se manda UNA notificación por evento.
    """
    motivos: Dict[str, str] = {}

    motivo = _es_exportacion_masiva(evento)
    if motivo:
        motivos["EXPORTACION_MASIVA"] = motivo

    motivo = _es_acceso_denegado_repetido(conn, evento)
    if motivo:
        motivos["ACCESOS_DENEGADOS_REPETIDOS"] = motivo

    if evento.get("nivel_alerta") == "ANOMALIA":
        motivos["ANOMALIA_DETECTADA"] = evento.get("motivo_alerta") or "Marcado como anomalía (HU-6.3)"

    if evento.get("tipo_accion") == "FIRMA_INVALIDA":
        motivos["FIRMA_INVALIDA"] = evento.get("motivo_fallo") or "Firma digital inválida"

    if evento.get("tipo_accion") == "AUDITORIA_DESACTIVADA":
        motivos["AUDITORIA_DESACTIVADA"] = (
            evento.get("motivo_alerta") or evento.get("contexto_ejecucion") or "Auditoría desactivada"
        )

    if not motivos:
        return None

    tipos = [c for c in CATALOGO_EVENTOS_CRITICOS if c in motivos]  # orden del catálogo
    severidad = max((CATALOGO_EVENTOS_CRITICOS[t].severidad for t in tipos), key=severidad_rank)
    return ClasificacionCritica(tipos=tipos, severidad=severidad, motivos=motivos)


__all__ = [
    "SEVERIDADES",
    "CATALOGO_EVENTOS_CRITICOS",
    "TipoEventoCritico",
    "ClasificacionCritica",
    "clasificar_evento",
    "contar_accesos_denegados",
    "UMBRAL_ACCESOS_DENEGADOS",
    "VENTANA_ACCESOS_DENEGADOS_MIN",
]
