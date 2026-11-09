"""
audit_tracer/utils/zona_horaria.py
===================================
Hora de Colombia para todo lo que se le muestra a una persona.

Los timestamps se GUARDAN en UTC y así deben seguir: hash_integridad,
firmas Ed25519 y lotes de Merkle se calculan sobre ese valor exacto, y
el cliente (Colab) y el servidor pueden estar en zonas distintas. Este
módulo solo convierte al presentar (dashboard, CSV, mensajes) y al
interpretar fechas que escribe una persona (filtros por día).

Colombia usa UTC-5 todo el año (sin horario de verano), así que basta un
desfase fijo: no depende de la base tz del sistema operativo.
"""

from datetime import date, datetime, time, timedelta, timezone
from typing import Optional, Union

ZONA_COLOMBIA = timezone(timedelta(hours=-5), "COT")
ETIQUETA_ZONA = "hora Colombia"


def a_hora_colombia(valor: Union[str, datetime, None]) -> Optional[datetime]:
    """
    Convierte un timestamp a hora de Colombia. Un timestamp sin zona se
    asume UTC (convención de todo audit_tracer). None o vacío → None.
    """
    if valor in (None, ""):
        return None
    if isinstance(valor, str):
        texto = valor.strip().replace(" ", "T", 1).replace("Z", "+00:00")
        dt = datetime.fromisoformat(texto)
    else:
        dt = valor
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(ZONA_COLOMBIA)


def formatear_fecha(valor, segundos: bool = True, vacio: str = "—") -> str:
    """'2026-10-26 14:05:09' en hora de Colombia; si no se puede leer, el valor tal cual."""
    try:
        dt = a_hora_colombia(valor)
    except (TypeError, ValueError):
        return str(valor)
    if dt is None:
        return vacio
    return dt.strftime("%Y-%m-%d %H:%M:%S" if segundos else "%Y-%m-%d %H:%M")


def ahora_colombia() -> datetime:
    return datetime.now(ZONA_COLOMBIA)


def hoy_colombia() -> date:
    return ahora_colombia().date()


def _a_utc_iso(dt_local: datetime) -> str:
    return dt_local.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="microseconds")


def inicio_dia_utc(dia: Union[str, date, None]) -> Optional[str]:
    """Primer instante (en UTC ISO) del día `dia` de Colombia, para filtrar timestamps."""
    if not dia:
        return None
    if isinstance(dia, str):
        dia = date.fromisoformat(dia)
    return _a_utc_iso(datetime.combine(dia, time.min, ZONA_COLOMBIA))


def fin_dia_utc(dia: Union[str, date, None]) -> Optional[str]:
    """Último instante (en UTC ISO) del día `dia` de Colombia, para filtrar timestamps."""
    if not dia:
        return None
    if isinstance(dia, str):
        dia = date.fromisoformat(dia)
    return _a_utc_iso(datetime.combine(dia, time.max, ZONA_COLOMBIA))


def lote_a_hora_colombia(batch_hour: str) -> str:
    """Lote horario de Merkle ('YYYY-MM-DDTHH', en UTC) → '2026-10-26 12:00–12:59'."""
    try:
        inicio = a_hora_colombia(f"{batch_hour}:00:00")
    except (TypeError, ValueError):
        return str(batch_hour)
    return f"{inicio:%Y-%m-%d %H}:00–{inicio:%H}:59"
