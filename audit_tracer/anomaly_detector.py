"""
audit_tracer/anomaly_detector.py — Módulo de detección de anomalías sobre eventos centralizados.
HU-6.3:
  - CA1 / PDGTRAZDSA-153: Cálculo de promedios históricos por usuario (accesos, transformaciones, exportaciones).
  - CA2 / PDGTRAZDSA-154: Regla de volumen anómalo (marca nivel_alerta = ANOMALIA).
  - CA3 / PDGTRAZDSA-155: Regla de horario inusual (marca nivel_alerta = ANOMALIA).
  - CA4 / PDGTRAZDSA-156: Regla de correlación entre usuarios sobre el mismo dataset.
  - CA5 / PDGTRAZDSA-157: Soporte para visualización e inspección de anomalías.
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple


# Tipos de acciones según categoría de operación clínica
ACCIONES_ACCESO = ('CARGA', 'CONSULTA')
ACCIONES_TRANSFORMACION = ('TRANSFORMACION',)
ACCIONES_EXPORTACION = ('EXPORTACION',)
ACCIONES_AUDITABLES_VOLUMEN = ACCIONES_ACCESO + ACCIONES_TRANSFORMACION + ACCIONES_EXPORTACION

# Constantes por defecto para las reglas de detección
DEFAULT_FACTOR_UMBRAL_VOLUMEN = 3.0
DEFAULT_MIN_FILAS_UMBRAL = 50
DEFAULT_MIN_OPS_DIA = 5
DEFAULT_VENTANA_CORRELACION_MINUTOS = 15
DEFAULT_UMBRAL_USUARIOS_CORRELACION = 2
DEFAULT_HORA_INICIO_LABORAL = 7   # 07:00
DEFAULT_HORA_FIN_LABORAL = 19     # 19:00


# ─────────────────────────────────────────────────────────────────────────────
# CA1 / PDGTRAZDSA-153: Cálculo de promedios históricos por usuario
# ─────────────────────────────────────────────────────────────────────────────

def _parse_iso_timestamp(ts_str: Optional[str]) -> Optional[datetime]:
    """Parsea una cadena de fecha/hora ISO 8601 a un objeto datetime de forma tolerante."""
    if not ts_str:
        return None
    try:
        clean_ts = ts_str.replace('Z', '')
        if 'T' in clean_ts:
            return datetime.fromisoformat(clean_ts)
        elif ' ' in clean_ts:
            return datetime.fromisoformat(clean_ts.replace(' ', 'T'))
        return datetime.strptime(clean_ts[:10], '%Y-%m-%d')
    except Exception:
        return None


def calcular_promedios_historicos(
    conn: sqlite3.Connection,
    usuario_id: Optional[str] = None,
    excluir_fecha: Optional[str] = None
) -> Dict[str, Any]:
    """
    CA1 / PDGTRAZDSA-153:
    Calcula, por usuario (o globalmente si usuario_id=None), el promedio histórico
    de volumen de operaciones: accesos (CARGA, CONSULTA), transformaciones
    (TRANSFORMACION) y exportaciones (EXPORTACION), así como el total general
    y promedio de filas exportadas.

    Opcionalmente permite excluir_fecha (YYYY-MM-DD) para calcular la línea base
    histórica sin contaminarla con el día evaluado.

    Args:
        conn: Conexión SQLite a la base de datos (central o local).
        usuario_id: ID del usuario a consultar, o None para calcular el de todos.
        excluir_fecha: Fecha 'YYYY-MM-DD' opcional para omitir del histórico base.

    Returns:
        Dict con los promedios y métricas históricas del usuario.
    """
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    params: List[Any] = []
    where_clauses: List[str] = []

    if usuario_id:
        where_clauses.append("usuario_id = ?")
        params.append(usuario_id)

    if excluir_fecha:
        where_clauses.append("substr(timestamp, 1, 10) != ?")
        params.append(excluir_fecha[:10])

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else "WHERE 1=1"

    # 1. Conteo de días distintos en los que el usuario realizó operaciones
    query_dias = f"""
        SELECT COUNT(DISTINCT substr(timestamp, 1, 10)) as dias_activos
        FROM audit_log
        {where_sql}
          AND tipo_accion IN ({', '.join('?' for _ in ACCIONES_AUDITABLES_VOLUMEN)})
    """
    cursor.execute(query_dias, params + list(ACCIONES_AUDITABLES_VOLUMEN))
    row_dias = cursor.fetchone()
    dias_raw = row_dias['dias_activos'] if row_dias and row_dias['dias_activos'] else 0

    # Si se excluyó fecha y no quedan días, volver a calcular sin excluir fecha
    if dias_raw == 0 and excluir_fecha:
        return calcular_promedios_historicos(conn, usuario_id=usuario_id, excluir_fecha=None)

    dias_activos = max(1, dias_raw)

    # 2. Conteo por tipo de acción
    query_counts = f"""
        SELECT
            tipo_accion,
            COUNT(*) as total_eventos,
            SUM(CASE WHEN filas_exportadas IS NOT NULL THEN filas_exportadas ELSE 0 END) as suma_filas,
            COUNT(CASE WHEN filas_exportadas IS NOT NULL AND filas_exportadas > 0 THEN 1 END) as count_con_filas
        FROM audit_log
        {where_sql}
        GROUP BY tipo_accion
    """
    cursor.execute(query_counts, params)
    rows_counts = cursor.fetchall()

    counts: Dict[str, int] = {}
    suma_filas_exportadas = 0
    count_export_con_filas = 0

    for r in rows_counts:
        t = r['tipo_accion']
        counts[t] = r['total_eventos']
        if t in ACCIONES_EXPORTACION:
            suma_filas_exportadas += (r['suma_filas'] or 0)
            count_export_con_filas += (r['count_con_filas'] or 0)

    total_accesos = sum(counts.get(a, 0) for a in ACCIONES_ACCESO)
    total_transformaciones = sum(counts.get(t, 0) for t in ACCIONES_TRANSFORMACION)
    total_exportaciones = sum(counts.get(e, 0) for e in ACCIONES_EXPORTACION)
    total_operaciones = total_accesos + total_transformaciones + total_exportaciones

    # Promedios diarios
    promedio_accesos = round(total_accesos / dias_activos, 2)
    promedio_transformaciones = round(total_transformaciones / dias_activos, 2)
    promedio_exportaciones = round(total_exportaciones / dias_activos, 2)
    promedio_total = round(total_operaciones / dias_activos, 2)

    # Promedio de filas exportadas por evento
    promedio_filas = 0.0
    if count_export_con_filas > 0:
        promedio_filas = round(suma_filas_exportadas / count_export_con_filas, 2)

    return {
        'usuario_id': usuario_id or 'GLOBAL',
        'dias_activos': dias_raw,
        'total_operaciones': total_operaciones,
        'total_accesos': total_accesos,
        'total_transformaciones': total_transformaciones,
        'total_exportaciones': total_exportaciones,
        'promedio_accesos_diarios': promedio_accesos,
        'promedio_transformaciones_diarias': promedio_transformaciones,
        'promedio_exportaciones_diarias': promedio_exportaciones,
        'promedio_total_diario': promedio_total,
        'promedio_filas_exportadas': promedio_filas,
    }


# ─────────────────────────────────────────────────────────────────────────────
# CA2 / PDGTRAZDSA-154: Regla de volumen anómalo
# ─────────────────────────────────────────────────────────────────────────────

def contar_operaciones_dia(
    conn: sqlite3.Connection,
    usuario_id: str,
    fecha_iso: str
) -> int:
    """Cuenta el número de operaciones ejecutadas por un usuario en una fecha específica (YYYY-MM-DD)."""
    fecha_prefix = fecha_iso[:10]
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT COUNT(*) FROM audit_log
        WHERE usuario_id = ?
          AND substr(timestamp, 1, 10) = ?
          AND tipo_accion IN (?, ?, ?, ?)
        """,
        (usuario_id, fecha_prefix, 'CARGA', 'CONSULTA', 'TRANSFORMACION', 'EXPORTACION')
    )
    row = cursor.fetchone()
    return row[0] if row else 0


def evaluar_regla_volumen(
    conn: sqlite3.Connection,
    evento: Dict[str, Any],
    factor_umbral: float = DEFAULT_FACTOR_UMBRAL_VOLUMEN,
    min_filas_umbral: int = DEFAULT_MIN_FILAS_UMBRAL,
    min_ops_dia: int = DEFAULT_MIN_OPS_DIA
) -> Tuple[bool, Optional[str]]:
    """
    CA2 / PDGTRAZDSA-154:
    Evalúa si un evento supera significativamente el promedio histórico del usuario.
    Verifica dos facetas del volumen de datos clínicos:
      1. Volumen de filas (ej. filas_exportadas en EXPORTACION o TRANSFORMACION):
         Si filas_exportadas supera factor_umbral * promedio_filas_exportadas (y >= min_filas_umbral).
      2. Frecuencia/volumen de operaciones en el día:
         Si la cantidad de operaciones ejecutadas por el usuario en el día supera
         factor_umbral * promedio_total_diario (y >= min_ops_dia).

    Returns:
        (es_anomalo: bool, motivo_alerta: Optional[str])
    """
    usuario_id = evento.get('usuario_id')
    if not usuario_id or usuario_id == 'DESCONOCIDO':
        return False, None

    ts = evento.get('timestamp')
    fecha_prefix = ts[:10] if ts else None

    # Obtener línea base excluyendo la fecha actual para no autoinflar el promedio
    promedios = calcular_promedios_historicos(conn, usuario_id=usuario_id, excluir_fecha=fecha_prefix)

    # 1. Evaluación por volumen de filas exportadas
    filas = evento.get('filas_exportadas')
    if filas is not None and filas > 0:
        promedio_filas = promedios['promedio_filas_exportadas']
        # Si existe histórico previo de filas
        if promedio_filas > 0:
            if filas > (factor_umbral * promedio_filas) and filas >= min_filas_umbral:
                return True, (
                    f"Volumen anómalo: {filas:,} filas supera significativamente "
                    f"el promedio histórico del usuario ({promedio_filas:.1f} filas)"
                )
        elif filas >= min_filas_umbral * 5:
            # Si no tenía histórico de exportaciones y de repente exporta una cantidad notable
            return True, (
                f"Volumen anómalo: exportación de {filas:,} filas sin antecedente previo "
                f"de este volumen para el usuario"
            )

    # 2. Evaluación por volumen de operaciones en el día del evento
    if ts:
        ops_hoy = contar_operaciones_dia(conn, usuario_id, ts)
        promedio_diario = promedios['promedio_total_diario']
        if promedio_diario > 0:
            if ops_hoy >= (factor_umbral * promedio_diario) and ops_hoy >= min_ops_dia:
                return True, (
                    f"Volumen anómalo: {ops_hoy} operaciones en el día supera significativamente "
                    f"el promedio diario histórico del usuario ({promedio_diario:.1f} ops/día)"
                )

    return False, None


# ─────────────────────────────────────────────────────────────────────────────
# CA3 / PDGTRAZDSA-155: Regla de horario inusual
# ─────────────────────────────────────────────────────────────────────────────

def obtener_horario_habitual(
    conn: sqlite3.Connection,
    usuario_id: str,
    min_eventos: int = 5,
    hora_inicio_defecto: int = DEFAULT_HORA_INICIO_LABORAL,
    hora_fin_defecto: int = DEFAULT_HORA_FIN_LABORAL,
    margen_tolerancia: int = 1
) -> Tuple[int, int]:
    """
    Calcula el rango de horas habituales [hora_inicio, hora_fin] del usuario
    a partir de sus eventos históricos en audit_log.
    Si el usuario tiene menos de min_eventos históricos, retorna el horario
    laboral institucional por defecto [07:00, 19:00].
    """
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT timestamp FROM audit_log
        WHERE usuario_id = ?
        ORDER BY timestamp ASC
        """,
        (usuario_id,)
    )
    rows = cursor.fetchall()
    horas: List[int] = []
    for r in rows:
        dt = _parse_iso_timestamp(r[0])
        if dt:
            horas.append(dt.hour)

    if len(horas) < min_eventos:
        return (hora_inicio_defecto, hora_fin_defecto)

    min_hora = max(0, min(horas) - margen_tolerancia)
    max_hora = min(23, max(horas) + margen_tolerancia)

    return (min_hora, max_hora)


def evaluar_regla_horario(
    conn: sqlite3.Connection,
    evento: Dict[str, Any],
    min_eventos_historicos: int = 5,
    hora_inicio_defecto: int = DEFAULT_HORA_INICIO_LABORAL,
    hora_fin_defecto: int = DEFAULT_HORA_FIN_LABORAL,
    margen_tolerancia: int = 1
) -> Tuple[bool, Optional[str]]:
    """
    CA3 / PDGTRAZDSA-155:
    Detecta accesos fuera del horario habitual del usuario.
    Si el usuario no tiene suficiente histórico, se evalúa contra el
    horario institucional estándar (07:00 - 19:00).

    Returns:
        (es_anomalo: bool, motivo_alerta: Optional[str])
    """
    ts_str = evento.get('timestamp')
    dt = _parse_iso_timestamp(ts_str)
    if not dt:
        return False, None

    usuario_id = evento.get('usuario_id')
    if not usuario_id or usuario_id == 'DESCONOCIDO':
        return False, None

    hora_evento = dt.hour
    hora_min, hora_max = obtener_horario_habitual(
        conn,
        usuario_id,
        min_eventos=min_eventos_historicos,
        hora_inicio_defecto=hora_inicio_defecto,
        hora_fin_defecto=hora_fin_defecto,
        margen_tolerancia=margen_tolerancia
    )

    if hora_evento < hora_min or hora_evento > hora_max:
        return True, (
            f"Horario inusual: acceso registrado a las {hora_evento:02d}:{dt.minute:02d} "
            f"fuera del horario habitual del usuario ({hora_min:02d}:00 - {hora_max:02d}:00)"
        )

    return False, None


# ─────────────────────────────────────────────────────────────────────────────
# CA4 / PDGTRAZDSA-156: Regla de correlación entre usuarios sobre el mismo dataset
# ─────────────────────────────────────────────────────────────────────────────

def evaluar_regla_correlacion(
    conn: sqlite3.Connection,
    evento: Dict[str, Any],
    ventana_minutos: int = DEFAULT_VENTANA_CORRELACION_MINUTOS,
    umbral_usuarios: int = DEFAULT_UMBRAL_USUARIOS_CORRELACION
) -> Tuple[bool, Optional[str]]:
    """
    CA4 / PDGTRAZDSA-156:
    Detecta cuando el mismo dataset es accedido por múltiples usuarios distintos
    en una ventana corta de tiempo y genera una alerta de correlación.
    """
    dataset_nombre = evento.get('dataset_nombre')
    if not dataset_nombre or dataset_nombre.strip() in ('', '—', 'None'):
        return False, None

    ts_str = evento.get('timestamp')
    dt_actual = _parse_iso_timestamp(ts_str)
    if not dt_actual:
        return False, None

    usuario_actual = evento.get('usuario_id', 'DESCONOCIDO')
    desde = (dt_actual - timedelta(minutes=ventana_minutos)).isoformat()
    hasta = dt_actual.isoformat()

    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT DISTINCT usuario_id FROM audit_log
        WHERE dataset_nombre = ?
          AND timestamp >= ? AND timestamp <= ?
          AND usuario_id != 'DESCONOCIDO'
        """,
        (dataset_nombre, desde, hasta)
    )
    rows = cursor.fetchall()
    usuarios_encontrados = {r[0] for r in rows if r[0]}

    if usuario_actual and usuario_actual != 'DESCONOCIDO':
        usuarios_encontrados.add(usuario_actual)

    if len(usuarios_encontrados) >= umbral_usuarios:
        usuarios_str = ", ".join(sorted(usuarios_encontrados))
        return True, (
            f"Alerta de correlación: dataset '{dataset_nombre}' accedido por "
            f"{len(usuarios_encontrados)} usuarios distintos ({usuarios_str}) "
            f"en una ventana de {ventana_minutos} minutos"
        )

    return False, None


# ─────────────────────────────────────────────────────────────────────────────
# EVALUADOR INTEGRADO DE ANOMALÍAS
# ─────────────────────────────────────────────────────────────────────────────

def evaluar_evento_anomalias(
    conn: sqlite3.Connection,
    evento: Dict[str, Any],
    factor_umbral_volumen: float = DEFAULT_FACTOR_UMBRAL_VOLUMEN,
    min_filas_umbral: int = DEFAULT_MIN_FILAS_UMBRAL,
    min_ops_dia: int = DEFAULT_MIN_OPS_DIA,
    ventana_correlacion_minutos: int = DEFAULT_VENTANA_CORRELACION_MINUTOS,
    umbral_usuarios_correlacion: int = DEFAULT_UMBRAL_USUARIOS_CORRELACION,
    min_eventos_historicos_horario: int = 5
) -> Tuple[bool, Dict[str, Any], List[str]]:
    """
    Evalúa un evento contra las 3 reglas de detección de anomalías:
      1. Volumen anómalo (CA2)
      2. Horario inusual (CA3)
      3. Correlación de múltiples usuarios sobre el mismo dataset (CA4)
    """
    evento_resultado = dict(evento)
    motivos: List[str] = []

    # Regla 1: Volumen anómalo (CA2)
    anomalo_volumen, motivo_vol = evaluar_regla_volumen(
        conn, evento_resultado,
        factor_umbral=factor_umbral_volumen,
        min_filas_umbral=min_filas_umbral,
        min_ops_dia=min_ops_dia
    )
    if anomalo_volumen and motivo_vol:
        motivos.append(motivo_vol)

    # Regla 2: Horario inusual (CA3)
    anomalo_horario, motivo_hor = evaluar_regla_horario(
        conn, evento_resultado,
        min_eventos_historicos=min_eventos_historicos_horario
    )
    if anomalo_horario and motivo_hor:
        motivos.append(motivo_hor)

    # Regla 3: Correlación entre usuarios sobre el mismo dataset (CA4)
    anomalo_corr, motivo_corr = evaluar_regla_correlacion(
        conn, evento_resultado,
        ventana_minutos=ventana_correlacion_minutos,
        umbral_usuarios=umbral_usuarios_correlacion
    )
    if anomalo_corr and motivo_corr:
        motivos.append(motivo_corr)

    es_anomalo = len(motivos) > 0

    if es_anomalo:
        if evento_resultado.get('nivel_alerta') != 'CRITICO':
            evento_resultado['nivel_alerta'] = 'ANOMALIA'

        nuevo_motivo = " | ".join(motivos)
        if evento_resultado.get('motivo_alerta'):
            evento_resultado['motivo_alerta'] = f"{evento_resultado['motivo_alerta']} | {nuevo_motivo}"
        else:
            evento_resultado['motivo_alerta'] = nuevo_motivo

    return es_anomalo, evento_resultado, motivos
