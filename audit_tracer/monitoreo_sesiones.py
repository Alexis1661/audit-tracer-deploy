"""
audit_tracer/monitoreo_sesiones.py
==================================
LIB-D2 / CAN-D1 / LIB-T3 (21/11/2026) — Sesiones de la librería que dejaron
de reportar.

Si alguien mata el proceso, desactiva la sincronización o modifica la
librería para que no envíe nada, el servidor solo ve el INICIO_SESION y
después silencio. sesiones_sin_cierre() lista las sesiones de la librería
(contexto MODO_LIBRERIA) sin CIERRE_SESION ni SESION_INTERRUMPIDA cuyo
último evento recibido tiene más de `horas` horas. El panel de
sincronización del dashboard las muestra para que el administrador averigüe
qué pasó.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional


def sesiones_sin_cierre(conn, horas: float = 24, limite: int = 50,
                        ahora: Optional[datetime] = None) -> List[Dict]:
    ahora = ahora or datetime.utcnow()
    corte = (ahora - timedelta(hours=horas)).isoformat()
    cursor = conn.execute(
        """
        SELECT i.sesion_id, i.usuario_id, MIN(i.timestamp) AS inicio,
               (SELECT MAX(t.timestamp) FROM audit_log t WHERE t.sesion_id = i.sesion_id) AS ultimo,
               (SELECT COUNT(*) FROM audit_log t WHERE t.sesion_id = i.sesion_id) AS eventos
        FROM audit_log i
        WHERE i.tipo_accion = 'INICIO_SESION'
          AND i.contexto_ejecucion LIKE 'MODO_LIBRERIA%'
          AND NOT EXISTS (
              SELECT 1 FROM audit_log c
              WHERE c.sesion_id = i.sesion_id AND c.tipo_accion IN ('CIERRE_SESION', 'SESION_INTERRUMPIDA')
          )
        GROUP BY i.sesion_id, i.usuario_id
        HAVING ultimo < ?
        ORDER BY ultimo DESC
        LIMIT ?
        """,
        (corte, limite),
    )
    nombres = [d[0] for d in cursor.description]
    return [dict(zip(nombres, fila)) for fila in cursor.fetchall()]
