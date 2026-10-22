"""
audit_tracer/merkle_scheduler.py
=================================
PDGTRAZDSA-148 — Job periódico de publicación de la raíz Merkle en el canal externo.

Este módulo ofrece dos modos de ejecución:
  1. **APScheduler** (recomendado para el servidor Flask): inicia un scheduler
     en background que publica automáticamente los lotes pasados cada hora.
  2. **Modo CLI** (``python -m audit_tracer.merkle_scheduler``): útil para
     ejecutar el job desde cron, systemd timer o cualquier orquestador externo.

El job publicará cualquier lote horario completo (pasado) que aún no tenga un
archivo de anclaje en el directorio configurado (``AUDIT_MERKLE_ANCHORS_DIR``
o ``merkle_anchors/`` relativo al proyecto).
"""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


def run_publish_job(db_path: Optional[str] = None, anchors_dir: Optional[str] = None) -> None:
    """
    Publica los anclajes Merkle de todos los lotes pasados que aún no tienen
    archivo de anclaje externo.

    Diseñado para ser llamado periódicamente por el scheduler (cada hora) o
    desde el CLI.

    Args:
        db_path:     ruta a la base de datos central. Si es None, usa la
                     conexión central por defecto (``audit_central.db``).
        anchors_dir: directorio de anclajes. Si es None, usa el valor de la
                     variable de entorno ``AUDIT_MERKLE_ANCHORS_DIR`` o el
                     directorio por defecto del módulo merkle.
    """
    from audit_tracer.db import get_central_connection
    from audit_tracer.merkle import publish_all_pending, get_pending_batch_hours

    conn_args = {} if db_path is None else {"db_path": db_path}
    conn = get_central_connection(**conn_args)

    try:
        pending = get_pending_batch_hours(conn, anchors_dir)
        if not pending:
            logger.info("[MerkleScheduler] Sin lotes pendientes de publicar.")
            return

        logger.info(
            "[MerkleScheduler] Publicando %d lote(s) pendiente(s): %s",
            len(pending),
            pending,
        )
        published = publish_all_pending(conn, anchors_dir)
        for anchor in published:
            logger.info(
                "[MerkleScheduler] Lote %s publicado → raíz=%s… (%d hojas) en %s",
                anchor.get("batch_hour"),
                str(anchor.get("root", ""))[:12],
                anchor.get("leaf_count", 0),
                anchor.get("_file_path", ""),
            )
    except Exception as exc:
        logger.error("[MerkleScheduler] Error durante publicación: %s", exc, exc_info=True)
    finally:
        conn.close()


# ── Integración con APScheduler (opcional) ──────────────────────────────────

_scheduler = None


def start_scheduler(
    db_path: Optional[str] = None,
    anchors_dir: Optional[str] = None,
    interval_hours: int = 1,
) -> None:
    """
    Inicia el job periódico de publicación usando APScheduler BackgroundScheduler.

    Llama a esta función una sola vez al arrancar el servidor Flask (en
    ``app.py``, después de ``create_app()``).

    Args:
        db_path:        ruta a la base central (None = por defecto).
        anchors_dir:    directorio de anclajes (None = por defecto).
        interval_hours: cada cuántas horas se ejecuta el job (default: 1).
    """
    global _scheduler

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        logger.warning(
            "[MerkleScheduler] APScheduler no instalado. "
            "El job periódico de Merkle no se iniciará automáticamente. "
            "Instale 'apscheduler' o ejecute el job manualmente."
        )
        return

    if _scheduler is not None and _scheduler.running:
        logger.warning("[MerkleScheduler] El scheduler ya está en ejecución.")
        return

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        func=run_publish_job,
        trigger="interval",
        hours=interval_hours,
        kwargs={"db_path": db_path, "anchors_dir": anchors_dir},
        id="merkle_publish_job",
        name="Publicación periódica de raíces Merkle",
        replace_existing=True,
        next_run_time=datetime.now(timezone.utc),  # ejecutar también al arrancar
    )
    _scheduler.start()
    logger.info(
        "[MerkleScheduler] Scheduler iniciado. Job ejecutará cada %d hora(s).",
        interval_hours,
    )


def stop_scheduler() -> None:
    """Detiene el scheduler si está en ejecución."""
    global _scheduler
    if _scheduler is not None and _scheduler.running:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("[MerkleScheduler] Scheduler detenido.")


# ── Modo CLI ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    db_path_arg = sys.argv[1] if len(sys.argv) > 1 else None
    anchors_dir_arg = sys.argv[2] if len(sys.argv) > 2 else None

    logger.info("Ejecutando job de publicación Merkle (modo CLI)...")
    run_publish_job(db_path=db_path_arg, anchors_dir=anchors_dir_arg)
    logger.info("Job completado.")
