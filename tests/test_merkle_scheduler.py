"""
tests/test_merkle_scheduler.py
==============================
PDGTRAZDSA-148 — El job periódico de publicación de raíces Merkle corre de
verdad con APScheduler (dependencia declarada en requirements.txt).
"""

import json
import os
import time
from datetime import datetime, timedelta, timezone

import pytest

from audit_tracer import merkle_scheduler
from audit_tracer.db import get_central_connection
from audit_tracer.merkle import verify_external_anchor
from audit_tracer.models.audit_log import insert_event

apscheduler = pytest.importorskip("apscheduler")


def _hora(delta_h):
    return (datetime.now(timezone.utc).replace(minute=20, second=0, microsecond=0, tzinfo=None)
            - timedelta(hours=delta_h))


@pytest.fixture
def central(tmp_path):
    db = str(tmp_path / "central.db")
    conn = get_central_connection(db)
    for h in (3, 2, 0):  # dos horas completas y la hora en curso
        for i in range(3):
            insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA",
                                "dataset_nombre": "A.csv",
                                "timestamp": (_hora(h) + timedelta(minutes=i)).isoformat()})
    conn.close()
    return db, str(tmp_path / "anclas")


def _archivos(anclas):
    return sorted(os.listdir(anclas)) if os.path.isdir(anclas) else []


def test_apscheduler_esta_declarado_como_dependencia():
    from pathlib import Path
    raiz = Path(__file__).resolve().parent.parent
    assert "apscheduler" in (raiz / "requirements.txt").read_text().lower()
    assert "apscheduler" in (raiz / "pyproject.toml").read_text().lower()


def test_el_job_publica_los_lotes_completos_y_no_la_hora_en_curso(central):
    db, anclas = central
    merkle_scheduler.run_publish_job(db_path=db, anchors_dir=anclas)
    esperados = sorted(f"merkle_{_hora(h).strftime('%Y-%m-%dT%H')}.json" for h in (3, 2))
    assert _archivos(anclas) == esperados          # la hora en curso queda pendiente


def test_las_anclas_del_job_verifican_y_el_job_es_idempotente(central):
    db, anclas = central
    merkle_scheduler.run_publish_job(db_path=db, anchors_dir=anclas)
    antes = {f: open(os.path.join(anclas, f), encoding="utf-8").read() for f in _archivos(anclas)}
    merkle_scheduler.run_publish_job(db_path=db, anchors_dir=anclas)
    assert {f: open(os.path.join(anclas, f), encoding="utf-8").read() for f in _archivos(anclas)} == antes
    conn = get_central_connection(db)
    try:
        for h in (3, 2):
            r = verify_external_anchor(conn, _hora(h).strftime("%Y-%m-%dT%H"), anclas)
            assert r["integrity_ok"] and r["leaf_count_match"]
    finally:
        conn.close()


def test_el_scheduler_arranca_ejecuta_el_job_y_lo_deja_programado_cada_hora(central):
    db, anclas = central
    merkle_scheduler.start_scheduler(db_path=db, anchors_dir=anclas, interval_hours=1)
    try:
        sch = merkle_scheduler._scheduler
        assert sch is not None and sch.running
        job = sch.get_job("merkle_publish_job")
        assert job is not None and job.trigger.interval == timedelta(hours=1)
        limite = time.monotonic() + 15
        while len(_archivos(anclas)) < 2 and time.monotonic() < limite:
            time.sleep(0.2)
        assert len(_archivos(anclas)) == 2          # corrió al arrancar, sin intervención
    finally:
        merkle_scheduler.stop_scheduler()


def test_el_job_vuelve_a_correr_solo_y_publica_lo_nuevo(tmp_path):
    db, anclas = str(tmp_path / "c.db"), str(tmp_path / "anclas")
    conn = get_central_connection(db)
    insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA",
                        "timestamp": _hora(5).isoformat()})
    conn.close()
    merkle_scheduler.start_scheduler(db_path=db, anchors_dir=anclas, interval_hours=1 / 3600)  # cada segundo
    try:
        limite = time.monotonic() + 15
        while len(_archivos(anclas)) < 1 and time.monotonic() < limite:
            time.sleep(0.2)
        assert len(_archivos(anclas)) == 1
        conn = get_central_connection(db)       # llega un evento de otra hora completa
        insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA",
                            "timestamp": _hora(4).isoformat()})
        conn.close()
        limite = time.monotonic() + 15
        while len(_archivos(anclas)) < 2 and time.monotonic() < limite:
            time.sleep(0.2)
        assert len(_archivos(anclas)) == 2      # la segunda ejecución automática lo publicó
    finally:
        merkle_scheduler.stop_scheduler()
