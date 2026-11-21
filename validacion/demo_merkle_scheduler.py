"""
Demostración del job periódico de Merkle con APScheduler: arranca el scheduler
(intervalo de 2 s para poder verlo), publica los lotes pendientes y vuelve a
correr solo cuando llegan eventos de otra hora. Salida: el log del módulo.

    python validacion/demo_merkle_scheduler.py > validacion/evidencia/<fecha>/merkle_scheduler.log
"""
import logging
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ["HOME"] = os.environ["USERPROFILE"] = tempfile.mkdtemp(prefix="merkle_demo_home_")

import apscheduler  # noqa: E402
from audit_tracer import merkle_scheduler  # noqa: E402
from audit_tracer.db import get_central_connection  # noqa: E402
from audit_tracer.models.audit_log import insert_event  # noqa: E402

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format="%(asctime)s [%(levelname)s] %(message)s")
logging.getLogger("apscheduler").setLevel(logging.INFO)

base = Path(tempfile.mkdtemp(prefix="merkle_demo_"))
db, anclas = str(base / "audit_central.db"), str(base / "anclas")
hora = lambda h: datetime.now(timezone.utc).replace(minute=20, second=0, microsecond=0, tzinfo=None) - timedelta(hours=h)


def eventos(h, n):
    conn = get_central_connection(db)
    for i in range(n):
        insert_event(conn, {"usuario_id": "u", "sesion_id": "s", "tipo_accion": "CARGA", "dataset_nombre": "A.csv",
                            "timestamp": (hora(h) + timedelta(minutes=i)).isoformat()})
    conn.close()


print(f"APScheduler {apscheduler.__version__}; fecha {datetime.now().astimezone().isoformat(timespec='seconds')}")
eventos(3, 4); eventos(2, 3); eventos(0, 2)
print("Eventos: 2 horas completas (4 y 3 eventos) y la hora en curso (2 eventos)")
merkle_scheduler.start_scheduler(db_path=db, anchors_dir=anclas, interval_hours=2 / 3600)
time.sleep(3)
print("Anclas tras el primer ciclo:", sorted(os.listdir(anclas)))
print(">>> llegan eventos de otra hora completa")
eventos(1, 5)
time.sleep(4)
print("Anclas tras la ejecución automática siguiente:", sorted(os.listdir(anclas)))
merkle_scheduler.stop_scheduler()
