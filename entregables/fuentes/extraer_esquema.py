"""
Extrae el esquema REAL de las bases SQLite de Audit Tracer (local y central)
creándolas desde cero con el mismo código que usa el sistema, y lo guarda en
entregables/fuentes/esquema.json (DDL, columnas, índices, disparadores y
llaves foráneas). Fuente del Anexo 11 (02_modelo_datos_auditoria).

    python entregables/fuentes/extraer_esquema.py
"""
import json
import os
import sqlite3
import sys
import tempfile
from contextlib import closing
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(RAIZ))
_home = tempfile.mkdtemp(prefix="esquema_home_")
os.environ.update(HOME=_home, USERPROFILE=_home, AUDIT_ALERTAS_DESACTIVADAS="1")

from audit_tracer.db import get_central_connection, get_connection  # noqa: E402
from audit_tracer.models import alertas, device_codes  # noqa: E402
from audit_tracer.audit_workspace import workspace_db  # noqa: E402


def volcar(conn):
    objetos = conn.execute(
        "SELECT type, name, tbl_name, sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY CASE type WHEN 'table' THEN 0 WHEN 'index' THEN 1 ELSE 2 END, name"
    ).fetchall()
    tablas = {}
    for tipo, nombre, tabla, sql in objetos:
        if tipo == "table":
            tablas[nombre] = {
                "sql": sql,
                "columnas": [dict(zip(("cid", "nombre", "tipo", "notnull", "default", "pk"), c))
                             for c in conn.execute(f"PRAGMA table_info('{nombre}')")],
                "llaves_foraneas": [dict(zip(("id", "seq", "tabla", "desde", "hacia", "on_update", "on_delete", "match"), f))
                                    for f in conn.execute(f"PRAGMA foreign_key_list('{nombre}')")],
                "indices": [], "disparadores": [],
            }
    for tipo, nombre, tabla, sql in objetos:
        if tipo == "index":
            tablas[tabla]["indices"].append({"nombre": nombre, "sql": sql,
                                             "unico": bool(conn.execute(
                                                 f"SELECT \"unique\" FROM pragma_index_list('{tabla}') WHERE name=?",
                                                 (nombre,)).fetchone()[0])})
        elif tipo == "trigger":
            tablas[tabla]["disparadores"].append({"nombre": nombre, "sql": sql})
    return {"tablas": tablas,
            "journal_mode": conn.execute("PRAGMA journal_mode").fetchone()[0]}


def main():
    d = Path(tempfile.mkdtemp(prefix="esquema_"))
    with closing(get_connection(str(d / "audit_trail.db"))):
        pass
    with closing(get_connection(str(d / "audit_trail.db"))) as local:  # reabrir aplica migraciones
        esquema_local = volcar(local)

    central_path = str(d / "audit_central.db")
    with closing(get_central_connection(central_path)) as c:
        alertas.ensure_alert_tables(c)
        device_codes._ensure_device_codes_table(c)  # el modelo la crea en el primer uso del login por dispositivo
    with workspace_db(lambda: get_central_connection(central_path)):
        pass
    with closing(get_central_connection(central_path)) as central:
        esquema_central = volcar(central)

    salida = Path(__file__).resolve().parent / "esquema.json"
    salida.write_text(json.dumps({"local": esquema_local, "central": esquema_central}, ensure_ascii=False, indent=1),
                      encoding="utf-8")
    for nombre, e in (("local", esquema_local), ("central", esquema_central)):
        print(nombre, e["journal_mode"], sorted(e["tablas"]))


if __name__ == "__main__":
    main()
