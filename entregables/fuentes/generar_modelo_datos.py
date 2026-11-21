"""
Genera entregables/02_modelo_datos_auditoria.md (Anexo 11) y los diagramas
entidad-relación (img/er_local.svg, img/er_central.svg) a partir de:

  * entregables/fuentes/esquema.json   — esquema real (extraer_esquema.py)
  * entregables/fuentes/ejemplos_esquema.json — una fila real por tabla,
    tomada de la validación MIMIC del 21/11/2026, con secretos enmascarados
    (se regenera con --ejemplos <central.db> <local.db>)

    python entregables/fuentes/generar_modelo_datos.py
"""
import html
import json
import re
import sqlite3
import sys
from pathlib import Path

FUENTES = Path(__file__).resolve().parent
CARPETA = FUENTES.parent
IMG = CARPETA / "img"

# ── Descripciones del diccionario (leídas del código y de los comentarios del esquema) ──
DESC = {
    "audit_log": {
        "event_id": "Identificador local autoincremental. Distinto en cada base; no entra en el hash.",
        "evento_uuid": "Identificador global del evento (UUID4). Igual en la base local y en la central; garantiza que reenviar un evento no lo duplique.",
        "usuario_id": "Usuario que ejecutó la operación. 'DESCONOCIDO' si no se identificó (el evento pasa a CRITICO); 'SISTEMA' en altas automáticas.",
        "sesion_id": "Sesión de trabajo: un UUID por proceso de Python o por sesión del dashboard. 'SIN_SESION' si falta.",
        "timestamp": "Fecha y hora UTC (ISO 8601) del momento exacto de la operación.",
        "tipo_accion": "Tipo de evento (CARGA, CONSULTA, TRANSFORMACION, EXPORTACION, ACCESO_FALLIDO, INICIO_SESION, ...). Texto libre: no hay CHECK.",
        "dataset_nombre": "Archivo o dataset afectado (nombre del archivo leído o 'merge(A,B)').",
        "columnas_afectadas": "Columnas leídas, consultadas o transformadas, como lista JSON. Nunca valores de celdas.",
        "ruta_destino": "Ruta del archivo escrito en una EXPORTACION.",
        "filas_exportadas": "Número de filas exportadas (EXPORTACION).",
        "sobrescritura": "1 si la exportación sobrescribió un archivo existente; 0 si no.",
        "contexto_ejecucion": "Origen: 'Script: <archivo> | Env: <entorno> | Host: <equipo>' y datos adicionales (formato, comparación de estructura, duración).",
        "motivo_fallo": "Causa del fallo en ACCESO_FALLIDO; '[SUBTIPO] descripción' en TRANSFORMACION.",
        "nivel_alerta": "NORMAL, ADVERTENCIA, CRITICO o ANOMALIA.",
        "motivo_alerta": "Explicación del nivel de alerta.",
        "hash_integridad": "SHA-256 (hex) sobre los 13 campos funcionales del evento, con claves ordenadas.",
        "firma_digital": "Firma Ed25519 (base64url) del evento con la llave del usuario. Nula en eventos generados por el servidor.",
    },
    "audit_sync_queue": {
        "event_id": "Evento de la base local pendiente de sincronizar (FK a audit_log).",
        "evento_uuid": "UUID del evento, para confirmar con el servidor.",
        "estado": "PENDIENTE, SINCRONIZADO o ERROR.",
        "intentos": "Intentos de envío realizados.",
        "ultimo_intento": "Fecha UTC del último intento.",
        "ultimo_error": "Mensaje del último error de envío.",
        "sincronizado_en": "Fecha UTC en que el servidor confirmó el evento.",
    },
    "audit_intentos_bloqueados": {
        "intento_id": "Identificador del intento.",
        "timestamp": "Fecha UTC del intento (la pone SQLite).",
        "tipo_intento": "INTENTO_MODIFICACION (UPDATE) o INTENTO_ELIMINACION (DELETE).",
        "event_id_objetivo": "event_id que se intentó modificar o borrar.",
        "usuario_id": "Usuario del evento objetivo (no quien ejecutó la sentencia: SQLite no lo conoce).",
        "sesion_id": "Sesión del evento objetivo.",
        "nivel_alerta": "Siempre CRITICO.",
        "motivo_alerta": "Descripción del intento bloqueado.",
    },
    "usuarios": {
        "usuario_id": "Identificador del usuario (UUID4).",
        "email": "Correo institucional; único.",
        "password_hash": "Contraseña con bcrypt y sal propia; nunca en claro.",
        "rol": "ADMIN, ANALISTA, AUDITOR o CIENTIFICO_DATOS.",
        "activo": "1 activo; 0 bloqueado (5 intentos fallidos).",
        "intentos_fallidos": "Intentos fallidos acumulados desde el último acceso exitoso.",
        "llave_publica": "Llave pública Ed25519 (PEM) para verificar las firmas del usuario.",
    },
    "tokens_acceso": {
        "token_id": "Identificador del token.",
        "usuario_id": "Dueño del token (FK a usuarios).",
        "token": "Token personal de 256 bits (se guarda en claro: brecha B3 de la matriz).",
        "fecha_creacion": "Fecha UTC de emisión.",
        "fecha_expiracion": "Fecha UTC de vencimiento (30 días por defecto).",
        "estado": "ACTIVO, REVOCADO o EXPIRADO.",
        "creado_por": "Origen: LOGIN, DEVICE_LOGIN o el usuario administrador que lo emitió.",
    },
    "codigos_dispositivo": {
        "codigo": "Código corto que ve el usuario (formato XXXX-XXXX).",
        "device_code": "Secreto largo que solo conoce el proceso de la librería; sirve para consultar el estado.",
        "estado": "PENDIENTE, CONFIRMADO, CONSUMIDO o EXPIRADO.",
        "usuario_id": "Usuario que confirmó el código en el dashboard.",
        "token": "Token emitido al confirmar (se entrega una sola vez a la librería).",
        "fecha_creacion": "Fecha UTC de creación.",
        "fecha_expiracion": "Fecha UTC de vencimiento del código.",
    },
    "alertas_destinatarios": {
        "destinatario_id": "Identificador.",
        "tipo_destino": "ROL (todos los usuarios activos de ese rol) o EMAIL.",
        "valor": "Nombre del rol o dirección de correo.",
        "severidad_minima": "Severidad mínima que recibe: MEDIA, ALTA o CRITICA.",
        "tipos_evento": "Tipos críticos que recibe (separados por coma); vacío = todos.",
        "activo": "1 activo; 0 desactivado.",
        "creado_por": "Usuario administrador que lo creó.",
        "creado_en": "Fecha UTC de creación.",
        "actualizado_en": "Fecha UTC del último cambio.",
    },
    "alertas_notificaciones": {
        "notificacion_id": "Identificador.",
        "event_id": "Evento notificado (uno por evento: UNIQUE).",
        "evento_uuid": "UUID del evento.",
        "usuario_id": "Usuario del evento.",
        "tipo_accion": "Tipo de acción del evento.",
        "tipos_criticos": "Tipos del catálogo que aplicaron (EXPORTACION_MASIVA, ANOMALIA_DETECTADA, ...).",
        "severidad": "MEDIA, ALTA o CRITICA.",
        "destinatarios": "Correos a los que se envió, separados por coma.",
        "estado": "PENDIENTE, ENVIADA, FALLIDA, AGRUPADA, SIN_DESTINATARIOS o SIN_SERVICIO_CORREO.",
        "intentos": "Intentos de envío.",
        "error": "Último error de envío.",
        "creado_en": "Fecha UTC de creación.",
        "enviado_en": "Fecha UTC de envío exitoso.",
    },
    "audit_alert_reviews": {
        "event_id": "Alerta (evento) en revisión.",
        "estado": "PENDIENTE, EN_REVISION o RESUELTA.",
        "responsable_id": "Usuario responsable de la revisión.",
        "version": "Versión para control de concurrencia optimista.",
    },
    "audit_alert_history": {
        "id": "Identificador.",
        "event_id": "Alerta (evento) a la que pertenece el cambio.",
        "autor_id": "Usuario que hizo el cambio.",
        "fecha": "Fecha UTC del cambio.",
        "estado": "Estado asignado.",
        "responsable_id": "Responsable asignado.",
        "comentario": "Comentario del revisor.",
    },
    "audit_saved_filters": {
        "id": "Identificador.",
        "usuario_id": "Dueño del filtro.",
        "nombre": "Nombre del filtro (único por usuario, sin distinguir mayúsculas).",
        "filtros": "Parámetros del filtro en JSON.",
    },
    "audit_notification_settings": {
        "usuario_id": "Usuario.",
        "en_panel": "1 si recibe avisos en el panel.",
        "por_correo": "1 si recibe avisos por correo.",
        "leido_hasta": "Último aviso leído (marca de tiempo Unix).",
        "correo_hasta": "Último aviso enviado por correo.",
        "correo_reserva": "Identificador de la reserva del envío en curso.",
        "correo_reserva_hasta": "Vencimiento de la reserva (marca de tiempo Unix).",
    },
}

PROPOSITO = {
    "audit_log": "Bitácora de auditoría: un registro inmutable por evento.",
    "audit_sync_queue": "Cola de sincronización de la librería (solo base local).",
    "audit_intentos_bloqueados": "Constancia de los UPDATE/DELETE bloqueados por los disparadores.",
    "usuarios": "Cuentas, roles y llave pública de firma.",
    "tokens_acceso": "Tokens personales de la librería y del dashboard.",
    "codigos_dispositivo": "Login por código de dispositivo (RFC 8628).",
    "alertas_destinatarios": "Quién recibe las alertas por correo.",
    "alertas_notificaciones": "Resultado de cada notificación de evento crítico.",
    "audit_alert_reviews": "Estado de revisión de cada alerta (espacio de auditoría).",
    "audit_alert_history": "Historial de cambios de estado de las alertas.",
    "audit_saved_filters": "Filtros guardados por usuario en el espacio de auditoría.",
    "audit_notification_settings": "Preferencias de aviso por usuario.",
}

CREACION = {
    "audit_log": "schema/audit_log.sql (local) y schema/audit_log_central.sql (central)",
    "audit_sync_queue": "schema/audit_log.sql; db._migrate_sync_queue",
    "audit_intentos_bloqueados": "schema/*.sql; db._IMMUTABILITY_DDL",
    "usuarios": "schema/usuarios.sql",
    "tokens_acceso": "schema/tokens.sql",
    "codigos_dispositivo": "models/device_codes.py (primer uso del login por dispositivo)",
    "alertas_destinatarios": "models/alertas.py (al arrancar el despachador)",
    "alertas_notificaciones": "models/alertas.py",
    "audit_alert_reviews": "schema/audit_workspace.sql (primer uso de /auditoria)",
    "audit_alert_history": "schema/audit_workspace.sql",
    "audit_saved_filters": "schema/audit_workspace.sql",
    "audit_notification_settings": "schema/audit_workspace.sql",
}

# Relaciones lógicas (FK declaradas o por valor). (origen.campo, destino.campo, cardinalidad, declarada)
RELACIONES = [
    ("audit_log.usuario_id", "usuarios.usuario_id", "N:1", False),
    ("tokens_acceso.usuario_id", "usuarios.usuario_id", "N:1", True),
    ("audit_sync_queue.event_id", "audit_log.event_id", "1:1", True),
    ("audit_intentos_bloqueados.event_id_objetivo", "audit_log.event_id", "N:1", False),
    ("codigos_dispositivo.usuario_id", "usuarios.usuario_id", "N:1", False),
    ("alertas_notificaciones.event_id", "audit_log.event_id", "1:1", False),
    ("audit_alert_reviews.event_id", "audit_log.event_id", "1:1", True),
    ("audit_alert_history.event_id", "audit_log.event_id", "N:1", True),
    ("audit_alert_history.autor_id", "usuarios.usuario_id", "N:1", True),
    ("audit_saved_filters.usuario_id", "usuarios.usuario_id", "N:1", True),
    ("audit_notification_settings.usuario_id", "usuarios.usuario_id", "1:1", True),
]

SECRETOS = {("usuarios", "password_hash"), ("usuarios", "llave_publica"), ("tokens_acceso", "token"),
            ("codigos_dispositivo", "token"), ("codigos_dispositivo", "device_code"), ("audit_log", "firma_digital")}


def extraer_ejemplos(central: str, local: str) -> None:
    ejemplos = {}
    for base, ruta in (("central", central), ("local", local)):
        conn = sqlite3.connect(ruta)
        conn.row_factory = sqlite3.Row
        for (tabla,) in conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            orden = "ORDER BY filas_exportadas DESC" if tabla == "audit_log" else ""
            fila = conn.execute(f"SELECT * FROM {tabla} {orden} LIMIT 1").fetchone()
            if fila is None:
                continue
            valores = {}
            for k in fila.keys():
                v = fila[k]
                if (tabla, k) in SECRETOS and v:
                    v = f"{str(v)[:12]}… ({len(str(v))} caracteres, enmascarado)"
                valores[k] = v
            ejemplos.setdefault(tabla, valores)
        conn.close()
    (FUENTES / "ejemplos_esquema.json").write_text(json.dumps(ejemplos, ensure_ascii=False, indent=1), encoding="utf-8")


# ── Diagramas ER en SVG ─────────────────────────────────────────────────────

def _svg(tablas: dict, posiciones: dict, titulo: str, ancho: int, alto: int) -> str:
    fk_de = {}
    for o, d, card, decl in RELACIONES:
        t, c = o.split(".")
        fk_de.setdefault(t, set()).add(c)
    cajas, lineas = [], []
    geom = {}
    for nombre, (x, y) in posiciones.items():
        cols = tablas[nombre]["columnas"]
        w = 250
        h = 26 + 15 * len(cols) + 6
        geom[nombre] = (x, y, w, h)
        filas = []
        for i, c in enumerate(cols):
            marca = "PK" if c["pk"] else ("FK" if c["nombre"] in fk_de.get(nombre, ()) else "")
            yy = y + 40 + 15 * i
            peso = "700" if c["pk"] else "400"
            filas.append(
                f'<text x="{x + 8}" y="{yy}" font-size="10.5" fill="#64748b" font-family="Consolas,monospace">{marca}</text>'
                f'<text x="{x + 30}" y="{yy}" font-size="11" font-weight="{peso}" fill="#0f172a" font-family="Segoe UI,Arial">{html.escape(c["nombre"])}</text>'
                f'<text x="{x + w - 8}" y="{yy}" font-size="10" fill="#475569" text-anchor="end" font-family="Consolas,monospace">{html.escape(c["tipo"] or "")}{" NN" if c["notnull"] and not c["pk"] else ""}</text>')
        cajas.append(
            f'<g><rect x="{x}" y="{y}" width="{w}" height="{h}" rx="6" fill="#ffffff" stroke="#1e3a5f" stroke-width="1.4"/>'
            f'<rect x="{x}" y="{y}" width="{w}" height="24" rx="6" fill="#1e3a5f"/>'
            f'<rect x="{x}" y="{y + 16}" width="{w}" height="8" fill="#1e3a5f"/>'
            f'<text x="{x + 10}" y="{y + 17}" font-size="12.5" font-weight="700" fill="#ffffff" font-family="Segoe UI,Arial">{nombre}</text>'
            + "".join(filas) + "</g>")
    for o, d, card, decl in RELACIONES:
        to, co = o.split(".")
        td, cd = d.split(".")
        if to not in geom or td not in geom:
            continue
        xo, yo, wo, ho = geom[to]
        xd, yd, wd, hd = geom[td]
        iy_o = yo + 36 + 15 * [c["nombre"] for c in tablas[to]["columnas"]].index(co)
        iy_d = yd + 36 + 15 * [c["nombre"] for c in tablas[td]["columnas"]].index(cd)
        if xo + wo < xd:
            x1, x2 = xo + wo, xd
        elif xd + wd < xo:
            x1, x2 = xo, xd + wd
        else:
            x1, x2 = xo + wo, xd + wd
        mx = (x1 + x2) / 2 if x1 != x2 else x1 + 30
        trazo = "" if decl else ' stroke-dasharray="5,4"'
        lineas.append(
            f'<path d="M{x1},{iy_o} C{mx},{iy_o} {mx},{iy_d} {x2},{iy_d}" fill="none" stroke="#0369a1" stroke-width="1.3"{trazo}/>'
            f'<circle cx="{x2}" cy="{iy_d}" r="3" fill="#0369a1"/>'
            f'<text x="{mx + 4}" y="{(iy_o + iy_d) / 2 - 4}" font-size="10" fill="#0369a1" font-family="Segoe UI,Arial">{card}</text>')
    leyenda = (f'<text x="20" y="{alto - 14}" font-size="10.5" fill="#475569" font-family="Segoe UI,Arial">'
               'PK llave primaria · FK referencia · NN NOT NULL · línea continua: FOREIGN KEY declarada · '
               'línea punteada: relación por valor (sin restricción en SQLite)</text>')
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{ancho}" height="{alto}" viewBox="0 0 {ancho} {alto}">'
            f'<rect width="100%" height="100%" fill="#f8fafc"/>'
            f'<text x="20" y="28" font-size="16" font-weight="700" fill="#1e3a5f" font-family="Segoe UI,Arial">{html.escape(titulo)}</text>'
            + "".join(lineas) + "".join(cajas) + leyenda + "</svg>")


def diagramas(esquema: dict) -> None:
    IMG.mkdir(exist_ok=True)
    local = {
        "usuarios": (40, 60), "tokens_acceso": (40, 250),
        "audit_log": (380, 60), "audit_sync_queue": (720, 60), "audit_intentos_bloqueados": (720, 250),
    }
    (IMG / "er_local.svg").write_text(
        _svg(esquema["local"]["tablas"], local, "Base local de la librería (~/.audit_tracer/audit_trail.db)", 1010, 470),
        encoding="utf-8")
    central = {
        "codigos_dispositivo": (40, 60), "tokens_acceso": (40, 230), "usuarios": (40, 400),
        "audit_saved_filters": (40, 580), "audit_notification_settings": (40, 700),
        "audit_log": (380, 60), "audit_intentos_bloqueados": (380, 400),
        "alertas_notificaciones": (720, 60), "alertas_destinatarios": (720, 300),
        "audit_alert_reviews": (720, 480), "audit_alert_history": (720, 590),
    }
    (IMG / "er_central.svg").write_text(
        _svg(esquema["central"]["tablas"], central, "Base central del servidor (audit_central.db)", 1010, 885),
        encoding="utf-8")


def mermaid(esquema: dict, base: str) -> str:
    tablas = esquema[base]["tablas"]
    lineas = ["erDiagram"]
    for nombre, t in tablas.items():
        lineas.append(f"    {nombre} {{")
        for c in t["columnas"]:
            tipo = (c["tipo"] or "TEXT").split()[0]
            clave = " PK" if c["pk"] else ""
            lineas.append(f"        {tipo} {c['nombre']}{clave}")
        lineas.append("    }")
    simbolos = {"N:1": "}o--||", "1:1": "|o--||"}
    for o, d, card, decl in RELACIONES:
        to, td = o.split(".")[0], d.split(".")[0]
        if to in tablas and td in tablas:
            lineas.append(f'    {to} {simbolos[card]} {td} : "{o.split(".")[1]}"')
    return "\n".join(lineas)


def _limpiar_sql(sql: str) -> str:
    sql = re.sub(r"\n[ \t]*\n+", "\n", sql.strip())
    return "\n".join(l[8:] if l.startswith("        ") and not sql.startswith("CREATE TABLE audit") else l
                     for l in sql.splitlines())


def documento(esquema: dict, ejemplos: dict) -> str:
    centrales = esquema["central"]["tablas"]
    locales = esquema["local"]["tablas"]
    todas = list(dict.fromkeys(list(locales) + list(centrales)))
    resumen = "\n".join(
        f"| `{t}` | {'Sí' if t in locales else '—'} | {'Sí' if t in centrales else '—'} | {PROPOSITO[t]} | `{CREACION[t]}` |"
        for t in todas)

    ddl = []
    for base, titulo in (("local", "Base local (librería)"), ("central", "Base central (servidor)")):
        ddl.append(f"## 3.{1 if base == 'local' else 2} {titulo}\n")
        for t, v in esquema[base]["tablas"].items():
            bloques = [v["sql"].strip() + ";"]
            bloques += [i["sql"].strip() + ";" for i in v["indices"] if i["sql"]]
            bloques += [d["sql"].strip() + ";" for d in v["disparadores"]]
            ddl.append(f"**{t}**\n\n```sql\n" + "\n\n".join(bloques) + "\n```\n")

    dicc = []
    for t in todas:
        v = centrales.get(t) or locales[t]
        ej = ejemplos.get(t, {})
        unicos = set()
        for i in v["indices"]:
            m = re.search(r"\(([^)]*)\)", i["sql"] or "")
            if i["unico"] and m and "," not in m.group(1):
                unicos.add(m.group(1).strip())
        sql = v["sql"]
        filas = []
        for c in v["columnas"]:
            restr = []
            if c["pk"]:
                restr.append("PK" + (" AUTOINCREMENT" if "AUTOINCREMENT" in sql and re.search(rf"\b{c['nombre']}\b[^,\n]*AUTOINCREMENT", sql) else ""))
            if re.search(rf"\b{c['nombre']}\b[^,\n]*\bUNIQUE\b", sql) or c["nombre"] in unicos:
                restr.append("UNIQUE")
            fk = [f for f in v["llaves_foraneas"] if f["desde"] == c["nombre"]]
            if fk:
                restr.append(f"FK → {fk[0]['tabla']}.{fk[0]['hacia']}")
            chk = re.search(rf"\b{c['nombre']}\b[^\n]*?CHECK \(([^)]*\))\)", sql)
            if chk:
                restr.append(f"CHECK ({chk.group(1)})")
            if c["default"] is not None:
                restr.append(f"DEFAULT {c['default']}")
            nulo = "No" if (c["notnull"] or c["pk"]) else "Sí"
            ejemplo = ej.get(c["nombre"])
            ejemplo = "—" if ejemplo in (None, "") else str(ejemplo)
            if len(ejemplo) > 90:
                ejemplo = ejemplo[:87] + "…"
            ejemplo = ejemplo.replace("|", "\\|")
            filas.append(f"| {t} | `{c['nombre']}` | {c['tipo']} | {nulo} | {'; '.join(restr) or '—'} | "
                         f"{DESC[t][c['nombre']]} | `{ejemplo}` |" if ejemplo != "—" else
                         f"| {t} | `{c['nombre']}` | {c['tipo']} | {nulo} | {'; '.join(restr) or '—'} | "
                         f"{DESC[t][c['nombre']]} | — |")
        dicc.append(f"## 4.{len(dicc) + 1} {t}\n\n{PROPOSITO[t]}\n\n"
                    "| Tabla | Campo | Tipo | Nulo | Restricción | Descripción | Ejemplo |\n|---|---|---|---|---|---|---|\n"
                    + "\n".join(filas) + "\n")

    return f"""---
titulo: Modelo de datos de auditoría
anexo: Anexo 11 · Documento técnico
fecha: 2026-11-21
---

[TOC]

# 1. Alcance y fuentes

El sistema usa **dos bases SQLite con el mismo modelo de evento**:

* **Base local** de la librería, en el equipo del científico de datos (`~/.audit_tracer/audit_trail.db`, o la carpeta de Google Drive en Colab). Guarda cada evento antes de cualquier envío y la cola de sincronización.
* **Base central** del servidor (`audit_central.db` junto a `app.py`). Consolida los eventos de todos los usuarios y guarda cuentas, tokens, códigos de dispositivo, alertas y el espacio de auditoría.

Motor: SQLite en modo **WAL** (`PRAGMA journal_mode = WAL`, verificado: ambas bases reportan `{esquema['local']['journal_mode']}`/`{esquema['central']['journal_mode']}`), con `busy_timeout = 5000` ms (`audit_tracer/db.py`).

**De dónde sale este documento.** El DDL y las columnas no se copiaron de los archivos `.sql`: `entregables/fuentes/extraer_esquema.py` crea las dos bases desde cero con el mismo código del sistema (incluidas las tablas que se crean en el primer uso) y lee `sqlite_master` y los `PRAGMA`. Los ejemplos son filas reales de la validación con MIMIC-III del 21/11/2026, con los secretos enmascarados. Código: commit `31361a3`.

| Tabla | Local | Central | Propósito | Se crea en |
|---|---|---|---|---|
{resumen}

**Llaves foráneas.** Las FOREIGN KEY declaradas solo se hacen cumplir donde se activa `PRAGMA foreign_keys = ON` (las tablas del espacio de auditoría, `audit_workspace.py:40`). `audit_log.usuario_id` no tiene llave foránea: un evento puede pertenecer a `DESCONOCIDO` o a un usuario de otra base. `tipo_accion` y `nivel_alerta` son texto libre (sin `CHECK`): los valores válidos los impone el código.

**Inmutabilidad.** Los disparadores `trg_audit_log_no_update` y `trg_audit_log_no_delete` existen en las dos bases. Antes de abortar con `RAISE(FAIL)` insertan una fila en `audit_intentos_bloqueados`. `RAISE(FAIL)` aborta la sentencia pero conserva lo que el disparador ya escribió, así que la constancia queda guardada; la excepción es que quien ejecuta la sentencia la envuelva en una transacción explícita y la revierta (`BEGIN … ROLLBACK`): en ese caso no queda constancia (verificado el 21/11/2026 contra una base central creada con `get_central_connection`).

# 2. Diagramas entidad-relación

![Diagrama entidad-relación de la base local](img/er_local.svg)

![Diagrama entidad-relación de la base central](img/er_central.svg)

Fuente Mermaid de la base central (equivalente, para editarla o versionarla):

```mermaid
{mermaid(esquema, 'central')}
```

Fuente Mermaid de la base local:

```mermaid
{mermaid(esquema, 'local')}
```

# 3. DDL completo (SQLite)

Sentencias tal como quedan en `sqlite_master` (incluidos los comentarios del código fuente), seguidas de los índices y disparadores de cada tabla.

{chr(10).join(ddl)}

# 4. Diccionario de datos

Los ejemplos de `audit_log` son la exportación masiva del caso 2 de la validación MIMIC-III (evento real del 21/11/2026). Un guion (—) en la columna Ejemplo indica que el campo o la tabla estaba vacío en esa corrida (p. ej. las tablas del espacio de auditoría, que se crean en el primer uso de `/auditoria`).

{chr(10).join(dicc)}

# 5. Correspondencia con las entidades del documento

El documento (sección 7.2) promete un modelo con siete entidades. En la implementación **todas son atributos de `audit_log`** (más `usuarios` para la identidad), no tablas separadas:

| Entidad prometida | Dónde está | Observación |
|---|---|---|
| Usuario | `usuarios` (`usuario_id`, `email`, `rol`) y `audit_log.usuario_id` | Relación por valor, sin FK. |
| Acción realizada | `audit_log.tipo_accion` (+ subtipo en `motivo_fallo` para transformaciones) | Catálogo en el Anexo 10. |
| Dataset afectado | `audit_log.dataset_nombre`, `columnas_afectadas` | No hay tabla de datasets: el dataset se identifica por nombre de archivo. |
| Fecha y hora | `audit_log.timestamp` (UTC, ISO 8601) | La interfaz lo muestra en hora de Colombia. |
| Tipo de operación | `audit_log.tipo_accion`, `nivel_alerta` | — |
| Origen de la solicitud | `audit_log.contexto_ejecucion` (script/notebook, entorno, host) y `sesion_id` | Texto con formato fijo, no columnas separadas. No se guarda la IP. |
| Contexto de ejecución | `audit_log.contexto_ejecucion`, `sesion_id`, `ruta_destino`, `filas_exportadas`, `sobrescritura` | — |

Atributos que el documento no menciona y que el modelo sí tiene: `evento_uuid` (idempotencia), `hash_integridad` (SHA-256), `firma_digital` (Ed25519) y la tabla `audit_intentos_bloqueados`.
"""


def main():
    if len(sys.argv) == 4 and sys.argv[1] == "--ejemplos":
        extraer_ejemplos(sys.argv[2], sys.argv[3])
    esquema = json.loads((FUENTES / "esquema.json").read_text(encoding="utf-8"))
    ejemplos = json.loads((FUENTES / "ejemplos_esquema.json").read_text(encoding="utf-8"))
    diagramas(esquema)
    (CARPETA / "02_modelo_datos_auditoria.md").write_text(documento(esquema, ejemplos), encoding="utf-8")
    print("02_modelo_datos_auditoria.md e img/er_*.svg generados")


if __name__ == "__main__":
    main()
