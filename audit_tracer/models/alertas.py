"""
alertas.py — Modelo de datos de las alertas en tiempo real (HU-7.2).

Dos tablas, ambas en la base CENTRAL y creadas de forma perezosa en la
conexión que se les pase (mismo patrón que tokens_acceso / codigos_dispositivo):

  - alertas_destinatarios (Sub-tarea 4): a quién se notifica y con qué
    severidad mínima. Se administra desde el dashboard (/admin/alertas).
    Un destinatario es un ROL (se resuelve a los correos de los usuarios
    activos con ese rol) o un EMAIL suelto (p. ej. un buzón de cumplimiento).

  - alertas_notificaciones: historial de cada notificación disparada
    (una fila por evento crítico): estado del envío, destinatarios, error.

Ninguna de las dos está sujeta a los triggers de inmutabilidad de audit_log
(HU-5.4): son metadata operativa que necesita mutar (activar/desactivar un
destinatario, pasar una notificación de PENDIENTE a ENVIADA). El evento
auditado en sí sigue intacto en audit_log.
"""

import sqlite3
from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional

# Orden de severidad: un destinatario con severidad_minima = 'ALTA' recibe
# eventos ALTA y CRITICA, pero no MEDIA.
SEVERIDADES = ("MEDIA", "ALTA", "CRITICA")

TIPOS_DESTINO = ("ROL", "EMAIL")

# Estados posibles de una notificación.
ESTADO_PENDIENTE = "PENDIENTE"
ESTADO_ENVIADA = "ENVIADA"
ESTADO_FALLIDA = "FALLIDA"
ESTADO_SIN_DESTINATARIOS = "SIN_DESTINATARIOS"
ESTADO_SIN_SERVICIO = "SIN_SERVICIO_CORREO"
ESTADO_AGRUPADA = "AGRUPADA"  # suprimida por ventana anti-spam (ver catálogo)

# Destinatarios sembrados la primera vez que se crea la tabla, para que el
# sistema notifique desde el primer momento sin configuración manual:
# el AUDITOR es el rol del oficial de cumplimiento (recibe todo) y el ADMIN
# recibe solo lo de severidad ALTA o superior. Se pueden editar o
# desactivar desde el dashboard; no se vuelven a sembrar.
DESTINATARIOS_POR_DEFECTO = (
    ("ROL", "AUDITOR", "MEDIA"),
    ("ROL", "ADMIN", "ALTA"),
)


def severidad_rank(severidad: Optional[str]) -> int:
    """Posición de la severidad en SEVERIDADES (-1 si no es válida)."""
    try:
        return SEVERIDADES.index((severidad or "").upper())
    except ValueError:
        return -1


def _ahora() -> str:
    return datetime.utcnow().isoformat()


def ensure_alert_tables(conn: sqlite3.Connection) -> None:
    """Crea (si no existen) las tablas de alertas y siembra los destinatarios por defecto."""
    existia = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='alertas_destinatarios'"
    ).fetchone() is not None

    conn.execute("""
        CREATE TABLE IF NOT EXISTS alertas_destinatarios (
            destinatario_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            tipo_destino      TEXT    NOT NULL CHECK (tipo_destino IN ('ROL', 'EMAIL')),
            valor             TEXT    NOT NULL,
            severidad_minima  TEXT    NOT NULL DEFAULT 'MEDIA'
                              CHECK (severidad_minima IN ('MEDIA', 'ALTA', 'CRITICA')),
            tipos_evento      TEXT,   -- CSV de códigos del catálogo; NULL = todos
            activo            INTEGER NOT NULL DEFAULT 1,
            creado_por        TEXT    NOT NULL DEFAULT 'SISTEMA',
            creado_en         TEXT    NOT NULL,
            actualizado_en    TEXT,
            UNIQUE (tipo_destino, valor)
        );
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alertas_notificaciones (
            notificacion_id   INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id          INTEGER NOT NULL UNIQUE,
            evento_uuid       TEXT,
            usuario_id        TEXT,
            tipo_accion       TEXT,
            tipos_criticos    TEXT    NOT NULL,  -- CSV de códigos del catálogo
            severidad         TEXT    NOT NULL,
            destinatarios     TEXT,              -- CSV de correos
            estado            TEXT    NOT NULL DEFAULT 'PENDIENTE',
            intentos          INTEGER NOT NULL DEFAULT 0,
            error             TEXT,
            creado_en         TEXT    NOT NULL,
            enviado_en        TEXT
        );
    """)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alertas_notif_usuario "
        "ON alertas_notificaciones(usuario_id, creado_en);"
    )

    if not existia:
        ahora = _ahora()
        for tipo, valor, severidad in DESTINATARIOS_POR_DEFECTO:
            conn.execute(
                """
                INSERT OR IGNORE INTO alertas_destinatarios
                    (tipo_destino, valor, severidad_minima, creado_por, creado_en)
                VALUES (?, ?, ?, 'SISTEMA', ?)
                """,
                (tipo, valor, severidad, ahora),
            )
    conn.commit()


# ──────────────────────────────────────────────────────────────
# Destinatarios (Sub-tarea 4)
# ──────────────────────────────────────────────────────────────

def _fila_destinatario(row) -> Dict:
    d = dict(row)
    d["tipos_evento"] = [t for t in (d.get("tipos_evento") or "").split(",") if t]
    d["activo"] = bool(d["activo"])
    return d


def listar_destinatarios(conn: sqlite3.Connection, solo_activos: bool = False) -> List[Dict]:
    ensure_alert_tables(conn)
    conn.row_factory = sqlite3.Row
    query = "SELECT * FROM alertas_destinatarios"
    if solo_activos:
        query += " WHERE activo = 1"
    query += " ORDER BY tipo_destino DESC, valor ASC"
    return [_fila_destinatario(r) for r in conn.execute(query).fetchall()]


def obtener_destinatario(conn: sqlite3.Connection, destinatario_id: int) -> Optional[Dict]:
    ensure_alert_tables(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM alertas_destinatarios WHERE destinatario_id = ?", (destinatario_id,)
    ).fetchone()
    return _fila_destinatario(row) if row else None


def _normalizar_tipos(tipos_evento: Optional[Iterable[str]]) -> Optional[str]:
    tipos = sorted({t.strip().upper() for t in (tipos_evento or []) if t and t.strip()})
    return ",".join(tipos) if tipos else None


def crear_destinatario(
    conn: sqlite3.Connection,
    tipo_destino: str,
    valor: str,
    severidad_minima: str = "MEDIA",
    tipos_evento: Optional[Iterable[str]] = None,
    creado_por: str = "SISTEMA",
) -> int:
    """Crea un destinatario. Lanza sqlite3.IntegrityError si (tipo, valor) ya existe."""
    ensure_alert_tables(conn)
    tipo_destino = tipo_destino.upper()
    valor = valor.strip().upper() if tipo_destino == "ROL" else valor.strip().lower()
    cursor = conn.execute(
        """
        INSERT INTO alertas_destinatarios
            (tipo_destino, valor, severidad_minima, tipos_evento, creado_por, creado_en)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (tipo_destino, valor, severidad_minima.upper(), _normalizar_tipos(tipos_evento),
         creado_por, _ahora()),
    )
    conn.commit()
    return cursor.lastrowid


def actualizar_destinatario(
    conn: sqlite3.Connection,
    destinatario_id: int,
    severidad_minima: Optional[str] = None,
    tipos_evento: Optional[Iterable[str]] = None,
    activo: Optional[bool] = None,
) -> bool:
    """Actualiza severidad, tipos (lista vacía = todos) y/o estado activo. True si existía."""
    ensure_alert_tables(conn)
    sets, params = [], []
    if severidad_minima is not None:
        sets.append("severidad_minima = ?")
        params.append(severidad_minima.upper())
    if tipos_evento is not None:
        sets.append("tipos_evento = ?")
        params.append(_normalizar_tipos(tipos_evento))
    if activo is not None:
        sets.append("activo = ?")
        params.append(1 if activo else 0)
    if not sets:
        return obtener_destinatario(conn, destinatario_id) is not None
    sets.append("actualizado_en = ?")
    params.append(_ahora())
    params.append(destinatario_id)
    cursor = conn.execute(
        f"UPDATE alertas_destinatarios SET {', '.join(sets)} WHERE destinatario_id = ?", params
    )
    conn.commit()
    return cursor.rowcount > 0


def eliminar_destinatario(conn: sqlite3.Connection, destinatario_id: int) -> bool:
    ensure_alert_tables(conn)
    cursor = conn.execute(
        "DELETE FROM alertas_destinatarios WHERE destinatario_id = ?", (destinatario_id,)
    )
    conn.commit()
    return cursor.rowcount > 0


def resolver_correos_destino(
    conn: sqlite3.Connection,
    severidad: str,
    tipos_criticos: Iterable[str],
) -> List[str]:
    """
    CA2 — Devuelve los correos (sin duplicados, en minúsculas) que deben
    recibir una notificación de `severidad` para los `tipos_criticos` dados:

      - solo destinatarios activos;
      - cuya severidad_minima sea <= severidad del evento;
      - cuyo filtro tipos_evento esté vacío (todos) o incluya alguno de los tipos;
      - un destinatario ROL se expande a los usuarios ACTIVOS con ese rol.
    """
    rank_evento = severidad_rank(severidad)
    tipos = {t.upper() for t in tipos_criticos}
    correos: List[str] = []
    vistos = set()

    for dest in listar_destinatarios(conn, solo_activos=True):
        if severidad_rank(dest["severidad_minima"]) > rank_evento:
            continue
        if dest["tipos_evento"] and not tipos.intersection(dest["tipos_evento"]):
            continue

        if dest["tipo_destino"] == "EMAIL":
            candidatos = [dest["valor"]]
        else:
            filas = conn.execute(
                "SELECT email FROM usuarios WHERE rol = ? AND activo = 1", (dest["valor"],)
            ).fetchall()
            candidatos = [f[0] for f in filas]

        for correo in candidatos:
            c = (correo or "").strip().lower()
            if c and c not in vistos:
                vistos.add(c)
                correos.append(c)

    return correos


# ──────────────────────────────────────────────────────────────
# Historial de notificaciones
# ──────────────────────────────────────────────────────────────

def registrar_notificacion(
    conn: sqlite3.Connection,
    evento: Dict,
    tipos_criticos: Iterable[str],
    severidad: str,
    estado: str = ESTADO_PENDIENTE,
    destinatarios: Optional[Iterable[str]] = None,
    error: Optional[str] = None,
) -> Optional[int]:
    """
    Registra la notificación de un evento crítico. Devuelve su id, o None si
    ese event_id ya tenía una (UNIQUE): así un evento nunca se notifica dos veces.
    """
    ensure_alert_tables(conn)
    try:
        cursor = conn.execute(
            """
            INSERT INTO alertas_notificaciones
                (event_id, evento_uuid, usuario_id, tipo_accion, tipos_criticos,
                 severidad, destinatarios, estado, error, creado_en)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                evento["event_id"], evento.get("evento_uuid"), evento.get("usuario_id"),
                evento.get("tipo_accion"), ",".join(tipos_criticos), severidad,
                ",".join(destinatarios or []) or None, estado, error, _ahora(),
            ),
        )
    except sqlite3.IntegrityError:
        conn.rollback()
        return None
    conn.commit()
    return cursor.lastrowid


def actualizar_notificacion(
    conn: sqlite3.Connection,
    notificacion_id: int,
    estado: str,
    intentos: int,
    error: Optional[str] = None,
    destinatarios: Optional[Iterable[str]] = None,
) -> None:
    sets = ["estado = ?", "intentos = ?", "error = ?"]
    params: list = [estado, intentos, error]
    if destinatarios is not None:
        sets.append("destinatarios = ?")
        params.append(",".join(destinatarios) or None)
    if estado == ESTADO_ENVIADA:
        sets.append("enviado_en = ?")
        params.append(_ahora())
    params.append(notificacion_id)
    conn.execute(
        f"UPDATE alertas_notificaciones SET {', '.join(sets)} WHERE notificacion_id = ?", params
    )
    conn.commit()


def existe_notificacion_reciente(
    conn: sqlite3.Connection,
    usuario_id: str,
    tipo_critico: str,
    desde: datetime,
    excluir_event_id: Optional[int] = None,
) -> bool:
    """
    ¿Ya se notificó (o se intentó notificar) `tipo_critico` para `usuario_id`
    desde `desde`? Usado para no mandar un correo por cada intento de una
    misma ráfaga de accesos denegados.
    """
    ensure_alert_tables(conn)
    row = conn.execute(
        """
        SELECT 1 FROM alertas_notificaciones
        WHERE usuario_id = ?
          AND (',' || tipos_criticos || ',') LIKE ?
          AND estado != ?
          AND creado_en >= ?
          AND event_id != ?
        LIMIT 1
        """,
        (usuario_id, f"%,{tipo_critico},%", ESTADO_AGRUPADA, desde.isoformat(),
         excluir_event_id if excluir_event_id is not None else -1),
    ).fetchone()
    return row is not None


def listar_notificaciones(conn: sqlite3.Connection, limite: int = 50) -> List[Dict]:
    ensure_alert_tables(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alertas_notificaciones ORDER BY notificacion_id DESC LIMIT ?", (limite,)
    ).fetchall()
    return [dict(r) for r in rows]


def obtener_notificacion_por_evento(conn: sqlite3.Connection, event_id: int) -> Optional[Dict]:
    ensure_alert_tables(conn)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM alertas_notificaciones WHERE event_id = ?", (event_id,)
    ).fetchone()
    return dict(row) if row else None


def resumen_notificaciones(conn: sqlite3.Connection, horas: int = 24) -> Dict[str, int]:
    """Conteo por estado de las notificaciones de las últimas `horas`."""
    ensure_alert_tables(conn)
    desde = (datetime.utcnow() - timedelta(hours=horas)).isoformat()
    filas = conn.execute(
        "SELECT estado, COUNT(*) FROM alertas_notificaciones WHERE creado_en >= ? GROUP BY estado",
        (desde,),
    ).fetchall()
    return {estado: total for estado, total in filas}
