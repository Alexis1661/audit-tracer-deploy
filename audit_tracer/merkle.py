"""
audit_tracer/merkle.py
======================
HU-6.2 — Estructura de Merkle tree y ancla externa de integridad.

Implementa:
  - PDGTRAZDSA-146: construcción del árbol de Merkle por lote horario.
  - PDGTRAZDSA-147: generación de la prueba de Merkle (Merkle proof) por evento.
  - PDGTRAZDSA-148: job periódico de publicación de la raíz en el canal externo.
  - PDGTRAZDSA-149: función de verificación externa de la raíz publicada.

El «canal externo» utilizado es un archivo JSON firmado que se persiste fuera
de la base de datos de auditoría (por defecto en merkle_anchors/), el cual
puede ser copiado o subido a un repositorio Git independiente, a un servicio
de sellado de tiempo (e.g., RFC 3161) o a cualquier almacén inmutable.

Diseño de seguridad:
  - Cada hoja del árbol es el hash_integridad ya calculado del evento (SHA-256).
  - Los nodos internos se calculan como SHA-256(hijo_izq || hijo_der).
  - Árboles con un número impar de hojas duplican la última hoja (convención
    estándar de Bitcoin / Ethereum para Merkle trees binarios completos).
  - La raíz se firma con la misma llave Ed25519 que las firmas de eventos
    (HU-6.1) para garantizar la autenticidad del anclaje externo.

Uso rápido:
    from audit_tracer.merkle import (
        build_merkle_tree, generate_merkle_proof, verify_merkle_proof,
        publish_batch_root, verify_external_anchor
    )
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ── Constantes ─────────────────────────────────────────────────────────────

# Directorio por defecto donde se publican los anclajes externos.
# Se resuelve relativo al directorio de trabajo del proceso servidor (app.py),
# igual que audit_central.db. Puede sobreescribirse con la variable de entorno
# AUDIT_MERKLE_ANCHORS_DIR o pasándolo explícitamente a publish_batch_root().
_DEFAULT_ANCHORS_DIR = os.environ.get(
    "AUDIT_MERKLE_ANCHORS_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "merkle_anchors"),
)


# ── Funciones de hashing ────────────────────────────────────────────────────

def _sha256(data: bytes) -> str:
    """Devuelve el hex-digest SHA-256 de `data`."""
    return hashlib.sha256(data).hexdigest()


def _combine(left: str, right: str) -> str:
    """
    Nodo interno del árbol: SHA-256 de la concatenación de los dos hashes hijos.
    El orden importa (izquierdo siempre a la izquierda).
    """
    return _sha256((left + right).encode("utf-8"))


# ── CA1: Construcción del árbol de Merkle por lote horario ─────────────────

def build_merkle_tree(hashes: List[str]) -> Dict:
    """
    PDGTRAZDSA-146 — Construye el árbol de Merkle completo a partir de una
    lista de hash_integridad de eventos (las hojas), ya ordenados por
    timestamp ASC + event_id ASC.

    Args:
        hashes: lista de hex-strings SHA-256 (hash_integridad de cada evento).
                Puede estar vacía; en ese caso la raíz es el hash de cadena vacía.

    Returns:
        Dict con:
          - ``root``  (str): raíz del árbol.
          - ``levels`` (List[List[str]]): todos los niveles del árbol, desde
            las hojas (nivel 0) hasta la raíz (último nivel, lista de 1 elemento).
            Útil para generar pruebas de forma eficiente.
          - ``leaf_count`` (int): número de hojas originales (antes de
            duplicación de nodo impar).
    """
    if not hashes:
        return {
            "root": _sha256(b""),
            "levels": [[]],
            "leaf_count": 0,
        }

    leaf_count = len(hashes)
    current_level = list(hashes)
    levels = [current_level[:]]  # nivel 0 = hojas originales

    while len(current_level) > 1:
        next_level: List[str] = []
        # Si el nivel tiene número impar de nodos, duplicar el último
        if len(current_level) % 2 == 1:
            current_level = current_level + [current_level[-1]]
        for i in range(0, len(current_level), 2):
            next_level.append(_combine(current_level[i], current_level[i + 1]))
        levels.append(next_level[:])
        current_level = next_level

    return {
        "root": current_level[0],
        "levels": levels,
        "leaf_count": leaf_count,
    }


def get_batch_events(
    conn: sqlite3.Connection,
    batch_hour: str,
) -> List[Dict]:
    """
    Devuelve todos los eventos de audit_log cuyo timestamp cae dentro de la
    hora indicada, ordenados por timestamp ASC, event_id ASC — el mismo orden
    que usará build_merkle_tree() para que la raíz sea reproducible.

    Args:
        conn:       conexión a la base (local o central).
        batch_hour: cadena ``"YYYY-MM-DDTHH"`` que identifica el lote horario
                    (p.ej. ``"2026-10-22T14"``).

    Returns:
        Lista de dicts con todos los campos de audit_log.
    """
    # El lote abarca [batch_hour:00:00, batch_hour:59:59.999…]
    inicio = f"{batch_hour}:00:00"
    # Incrementamos la hora en 1 para el límite superior exclusivo
    dt = datetime.strptime(batch_hour, "%Y-%m-%dT%H")
    fin_dt = dt.replace(minute=59, second=59, microsecond=999999)
    fin = fin_dt.strftime("%Y-%m-%dT%H:%M:%S.%f")

    query = """
        SELECT * FROM audit_log
        WHERE timestamp >= ? AND timestamp <= ?
        ORDER BY timestamp ASC, event_id ASC
    """
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute(query, (inicio, fin))
    return [dict(row) for row in cursor.fetchall()]


def build_batch_tree(conn: sqlite3.Connection, batch_hour: str) -> Dict:
    """
    Construye el árbol de Merkle para el lote horario ``batch_hour``.

    Returns:
        Dict con:
          - ``batch_hour`` (str)
          - ``root`` (str): raíz del árbol.
          - ``events`` (List[Dict]): eventos del lote (ordenados).
          - ``hashes`` (List[str]): hash_integridad de cada evento (hojas).
          - ``levels`` (List[List[str]]): todos los niveles del árbol.
          - ``leaf_count`` (int)
    """
    events = get_batch_events(conn, batch_hour)
    hashes = [e["hash_integridad"] for e in events]
    tree = build_merkle_tree(hashes)
    return {
        "batch_hour": batch_hour,
        "root": tree["root"],
        "events": events,
        "hashes": hashes,
        "levels": tree["levels"],
        "leaf_count": tree["leaf_count"],
    }


# ── CA2: Generación de la prueba de Merkle por evento ──────────────────────

def generate_merkle_proof(
    batch_tree: Dict,
    event_hash: str,
) -> Optional[Dict]:
    """
    PDGTRAZDSA-147 — Genera la prueba de Merkle (Merkle proof) para un evento
    dado, sin necesidad de recorrer todo el historial.

    La prueba es un camino desde la hoja (event_hash) hasta la raíz,
    compuesto por los hashes «hermanos» necesarios para reconstruir cada
    nodo padre, junto con su posición (``"left"`` o ``"right"``).

    Args:
        batch_tree: resultado de ``build_batch_tree()`` o ``build_merkle_tree()``
                    enriquecido con ``hashes`` y ``levels``.
        event_hash: ``hash_integridad`` del evento a probar (la hoja buscada).

    Returns:
        Dict con:
          - ``leaf_hash``  (str): hash de la hoja demostrada.
          - ``root``       (str): raíz del árbol.
          - ``batch_hour`` (str): identificador del lote (si disponible).
          - ``proof``      (List[Dict]): cada paso tiene ``{"sibling": str, "position": "left"|"right"}``.
            ``position`` es la posición del **hermano** — "left" significa que
            el hermano va a la izquierda, "right" que va a la derecha.
        None si el event_hash no se encuentra en las hojas del árbol.
    """
    levels = batch_tree.get("levels", [])
    root = batch_tree.get("root", "")

    if not levels or not levels[0]:
        return None

    leaves = levels[0]

    # Buscar el índice de la hoja
    try:
        idx = leaves.index(event_hash)
    except ValueError:
        return None

    proof_steps: List[Dict] = []
    current_idx = idx

    for level in levels[:-1]:  # todos menos la raíz
        # Duplicar si es impar (igual que en build_merkle_tree)
        padded_level = level if len(level) % 2 == 0 else level + [level[-1]]

        if current_idx % 2 == 0:  # nodo izquierdo → hermano está a la derecha
            sibling_idx = current_idx + 1
            position = "right"
        else:  # nodo derecho → hermano está a la izquierda
            sibling_idx = current_idx - 1
            position = "left"

        # El sibling puede ser el duplicado del último nodo
        sibling_hash = padded_level[sibling_idx] if sibling_idx < len(padded_level) else padded_level[current_idx]
        proof_steps.append({"sibling": sibling_hash, "position": position})

        # Subir al padre
        current_idx = current_idx // 2

    return {
        "leaf_hash": event_hash,
        "root": root,
        "batch_hour": batch_tree.get("batch_hour", ""),
        "proof": proof_steps,
    }


def generate_proof_for_event(
    conn: sqlite3.Connection,
    event_id: int,
) -> Optional[Dict]:
    """
    Wrapper de conveniencia: dado un event_id, recupera el evento, determina
    su lote horario, construye el árbol correspondiente y devuelve la prueba
    de Merkle lista para verificación.

    Returns:
        Resultado de ``generate_merkle_proof()``, o None si el evento no existe.
    """
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM audit_log WHERE event_id = ?", (event_id,)
    ).fetchone()
    if not row:
        return None

    evento = dict(row)
    # Extraer la hora del timestamp (YYYY-MM-DDTHH)
    ts = evento.get("timestamp", "")
    # El timestamp puede tener fracciones de segundo; tomamos los primeros 13 caracteres
    batch_hour = ts[:13] if len(ts) >= 13 else ts[:10] + "T00"

    batch_tree = build_batch_tree(conn, batch_hour)
    event_hash = evento.get("hash_integridad", "")
    proof = generate_merkle_proof(batch_tree, event_hash)

    if proof:
        proof["event_id"] = event_id
        proof["evento_uuid"] = evento.get("evento_uuid")
        proof["timestamp"] = ts

    return proof


# ── Verificación de una prueba de Merkle ───────────────────────────────────

def verify_merkle_proof(proof: Dict) -> bool:
    """
    Verifica que una prueba de Merkle es válida: reconstruye la raíz paso a
    paso y la compara con la raíz contenida en la prueba.

    No necesita acceso a la base de datos — solo usa la prueba misma.

    Args:
        proof: resultado de ``generate_merkle_proof()``.

    Returns:
        True si la prueba es válida (la raíz recalculada coincide), False si no.
    """
    if not proof:
        return False

    current_hash = proof.get("leaf_hash", "")
    expected_root = proof.get("root", "")

    for step in proof.get("proof", []):
        sibling = step["sibling"]
        position = step["position"]
        if position == "left":
            current_hash = _combine(sibling, current_hash)
        else:
            current_hash = _combine(current_hash, sibling)

    return current_hash == expected_root


# ── CA3: Publicación periódica de la raíz en el canal externo ──────────────

def publish_batch_root(
    conn: sqlite3.Connection,
    batch_hour: str,
    anchors_dir: str = None,
    private_key=None,
) -> Dict:
    """
    PDGTRAZDSA-148 — Construye el árbol del lote ``batch_hour``, firma la raíz
    y persiste el anclaje en un archivo JSON en ``anchors_dir``.

    El archivo se nombra ``merkle_<batch_hour>.json`` (con ':' reemplazados por
    '-' para compatibilidad con sistemas de archivos Windows). Su contenido
    puede copiarse a un repositorio Git externo o a cualquier servicio de
    sellado de tiempo (RFC 3161, blockchain, etc.).

    Args:
        conn:        conexión a la base de auditoría.
        batch_hour:  lote horario en formato ``"YYYY-MM-DDTHH"``.
        anchors_dir: directorio donde se escribe el archivo de anclaje.
                     Por defecto usa ``_DEFAULT_ANCHORS_DIR`` o la variable
                     de entorno ``AUDIT_MERKLE_ANCHORS_DIR``.
        private_key: llave privada Ed25519 para firmar la raíz. Si es None,
                     se intenta cargar la llave local del sistema (igual que
                     en HU-6.1). Si no existe ninguna, el anclaje se publica
                     sin firma (``signature: null``).

    Returns:
        Dict con el contenido del anclaje publicado (misma estructura que el
        archivo JSON).
    """
    if anchors_dir is None:
        anchors_dir = _DEFAULT_ANCHORS_DIR

    batch_tree = build_batch_tree(conn, batch_hour)

    # Construir el payload del anclaje
    published_at = datetime.now(timezone.utc).isoformat()
    anchor = {
        "schema_version": "1.0",
        "batch_hour": batch_hour,
        "root": batch_tree["root"],
        "leaf_count": batch_tree["leaf_count"],
        "published_at": published_at,
        "signature": None,
        "signer_public_key_pem": None,
    }

    # Firmar la raíz (opcional pero recomendado)
    try:
        if private_key is None:
            from audit_tracer.digital_signatures import get_or_create_user_keypair
            private_key, public_key = get_or_create_user_keypair()
        else:
            public_key = private_key.public_key()

        from audit_tracer.digital_signatures import public_key_to_pem
        import base64
        message = json.dumps(
            {
                "batch_hour": batch_hour,
                "root": batch_tree["root"],
                "leaf_count": batch_tree["leaf_count"],
                "published_at": published_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        raw_sig = private_key.sign(message)
        anchor["signature"] = base64.urlsafe_b64encode(raw_sig).decode("utf-8").rstrip("=")
        anchor["signer_public_key_pem"] = public_key_to_pem(public_key)
    except Exception as exc:
        # La publicación no falla si no hay llave; queda sin firma.
        anchor["signature_error"] = str(exc)

    # Persistir en disco
    Path(anchors_dir).mkdir(parents=True, exist_ok=True)
    safe_hour = batch_hour.replace(":", "-")
    file_path = os.path.join(anchors_dir, f"merkle_{safe_hour}.json")

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(anchor, f, ensure_ascii=False, indent=2)

    anchor["_file_path"] = file_path
    return anchor


def get_pending_batch_hours(
    conn: sqlite3.Connection,
    anchors_dir: str = None,
) -> List[str]:
    """
    PDGTRAZDSA-148 (job periódico) — Devuelve la lista de lotes horarios que
    tienen eventos en audit_log pero todavía no tienen un anclaje publicado en
    ``anchors_dir``.

    Útil para el scheduler que publica raíces pendientes (p.ej. APScheduler,
    cron, o el endpoint /api/merkle/publicar-pendientes).
    """
    if anchors_dir is None:
        anchors_dir = _DEFAULT_ANCHORS_DIR

    # Obtener todas las horas distintas presentes en la BD
    rows = conn.execute(
        "SELECT DISTINCT substr(timestamp, 1, 13) AS batch_hour FROM audit_log ORDER BY batch_hour ASC"
    ).fetchall()
    all_hours = [r[0] for r in rows]

    # Filtrar los que ya tienen anclaje publicado
    pending = []
    for hour in all_hours:
        safe_hour = hour.replace(":", "-")
        file_path = os.path.join(anchors_dir, f"merkle_{safe_hour}.json")
        if not os.path.exists(file_path):
            pending.append(hour)

    return pending


def publish_all_pending(
    conn: sqlite3.Connection,
    anchors_dir: str = None,
    private_key=None,
) -> List[Dict]:
    """
    PDGTRAZDSA-148 — Publica todos los lotes pendientes de anclaje.

    Returns:
        Lista de anclas publicadas en esta ejecución.
    """
    pending = get_pending_batch_hours(conn, anchors_dir)
    published = []
    for batch_hour in pending:
        anchor = publish_batch_root(conn, batch_hour, anchors_dir, private_key)
        published.append(anchor)
    return published


# ── CA4: Verificación externa de la raíz publicada ─────────────────────────

def verify_external_anchor(
    conn: sqlite3.Connection,
    batch_hour: str,
    anchors_dir: str = None,
) -> Dict:
    """
    PDGTRAZDSA-149 — Verifica que la raíz publicada en el anclaje externo
    coincide con la raíz recalculada a partir de los eventos actuales en la
    base de datos.

    Detecta tanto modificaciones en los eventos (raíz diferente) como la
    ausencia del archivo de anclaje (no publicado aún).

    Args:
        conn:        conexión a la base de auditoría.
        batch_hour:  lote horario en formato ``"YYYY-MM-DDTHH"``.
        anchors_dir: directorio donde se busca el archivo de anclaje.

    Returns:
        Dict con:
          - ``batch_hour``         (str)
          - ``anchor_exists``      (bool): True si el archivo de anclaje existe.
          - ``published_root``     (str | None): raíz publicada en el anclaje.
          - ``recalculated_root``  (str): raíz recalculada desde la BD.
          - ``integrity_ok``       (bool): True si ambas raíces coinciden.
          - ``leaf_count_match``   (bool): True si el número de hojas coincide.
          - ``published_leaf_count`` (int | None)
          - ``current_leaf_count`` (int)
          - ``signature_valid``    (bool | None): None si no hay firma, True/False si la hay.
          - ``published_at``       (str | None): fecha de publicación del anclaje.
          - ``details``            (str): mensaje descriptivo del resultado.
    """
    if anchors_dir is None:
        anchors_dir = _DEFAULT_ANCHORS_DIR

    safe_hour = batch_hour.replace(":", "-")
    file_path = os.path.join(anchors_dir, f"merkle_{safe_hour}.json")

    # Recalcular la raíz desde la BD
    batch_tree = build_batch_tree(conn, batch_hour)
    recalculated_root = batch_tree["root"]
    current_leaf_count = batch_tree["leaf_count"]

    result: Dict = {
        "batch_hour": batch_hour,
        "anchor_exists": False,
        "published_root": None,
        "recalculated_root": recalculated_root,
        "integrity_ok": False,
        "leaf_count_match": False,
        "published_leaf_count": None,
        "current_leaf_count": current_leaf_count,
        "signature_valid": None,
        "published_at": None,
        "details": "",
    }

    if not os.path.exists(file_path):
        result["details"] = (
            f"No existe anclaje externo para el lote {batch_hour}. "
            "Ejecute publish_batch_root() para publicarlo."
        )
        return result

    # Cargar el anclaje
    with open(file_path, "r", encoding="utf-8") as f:
        anchor = json.load(f)

    result["anchor_exists"] = True
    published_root = anchor.get("root")
    published_leaf_count = anchor.get("leaf_count")
    result["published_root"] = published_root
    result["published_leaf_count"] = published_leaf_count
    result["published_at"] = anchor.get("published_at")

    # Comparar raíces
    roots_match = published_root == recalculated_root
    counts_match = published_leaf_count == current_leaf_count
    result["integrity_ok"] = roots_match
    result["leaf_count_match"] = counts_match

    # Verificar firma si existe
    signature = anchor.get("signature")
    public_key_pem = anchor.get("signer_public_key_pem")
    if signature and public_key_pem:
        try:
            import base64
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            pk = load_pem_public_key(public_key_pem.encode("utf-8"))
            message = json.dumps(
                {
                    "batch_hour": anchor.get("batch_hour"),
                    "root": anchor.get("root"),
                    "leaf_count": anchor.get("leaf_count"),
                    "published_at": anchor.get("published_at"),
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            padding = "=" * (-len(signature) % 4)
            raw_sig = base64.urlsafe_b64decode(signature + padding)
            pk.verify(raw_sig, message)
            result["signature_valid"] = True
        except Exception:
            result["signature_valid"] = False
    else:
        result["signature_valid"] = None  # No hay firma en este anclaje

    # Armar mensaje descriptivo
    if roots_match and counts_match:
        result["details"] = (
            f"✓ Integridad verificada para el lote {batch_hour}. "
            f"Raíz publicada y recalculada coinciden ({current_leaf_count} eventos)."
        )
    else:
        discrepancias = []
        if not roots_match:
            discrepancias.append(
                f"raíz diferente (publicada={published_root[:12]}…, "
                f"actual={recalculated_root[:12]}…)"
            )
        if not counts_match:
            discrepancias.append(
                f"número de hojas diferente (publicado={published_leaf_count}, "
                f"actual={current_leaf_count})"
            )
        result["details"] = (
            f"✗ ALTERACIÓN DETECTADA en el lote {batch_hour}: "
            + "; ".join(discrepancias)
            + ". Los registros pueden haber sido modificados."
        )

    return result


def verify_all_anchors(
    conn: sqlite3.Connection,
    anchors_dir: str = None,
) -> List[Dict]:
    """
    PDGTRAZDSA-149 — Verifica todos los anclajes presentes en ``anchors_dir``.

    Returns:
        Lista de resultados de ``verify_external_anchor()`` para cada lote.
    """
    if anchors_dir is None:
        anchors_dir = _DEFAULT_ANCHORS_DIR

    if not os.path.exists(anchors_dir):
        return []

    results = []
    for filename in sorted(os.listdir(anchors_dir)):
        if not filename.startswith("merkle_") or not filename.endswith(".json"):
            continue
        # Reconstruir batch_hour desde el nombre de archivo (merkle_YYYY-MM-DDTHH.json)
        safe_hour = filename[len("merkle_"):-len(".json")]
        # Revertir el reemplazo de ':' → '-'  (solo el separador T→H)
        # Formato guardado: YYYY-MM-DD-HH → restaurar YYYY-MM-DDTHH
        # safe_hour tiene forma "2026-10-22T14" (con - sustituidos en los :)
        # En realidad para horas no había ':' en el batch_hour original (solo "T"),
        # así que el safe_hour ya es el batch_hour correcto.
        batch_hour = safe_hour
        result = verify_external_anchor(conn, batch_hour, anchors_dir)
        results.append(result)

    return results
