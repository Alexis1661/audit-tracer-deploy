"""
audit_tracer/retencion.py
=========================
B7 (21/11/2026) — Política de retención y archivado de audit_log.

Política:
  * Cada evento se conserva en la base central al menos AUDIT_RETENCION_ANIOS
    años (6 por defecto: el plazo con que HIPAA §164.316(b)(2)(i) exige
    conservar la documentación). Los disparadores de inmutabilidad impiden
    borrarlo antes; esa garantía no cambia.
  * Cumplido el plazo, el evento puede pasar a un archivo de conservación
    fuera de línea. archivar() escribe un JSONL con los eventos completos
    (incluidos hash_integridad y firma_digital) y un manifiesto con el
    SHA-256 del archivo, el conteo, el rango de fechas y las raíces de Merkle
    de los lotes cubiertos. verificar_archivo() comprueba, sin la base, que el
    archivo no cambió y que cada evento conserva su hash.
  * La purga de la base central NO la hace esta herramienta: requiere retirar
    los disparadores, lo que debe hacer el DBA con autorización escrita del
    oficial de cumplimiento, después de verificar el archivo y de copiarlo a
    un almacenamiento de solo escritura (Anexo 14, sección de retención).

Ley 1581, Art. 17 lit. d: conservar la información con las condiciones de
seguridad necesarias para impedir su adulteración, pérdida o uso no
autorizado. ISO/IEC 27701:2019, 6.9.4.2 (protección de la información de
registro) y 7.4.7 (retención).
"""

import hashlib
import json
import os
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from .models.audit_log import _HASHED_COLUMNS
from .utils.hashing import hash_event


def anios_retencion() -> int:
    try:
        return max(1, int(os.environ.get("AUDIT_RETENCION_ANIOS", "6")))
    except ValueError:
        return 6


def fecha_limite(ahora: Optional[datetime] = None, anios: Optional[int] = None) -> str:
    """Timestamp ISO (UTC) antes del cual un evento ya cumplió el plazo de retención."""
    ahora = ahora or datetime.utcnow()
    anios = anios or anios_retencion()
    return (ahora - timedelta(days=365 * anios + anios // 4)).isoformat()


def resumen(conn, ahora: Optional[datetime] = None) -> Dict:
    """Cuántos eventos hay, cuántos ya cumplieron el plazo y desde cuándo hay registros."""
    limite = fecha_limite(ahora)
    total, primero = conn.execute("SELECT COUNT(*), MIN(timestamp) FROM audit_log").fetchone()
    vencidos = conn.execute("SELECT COUNT(*) FROM audit_log WHERE timestamp < ?", (limite,)).fetchone()[0]
    return {"anios_retencion": anios_retencion(), "fecha_limite": limite, "total_eventos": total,
            "eventos_archivables": vencidos, "evento_mas_antiguo": primero}


def _filas(conn, hasta: str) -> List[Dict]:
    cursor = conn.execute("SELECT * FROM audit_log WHERE timestamp < ? ORDER BY event_id", (hasta,))
    nombres = [d[0] for d in cursor.description]
    return [dict(zip(nombres, fila)) for fila in cursor.fetchall()]


def archivar(conn, destino: str, hasta: Optional[str] = None, anchors_dir: Optional[str] = None) -> Dict:
    """
    Escribe en `destino` (carpeta) el archivo de los eventos con timestamp
    anterior a `hasta` (por defecto, la fecha límite de retención). No borra
    nada de la base.

    Returns:
        El manifiesto (también guardado como manifiesto.json junto al JSONL).
    """
    hasta = hasta or fecha_limite()
    eventos = _filas(conn, hasta)
    os.makedirs(destino, exist_ok=True)
    nombre = f"audit_log_hasta_{hasta[:10]}.jsonl"
    ruta = os.path.join(destino, nombre)
    with open(ruta, "w", encoding="utf-8", newline="\n") as f:
        for evento in eventos:
            f.write(json.dumps(evento, ensure_ascii=False, sort_keys=True) + "\n")
    with open(ruta, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()

    lotes = sorted({(e.get("timestamp") or "")[:13] for e in eventos if e.get("timestamp")})
    raices = {}
    if anchors_dir:
        for lote in lotes:
            archivo = os.path.join(anchors_dir, f"merkle_{lote.replace(':', '-')}.json")
            if os.path.exists(archivo):
                with open(archivo, encoding="utf-8") as f:
                    raices[lote] = json.load(f).get("root")
    manifiesto = {
        "archivo": nombre,
        "sha256": sha,
        "eventos": len(eventos),
        "desde": eventos[0]["timestamp"] if eventos else None,
        "hasta_excluido": hasta,
        "primer_event_id": eventos[0]["event_id"] if eventos else None,
        "ultimo_event_id": eventos[-1]["event_id"] if eventos else None,
        "anios_retencion": anios_retencion(),
        "raices_merkle": raices,
        "generado_en": datetime.utcnow().isoformat(),
    }
    with open(os.path.join(destino, "manifiesto.json"), "w", encoding="utf-8") as f:
        json.dump(manifiesto, f, ensure_ascii=False, indent=2)
    return manifiesto


def verificar_archivo(destino: str) -> Dict:
    """
    Comprueba un archivo de retención sin acceso a la base: el SHA-256 del
    JSONL coincide con el manifiesto, el conteo coincide y cada evento
    conserva su hash_integridad.
    """
    with open(os.path.join(destino, "manifiesto.json"), encoding="utf-8") as f:
        manifiesto = json.load(f)
    ruta = os.path.join(destino, manifiesto["archivo"])
    with open(ruta, "rb") as f:
        contenido = f.read()
    sha_ok = hashlib.sha256(contenido).hexdigest() == manifiesto["sha256"]
    alterados, total = [], 0
    for linea in contenido.decode("utf-8").splitlines():
        if not linea.strip():
            continue
        total += 1
        evento = json.loads(linea)
        if hash_event({c: evento.get(c) for c in _HASHED_COLUMNS}) != evento.get("hash_integridad"):
            alterados.append(evento.get("event_id"))
    return {
        "sha256_coincide": sha_ok,
        "conteo_coincide": total == manifiesto["eventos"],
        "eventos_alterados": alterados,
        "valido": sha_ok and total == manifiesto["eventos"] and not alterados,
    }
