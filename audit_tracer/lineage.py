"""
audit_tracer/lineage.py
=======================
HU-7.1 — Visualización de linaje de datos (grafo)

Construye, a partir de los eventos YA almacenados en audit_log, el grafo de
linaje de un dataset o de un evento. Es de solo lectura: no agrega columnas,
no toca el esquema, ni hash_integridad, ni la sincronización.

audit_log no tiene ningún campo explícito de linaje (evento padre, dataset
origen, etc.), así que el grafo se construye únicamente con relaciones que
se pueden DEDUCIR de campos almacenados — nunca inventadas:

  E1 (secuencia)   — Dentro de un mismo (sesion_id, dataset_nombre), cada
                     paso de linaje se conecta con el siguiente en orden de
                     timestamp. sesion_id vincula todos los eventos de una
                     misma ejecución (ver audit_tracer/schema/audit_log.sql); dos
                     sesiones distintas son ejecuciones independientes y
                     NO se enlazan entre sí.
  E2 (exportado_a) — Un evento EXPORTACION se conecta con el archivo que
                     produjo (ruta_destino), relación explícita en el evento.

Deliberadamente NO se enlaza una exportación con una carga posterior del
mismo nombre de archivo: la coincidencia de nombre no garantiza que sea el
mismo archivo (ej. 'data.csv' en dos máquinas), y mostrarlo como linaje
sería afirmar algo que los eventos no prueban.

Orden (CA3): timestamp ISO 8601 ascendente — el mismo criterio de
get_events() (HU-4.1). event_id solo desempata eventos con el mismo
timestamp, de forma determinista; nunca se usa como criterio primario.
El orden se recalcula aquí explícitamente y no depende del orden en que
la consulta devuelva las filas.

Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
"""

import re
import sqlite3
from typing import Dict, List, Optional, Set

from .models.audit_log import get_event_by_id


# Tipos de acción que forman parte del linaje del dato. CONSULTA no cambia
# el dato (solo lo lee) y los eventos de sesión/usuario/acceso no operan
# sobre un dataset, así que quedan fuera del grafo.
TIPOS_LINAJE = ("CARGA", "TRANSFORMACION", "MODELADO", "MODELADO_FALLIDO", "EXPORTACION")

# Tipo de nodo del grafo según tipo_accion (CA1: datasets, transformaciones
# y modelos; la exportación y su archivo resultante también son datasets).
_TIPO_NODO = {
    "CARGA": "dataset",
    "TRANSFORMACION": "transformacion",
    "MODELADO": "modelo",
    "MODELADO_FALLIDO": "modelo",
    "EXPORTACION": "exportacion",
}

# Nombres que los interceptores usan cuando NO pudieron identificar el
# dataset (data_capture.py / export_capture.py). No representan un dataset
# concreto: enlazarlos uniría operaciones sobre datos distintos.
_NOMBRES_NO_IDENTIFICABLES = {"dataset_desconocido", "dataset_externo", "left_dataset", "right_dataset"}
_PREFIJOS_NO_IDENTIFICABLES = ("buffer_",)

# Geometría del layout 'preset': eje X = paso temporal, una fila por cadena.
_ANCHO_PASO = 220
_ALTO_FILA = 150


def es_dataset_identificable(nombre: Optional[str]) -> bool:
    """True si dataset_nombre identifica un dataset concreto."""
    if not nombre:
        return False
    if nombre in _NOMBRES_NO_IDENTIFICABLES:
        return False
    return not nombre.startswith(_PREFIJOS_NO_IDENTIFICABLES)


def _orden_temporal(evento: Dict):
    return (evento["timestamp"] or "", evento["event_id"])


def _fetch_eventos_linaje(
    conn: sqlite3.Connection,
    dataset_nombre: str,
    sesion_id: Optional[str] = None,
) -> List[Dict]:
    """Eventos de linaje del dataset y de los que se unen con él (merge)."""
    conn.row_factory = sqlite3.Row
    nombres = sorted(_datasets_conectados(conn, dataset_nombre)) if es_dataset_identificable(dataset_nombre)         else [dataset_nombre]
    marcas = ", ".join("?" * len(nombres))
    placeholders = ", ".join("?" * len(TIPOS_LINAJE))
    query = (
        f"SELECT * FROM audit_log WHERE dataset_nombre IN ({marcas}) "
        f"AND tipo_accion IN ({placeholders})"
    )
    params: list = [*nombres, *TIPOS_LINAJE]
    if sesion_id is not None:
        query += " AND sesion_id = ?"
        params.append(sesion_id)

    conn.row_factory = sqlite3.Row
    rows = conn.execute(query, params).fetchall()
    # CA3: orden temporal explícito, independiente del orden de la consulta.
    return sorted((dict(r) for r in rows), key=_orden_temporal)


# ── Uniones (merge) ───────────────────────────────────────────
# df.merge() y pd.merge() registran sus eventos con el nombre del dataset de la
# izquierda y bautizan el resultado «merge(izquierda,derecha)»: las operaciones
# posteriores usan ese nombre. Para que la cohorte unida quede en un solo grafo,
# el nombre del resultado se descompone en sus entradas y se conectan.

def entradas_de_union(dataset_nombre: Optional[str]) -> Optional[tuple]:
    """('izq', 'der') si el nombre es 'merge(izq,der)' (los operandos pueden ser otras uniones)."""
    if not dataset_nombre or not dataset_nombre.startswith("merge(") or not dataset_nombre.endswith(")"):
        return None
    cuerpo, nivel = dataset_nombre[len("merge("):-1], 0
    for i, c in enumerate(cuerpo):
        if c == "(":
            nivel += 1
        elif c == ")":
            nivel -= 1
        elif c == "," and nivel == 0:
            return cuerpo[:i], cuerpo[i + 1:]
    return None


def _datasets_conectados(conn: sqlite3.Connection, dataset_nombre: str) -> Set[str]:
    """El dataset y todos los que se relacionan con él por uniones (entradas y resultados)."""
    placeholders = ", ".join("?" * len(TIPOS_LINAJE))
    nombres = [r[0] for r in conn.execute(
        f"SELECT DISTINCT dataset_nombre FROM audit_log WHERE tipo_accion IN ({placeholders}) "
        f"AND dataset_nombre LIKE 'merge(%'", TIPOS_LINAJE).fetchall()]
    uniones = {n: entradas_de_union(n) for n in nombres}
    uniones = {n: e for n, e in uniones.items() if e}
    conectados, pendientes = {dataset_nombre}, [dataset_nombre]
    while pendientes:
        actual = pendientes.pop()
        vecinos = set(uniones.get(actual, ()))                                  # entradas
        vecinos |= {n for n, e in uniones.items() if actual in e}               # resultados
        for v in vecinos - conectados:
            conectados.add(v)
            pendientes.append(v)
    return conectados


def list_lineage_datasets(conn: sqlite3.Connection) -> List[Dict]:
    """
    Datasets identificables que tienen al menos un evento de linaje, para
    el selector del dashboard (CA2). Ordenados por su último evento, el más
    reciente primero.

    Returns:
        List[Dict]: [{dataset_nombre, total_eventos, sesiones, ultimo_evento}]
    """
    placeholders = ", ".join("?" * len(TIPOS_LINAJE))
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        f"""
        SELECT dataset_nombre,
               COUNT(*)                  AS total_eventos,
               COUNT(DISTINCT sesion_id) AS sesiones,
               MAX(timestamp)            AS ultimo_evento
        FROM audit_log
        WHERE tipo_accion IN ({placeholders}) AND dataset_nombre IS NOT NULL
        GROUP BY dataset_nombre
        ORDER BY ultimo_evento DESC
        """,
        TIPOS_LINAJE,
    ).fetchall()
    return [dict(r) for r in rows if es_dataset_identificable(r["dataset_nombre"])]


def _etiqueta(evento: Dict) -> tuple[str, str]:
    """(label, sublabel) legibles para el nodo de un evento."""
    tipo = evento["tipo_accion"]
    if tipo == "CARGA":
        return evento["dataset_nombre"] or "Dataset", "Carga del dataset"
    if tipo == "TRANSFORMACION":
        # HU-2.2 (rama sin mergear) describe la operación en motivo_fallo
        # como "[TIPO] operación(...)"; si no hay descripción, columnas.
        detalle = evento.get("motivo_fallo") or evento.get("columnas_afectadas") or ""
        return "Transformación", detalle
    if tipo == "MODELADO":
        return "Modelo entrenado", evento.get("contexto_ejecucion") or ""
    if tipo == "MODELADO_FALLIDO":
        return "Modelado fallido", evento.get("motivo_fallo") or ""
    if tipo == "EXPORTACION":
        filas = evento.get("filas_exportadas")
        return "Exportación", f"{filas} filas" if filas is not None else ""
    return tipo, ""


def _nodo_evento(evento: Dict, paso: int, fila: int, seleccionado_id: Optional[int]) -> Dict:
    label, sublabel = _etiqueta(evento)
    return {
        "id": f"ev-{evento['event_id']}",
        "tipo": _TIPO_NODO[evento["tipo_accion"]],
        "label": label,
        "sublabel": sublabel,
        "event_id": evento["event_id"],
        "tipo_accion": evento["tipo_accion"],
        "timestamp": evento["timestamp"],
        "sesion_id": evento["sesion_id"],
        "usuario_id": evento["usuario_id"],
        "dataset_nombre": evento["dataset_nombre"],
        "nivel_alerta": evento.get("nivel_alerta") or "NORMAL",
        "paso": paso,
        "seleccionado": evento["event_id"] == seleccionado_id,
        "position": {"x": (paso - 1) * _ANCHO_PASO, "y": fila * _ALTO_FILA},
    }


def _construir(eventos: List[Dict], seleccionado_id: Optional[int] = None) -> Dict:
    """Arma nodos, aristas y cadenas a partir de eventos de linaje."""
    nodes: List[Dict] = []
    edges: List[Dict] = []
    cadenas: List[Dict] = []

    # Agrupar por (sesion_id, dataset_nombre) — cada grupo es una cadena E1.
    grupos: Dict[tuple, List[Dict]] = {}
    for ev in eventos:
        grupos.setdefault((ev["sesion_id"], ev["dataset_nombre"]), []).append(ev)

    # Las cadenas se muestran en el orden en que empezaron.
    claves = sorted(grupos, key=lambda k: _orden_temporal(sorted(grupos[k], key=_orden_temporal)[0]))

    archivos: Dict[str, Dict] = {}
    nodos_cadena: Dict[tuple, List[Dict]] = {}
    pasos_cadena: Dict[tuple, List[Dict]] = {}
    desplazamiento: Dict[tuple, int] = {}   # pasos que ocupan las entradas de una unión
    for fila, clave in enumerate(claves):
        pasos = sorted(grupos[clave], key=_orden_temporal)
        sesion_id, dataset_nombre = clave
        enlazable = es_dataset_identificable(dataset_nombre)
        entradas = entradas_de_union(dataset_nombre)
        desp = 0
        if entradas:
            desp = max((desplazamiento.get((sesion_id, e), 0) + len(grupos.get((sesion_id, e), ()))
                        for e in entradas), default=0)
        desplazamiento[clave] = desp

        previo = None
        for paso, ev in enumerate(pasos, start=1):
            nodo = _nodo_evento(ev, paso, fila, seleccionado_id)
            nodo["position"]["x"] += desp * _ANCHO_PASO
            nodes.append(nodo)
            nodos_cadena.setdefault(clave, []).append(nodo)
            pasos_cadena.setdefault(clave, []).append(ev)

            if previo is not None and enlazable:
                edges.append({
                    "id": f"{previo['id']}->{nodo['id']}",
                    "source": previo["id"],
                    "target": nodo["id"],
                    "tipo": "secuencia",
                })

            if ev["tipo_accion"] == "EXPORTACION" and ev.get("ruta_destino"):
                ruta = ev["ruta_destino"]
                archivo = archivos.get(ruta)
                if archivo is None:
                    archivo = {
                        "id": f"archivo-{len(archivos) + 1}",
                        "tipo": "archivo",
                        "label": ruta.replace("\\", "/").split("/")[-1],
                        "sublabel": ruta,
                        "ruta_destino": ruta,
                        "paso": paso + 1,
                        "seleccionado": False,
                        "position": {"x": (paso + desp) * _ANCHO_PASO, "y": fila * _ALTO_FILA},
                    }
                    archivos[ruta] = archivo
                    nodes.append(archivo)
                # El archivo refleja la exportación más reciente que lo escribió
                # (una exportación posterior lo sobrescribe): su clic abre ese evento.
                archivo.update({
                    "event_id": ev["event_id"],
                    "tipo_accion": "EXPORTACION",
                    "timestamp": ev["timestamp"],
                    "nivel_alerta": ev.get("nivel_alerta") or "NORMAL",
                })
                edges.append({
                    "id": f"{nodo['id']}->{archivo['id']}",
                    "source": nodo["id"],
                    "target": archivo["id"],
                    "tipo": "exportado_a",
                })

            previo = nodo

        cadenas.append({
            "sesion_id": sesion_id,
            "dataset_nombre": dataset_nombre,
            "usuario_id": pasos[0]["usuario_id"],
            "enlazada": enlazable,
            "entradas": list(entradas) if entradas else None,
            "pasos": [
                {
                    "paso": i,
                    "event_id": ev["event_id"],
                    "tipo_accion": ev["tipo_accion"],
                    "timestamp": ev["timestamp"],
                    "descripcion": " — ".join(p for p in _etiqueta(ev) if p),
                    "ruta_destino": ev.get("ruta_destino"),
                }
                for i, ev in enumerate(pasos, start=1)
            ],
        })

    # Aristas de unión: las entradas de un merge → primer paso del resultado.
    for (sesion_id, nombre), nodos in nodos_cadena.items():
        entradas = entradas_de_union(nombre)
        if not entradas:
            continue
        izq, der = entradas
        destino = nodos[0]
        for lado, entrada in (("izquierda", izq), ("derecha", der)):
            clave_entrada = (sesion_id, entrada)
            if clave_entrada not in nodos_cadena:
                continue
            candidatos = nodos_cadena[clave_entrada]
            origen = candidatos[-1]
            if lado == "izquierda":
                # el evento MERGE de la izquierda que menciona a la derecha
                for nodo, ev in zip(candidatos, pasos_cadena[clave_entrada]):
                    descripcion = ev.get("motivo_fallo") or ""
                    if descripcion.startswith("[MERGE]") and der in descripcion:
                        origen = nodo
            arista = {
                "id": f"{origen['id']}=>{destino['id']}",
                "source": origen["id"],
                "target": destino["id"],
                "tipo": "union",
                "entrada": lado,
            }
            if all(e["id"] != arista["id"] for e in edges):
                edges.append(arista)

    return {"nodes": nodes, "edges": edges, "cadenas": cadenas}


def build_lineage_graph(
    conn: sqlite3.Connection,
    dataset_nombre: Optional[str] = None,
    event_id: Optional[int] = None,
) -> Dict:
    """
    HU-7.1 CA1/CA2/CA3 — Construye el grafo de linaje de un dataset o de un evento.

    - dataset_nombre: todas las cadenas (una por sesión) de ese dataset.
    - event_id: la cadena de la sesión de ese evento sobre su dataset, con
      el nodo del evento marcado como seleccionado. Si el evento no es de
      linaje (ej. CONSULTA), se muestra igual el linaje de su dataset en su
      sesión, con una advertencia.

    Returns:
        Dict: {alcance, dataset_nombre, event_id, nodes, edges, cadenas,
        advertencias}. `nodes` incluye `position` para el layout 'preset'
        (eje X = paso temporal).
    """
    advertencias: List[str] = []
    alcance = None
    eventos: List[Dict] = []
    seleccionado_id = None

    if event_id is not None:
        alcance = "evento"
        evento = get_event_by_id(conn, event_id)
        if evento is None:
            return _resultado(alcance, None, event_id, [], [f"El evento #{event_id} no existe."])
        dataset_nombre = evento.get("dataset_nombre")
        seleccionado_id = event_id
        if evento["tipo_accion"] not in TIPOS_LINAJE:
            advertencias.append(
                f"El evento #{event_id} es de tipo {evento['tipo_accion']}, que no modifica "
                f"ni produce datos; se muestra el linaje de su dataset en la misma sesión."
            )
        if not dataset_nombre:
            advertencias.append(f"El evento #{event_id} no está asociado a ningún dataset.")
            return _resultado(alcance, None, event_id, [], advertencias)
        if es_dataset_identificable(dataset_nombre):
            eventos = _fetch_eventos_linaje(conn, dataset_nombre, sesion_id=evento["sesion_id"])
        elif evento["tipo_accion"] in TIPOS_LINAJE:
            # Nombre no identificable: solo el propio evento, sin relacionarlo.
            eventos = [evento]
    elif dataset_nombre:
        alcance = "dataset"
        eventos = _fetch_eventos_linaje(conn, dataset_nombre)
        if not eventos:
            advertencias.append(f"No hay eventos de linaje registrados para '{dataset_nombre}'.")

    if dataset_nombre and not es_dataset_identificable(dataset_nombre):
        advertencias.append(
            f"'{dataset_nombre}' no identifica un dataset concreto (el interceptor no "
            f"pudo determinar su nombre); sus eventos no se relacionan entre sí."
        )

    return _resultado(alcance, dataset_nombre, event_id, eventos, advertencias, seleccionado_id)


def _resultado(alcance, dataset_nombre, event_id, eventos, advertencias, seleccionado_id=None) -> Dict:
    grafo = _construir(eventos, seleccionado_id)
    return {
        "alcance": alcance,
        "dataset_nombre": dataset_nombre,
        "event_id": event_id,
        **grafo,
        "advertencias": advertencias,
    }
