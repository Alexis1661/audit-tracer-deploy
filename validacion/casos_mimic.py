"""
validacion/casos_mimic.py
=========================
Validación del prototipo con MIMIC-III Clinical Database Demo v1.4
(sección 7.4 del documento final): los tres casos de uso, cada afirmación
convertida en una verificación con resultado CUMPLE / NO CUMPLE y evidencia.

Uso (genera la evidencia en la carpeta indicada):

    python -m validacion.casos_mimic --evidencia validacion/evidencia/<fecha>

Las mismas verificaciones se ejecutan como pruebas en
tests/test_validacion_mimic.py y paso a paso en validacion/casos_mimic.ipynb.

Datos: validacion/descargar_mimic.py descarga el dataset desde PhysioNet y
verifica sus SHA-256 (o se indica la carpeta con MIMIC_DEMO_DIR).

Reloj: las operaciones del analista se ejecutan con validacion/reloj.py para
fijar la hora del día (10:00 y 03:10, hora de Colombia) sobre la fecha real
de ejecución. Los días de la línea base del caso 2 son los cinco días
anteriores a esa fecha. Todo lo demás (servidor, dashboard, sincronización,
correo) corre en tiempo real.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import io
import json
import os
import platform
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from contextlib import closing
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional

# Este proceso (CLI, notebook o pytest) importa partes de audit_tracer para
# verificar hashes, anomalías y alertas. Importar el paquete activa la captura,
# así que antes de la primera importación se le da un HOME temporal: nunca usa
# la base local, las llaves ni el token cacheado de quien ejecuta la validación.
if "audit_tracer" not in sys.modules:
    _HOME_ORQUESTADOR = tempfile.mkdtemp(prefix="validacion_mimic_orquestador_")
    os.environ["HOME"] = os.environ["USERPROFILE"] = _HOME_ORQUESTADOR
    os.environ.pop("AUDIT_TRACER_API_URL", None)

from validacion.entorno import (  # noqa: E402
    CORREO_OFICIAL, RAIZ, SCRIPTS, Analista, Navegador, ServidorCentral, cuenta, esperar,
)

COLOMBIA = timezone(timedelta(hours=-5))
NOMBRE_DATASET = "MIMIC-III Clinical Database Demo v1.4 (PhysioNet, ODbL 1.0, doi:10.13026/C2HM2Q)"
CARPETA_MIMIC_POR_DEFECTO = RAIZ / "validacion" / "datos" / "mimic-iii-clinical-database-demo-1.4"
ARCHIVOS_MIMIC = ("PATIENTS.csv", "ADMISSIONS.csv", "LABEVENTS.csv")


def carpeta_mimic() -> Optional[Path]:
    """Carpeta con los CSV de MIMIC-III Demo, o None si no están."""
    candidata = Path(os.environ.get("MIMIC_DEMO_DIR") or CARPETA_MIMIC_POR_DEFECTO)
    if all((candidata / a).is_file() for a in ARCHIVOS_MIMIC):
        return candidata
    return None


@dataclass
class Verificacion:
    id: str
    caso: str
    afirmacion: str
    cumple: bool
    detalle: str
    evidencia: List[str] = field(default_factory=list)

    @property
    def estado(self) -> str:
        return "CUMPLE" if self.cumple else "NO CUMPLE"


def _sha256_archivo(ruta: Path) -> str:
    h = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1 << 20), b""):
            h.update(bloque)
    return h.hexdigest()


def _commit() -> Dict[str, str]:
    def git(*args):
        try:
            return subprocess.run(["git", "-C", str(RAIZ), *args], capture_output=True, text=True,
                                  timeout=30).stdout.strip()
        except Exception:
            return ""
    return {
        "commit": git("rev-parse", "HEAD"),
        "rama": git("rev-parse", "--abbrev-ref", "HEAD"),
        "fecha_commit": git("log", "-1", "--format=%ci"),
        "cambios_sin_commit": bool(git("status", "--porcelain", "--", "audit_tracer", "app.py", "templates",
                                       "validacion/*.py", "validacion/scripts", "tests")),
    }


def entorno_de_ejecucion() -> Dict[str, str]:
    import pandas
    info = {
        "fecha_ejecucion": datetime.now(COLOMBIA).isoformat(timespec="seconds"),
        "python": platform.python_version(),
        "pandas": pandas.__version__,
        "sistema": f"{platform.system()} {platform.release()} ({platform.version()})",
        "maquina": platform.machine(),
        "procesador": platform.processor(),
        "cpus_logicas": str(os.cpu_count()),
    }
    info.update(_commit())
    return info


class ValidacionMIMIC:
    """Ejecuta los tres casos de uso contra el sistema real y junta la evidencia."""

    def __init__(self, evidencia: Path, datos: Path, base: Optional[Path] = None):
        self.evidencia = Path(evidencia)
        self.datos = Path(datos)
        self.base = Path(base) if base else Path(tempfile.mkdtemp(prefix="validacion_mimic_"))
        self.verificaciones: List[Verificacion] = []
        self.servidor: Optional[ServidorCentral] = None
        ahora = datetime.now(COLOMBIA)
        # Los casos fijan las 03:10 y las 10:00 de este día. Antes de las 11:00 esas
        # horas todavía no llegaron y el servidor marca, con razón, un timestamp en el
        # futuro (SRV-T3); en ese caso se usa el día anterior.
        hoy = ahora.date() if ahora.hour >= 11 else ahora.date() - timedelta(days=1)
        self.fecha: date = hoy
        self.usuario_cientifica: Optional[str] = None
        self.usuario_auditor: Optional[str] = None
        self.analista: Optional[Analista] = None

    # ── utilidades ──────────────────────────────────────────────
    def _utc(self, dia: date, hora_colombia: str) -> str:
        h, m = (int(x) for x in hora_colombia.split(":"))
        local = datetime(dia.year, dia.month, dia.day, h, m, tzinfo=COLOMBIA)
        return local.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")

    def _guardar(self, relativa: str, contenido) -> str:
        ruta = self.evidencia / relativa
        ruta.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contenido, (dict, list)):
            ruta.write_text(json.dumps(contenido, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
        elif isinstance(contenido, bytes):
            ruta.write_bytes(contenido)
        else:
            ruta.write_text(str(contenido), encoding="utf-8")
        return ruta.relative_to(self.evidencia).as_posix()

    def _v(self, id_, caso, afirmacion, cumple, detalle, evidencia=()):
        v = Verificacion(id_, caso, afirmacion, bool(cumple), detalle, list(evidencia))
        self.verificaciones.append(v)
        return v

    def _eventos_sesion(self, sesion_id: str) -> List[Dict]:
        return self.servidor.consultar(
            "SELECT * FROM audit_log WHERE sesion_id = ? ORDER BY timestamp, event_id", (sesion_id,))

    def _sesiones_de_script(self, script: str) -> List[str]:
        filas = self.servidor.consultar(
            "SELECT DISTINCT sesion_id FROM audit_log WHERE contexto_ejecucion LIKE ? ORDER BY event_id",
            (f"Script: {script}%",))
        return [f["sesion_id"] for f in filas]

    def _esperar_cierre(self, sesion_id: str) -> List[Dict]:
        esperar(lambda: self.servidor.consultar(
            "SELECT 1 FROM audit_log WHERE sesion_id = ? AND tipo_accion = 'CIERRE_SESION'", (sesion_id,)),
            timeout=60, descripcion=f"CIERRE_SESION de {sesion_id} en el servidor central")
        return self._eventos_sesion(sesion_id)

    def _correr_script(self, script: str, *args, hora_utc: str) -> Dict:
        """Ejecuta el script y devuelve {sesion_id, eventos_central, eventos_local, salida}."""
        antes = set(self._sesiones_de_script(script))
        r = self.analista.ejecutar(script, str(self.datos), *args, reloj_utc=hora_utc)
        sesion = esperar(lambda: [s for s in self._sesiones_de_script(script) if s not in antes],
                         timeout=60, descripcion=f"eventos de {script} en el servidor")[0]
        eventos = self._esperar_cierre(sesion)
        with closing(sqlite3.connect(self.analista.base_local())) as conn:
            conn.row_factory = sqlite3.Row
            locales = [dict(f) for f in conn.execute(
                "SELECT * FROM audit_log WHERE sesion_id = ? ORDER BY timestamp, event_id", (sesion,))]
        return {"sesion_id": sesion, "eventos_central": eventos, "eventos_local": locales,
                "stdout": r.stdout, "stderr": r.stderr}

    # ── preparación ─────────────────────────────────────────────
    def preparar(self) -> None:
        self._inicio = time.monotonic()
        self._info = entorno_de_ejecucion()
        self.evidencia.mkdir(parents=True, exist_ok=True)
        self.servidor = ServidorCentral(self.base).iniciar()
        usuarios = {u["email"]: u for u in self.servidor.consultar("SELECT usuario_id, email, rol FROM usuarios")}
        self.usuario_cientifica = usuarios[cuenta("CIENTIFICO_DATOS")["email"]]["usuario_id"]
        self.usuario_auditor = usuarios[cuenta("AUDITOR")["email"]]["usuario_id"]

        # El administrador designa al oficial de cumplimiento como destinatario de alertas.
        admin = Navegador(self.servidor, "ADMIN")
        admin.post("/admin/alertas/destinatarios", data={
            "tipo_destino": "EMAIL", "valor_email": CORREO_OFICIAL, "severidad_minima": "MEDIA"})
        destinatarios = self.servidor.consultar("SELECT * FROM alertas_destinatarios")

        # La científica de datos se autentica una vez con código de dispositivo (HU-5.7).
        self.analista = Analista(self.servidor, self.base / "equipo_cientifica")
        login = self.analista.iniciar_sesion_por_dispositivo()
        if not login.get("success"):
            raise RuntimeError(f"Falló el login por dispositivo:\n{login.get('salida')}")
        self._guardar("preparacion.json", {
            "dataset": NOMBRE_DATASET,
            "carpeta_datos": str(self.datos),
            "sha256_datos": {a: _sha256_archivo(self.datos / a) for a in ARCHIVOS_MIMIC},
            "servidor": self.servidor.url,
            "cuentas": [{"email": c["email"], "rol": c["rol"]} for c in
                        [cuenta(r) for r in ("ADMIN", "AUDITOR", "CIENTIFICO_DATOS")]],
            "usuario_id_cientifica": self.usuario_cientifica,
            "destinatarios_alertas": destinatarios,
            "login_dispositivo": {k: login.get(k) for k in
                                  ("success", "usuario_id", "origen", "codigo_mostrado", "confirmado_en_dashboard")},
        })

    def cerrar(self) -> None:
        if self.servidor:
            for nombre in ("servidor.log",):
                origen = self.base / nombre
                if origen.exists():
                    texto = origen.read_text(encoding="utf-8", errors="replace")
                    self._guardar(f"servidor/{nombre}", texto)
            self.servidor.detener()

    # ── CASO 1 ──────────────────────────────────────────────────
    def caso1(self) -> List[Verificacion]:
        C = "Caso 1 — Flujo de análisis normal"
        script = "caso1_analisis_cohorte.py"
        salida = self.base / "salidas_caso1"
        hora = self._utc(self.fecha, "10:00")
        ej = self._correr_script(script, str(salida), hora_utc=hora)
        # El servidor agrega eventos ANOMALIA_DETECTADA propios; no los generó el analista.
        anomalias_caso1 = [e for e in ej["eventos_central"] if e["tipo_accion"] == "ANOMALIA_DETECTADA"]
        eventos = [e for e in ej["eventos_central"] if e["tipo_accion"] != "ANOMALIA_DETECTADA"]
        self._guardar("caso1/eventos_anomalia_detectada.json", anomalias_caso1)
        ev_json = self._guardar("caso1/eventos_servidor_central.json", eventos)
        ev_local = self._guardar("caso1/eventos_base_local.json", ej["eventos_local"])
        archivos = {}
        for ruta in sorted(salida.glob("*.csv")):
            with open(ruta, encoding="utf-8") as f:
                cabecera = f.readline().strip()
                filas = sum(1 for _ in f)
            archivos[ruta.name] = {"filas": filas, "cabecera": cabecera, "sha256": _sha256_archivo(ruta)}
        ev_salidas = self._guardar("caso1/salidas_del_analista.json", archivos)
        codigo = (SCRIPTS / script).read_text(encoding="utf-8")
        ev_script = self._guardar(f"caso1/{script}", codigo)

        # 1.1 Captura automática sin modificar el código
        arbol = ast.parse(codigo)
        usos = [n for n in ast.walk(arbol) if isinstance(n, ast.Attribute)
                and isinstance(n.value, ast.Name) and n.value.id == "audit_tracer"]
        imports = [n for n in ast.walk(arbol) if isinstance(n, (ast.Import, ast.ImportFrom))
                   and any("audit_tracer" in (a.name or "") for a in n.names)
                   or (isinstance(n, ast.ImportFrom) and (n.module or "").startswith("audit_tracer"))]
        tipos = [e["tipo_accion"] for e in eventos]
        subtipos = sorted({re.match(r"\[(\w+)\]", e["motivo_fallo"] or "").group(1)
                           for e in eventos if e["tipo_accion"] == "TRANSFORMACION" and e["motivo_fallo"]})
        cargas = sorted(e["dataset_nombre"] for e in eventos if e["tipo_accion"] == "CARGA")
        exports = [e for e in eventos if e["tipo_accion"] == "EXPORTACION"]
        ok = (not usos and len(imports) == 1 and cargas == sorted(ARCHIVOS_MIMIC)
              and tipos.count("CONSULTA") >= 2 and len(exports) == 2
              and {"IMPUTACION", "MERGE", "ELIMINACION_COLS", "ELIMINACION_FILAS", "RENOMBRE"} <= set(subtipos))
        self._v("1.1", C, "La carga, la transformación y la exportación se capturan automáticamente "
                "sin modificar el código del analista.", ok,
                f"El script solo contiene `import audit_tracer` ({len(imports)} import, {len(usos)} llamadas a la "
                f"librería). Eventos en el servidor: CARGA={tipos.count('CARGA')} ({', '.join(cargas)}), "
                f"CONSULTA={tipos.count('CONSULTA')}, TRANSFORMACION={tipos.count('TRANSFORMACION')} "
                f"({', '.join(subtipos)}), EXPORTACION={len(exports)}.", [ev_script, ev_json])

        # 1.2 Identidad y sesión
        sesion = ej["sesion_id"]
        usuarios = {e["usuario_id"] for e in eventos}
        uuid_central = {e["evento_uuid"] for e in eventos}
        uuid_local = {e["evento_uuid"] for e in ej["eventos_local"]}
        firmados = sum(1 for e in eventos if e.get("firma_digital"))
        ok = (usuarios == {self.usuario_cientifica} and all(e["sesion_id"] == sesion for e in eventos)
              and tipos[0] == "INICIO_SESION" and tipos[-1] == "CIERRE_SESION" and uuid_central == uuid_local)
        self._v("1.2", C, "Cada evento queda con la identidad correcta del usuario y el identificador de sesión.",
                ok, f"{len(eventos)} eventos, todos con usuario_id={self.usuario_cientifica} "
                f"(cientifica@…, identificada con el token cacheado del login por dispositivo, sin escribir "
                f"credenciales) y sesion_id={sesion} (de INICIO_SESION a CIERRE_SESION). Los mismos "
                f"{len(uuid_local)} evento_uuid están en la base local y en la central; {firmados} con firma "
                f"Ed25519.", [ev_json, ev_local])

        # 1.3 Nivel de alerta según filas exportadas
        from audit_tracer.export_capture import UMBRAL_EXPORTACION_MASIVA
        detalle_exp = [(Path(e["ruta_destino"]).name, e["filas_exportadas"], e["nivel_alerta"], e["motivo_alerta"])
                       for e in exports]
        ok = all((f > UMBRAL_EXPORTACION_MASIVA) == (n == "CRITICO") for _, f, n, _ in detalle_exp) \
            and {n for _, _, n, _ in detalle_exp} == {"NORMAL", "CRITICO"}
        self._v("1.3", C, "La exportación activa el nivel de alerta según el número de registros exportados.", ok,
                "; ".join(f"{a}: {f} filas → {n}" + (f" ({m})" if m else "") for a, f, n, m in detalle_exp)
                + f". Umbral del código: > {UMBRAL_EXPORTACION_MASIVA} filas = CRITICO.", [ev_json, ev_salidas])

        # 1.4 Linaje (dashboard, como auditor)
        auditor = Navegador(self.servidor, "AUDITOR")
        grafos = {}
        for nombre in ("LABEVENTS.csv", "ADMISSIONS.csv", "merge(ADMISSIONS.csv,PATIENTS.csv)"):
            r = auditor.get("/api/linaje", params={"dataset": nombre})
            r.raise_for_status()
            g = r.json()
            g["cadenas"] = [c for c in g["cadenas"] if c["sesion_id"] == sesion]
            grafos[nombre] = g
        ev_linaje = self._guardar("caso1/linaje_api.json", grafos)

        def pasos(nombre):
            return [p["tipo_accion"] for c in grafos[nombre]["cadenas"] for p in c["pasos"]]

        def archivos_exportados(nombre):
            return sorted(n["label"] for n in grafos[nombre]["nodes"] if n.get("tipo") == "archivo"
                          and any(c["sesion_id"] == sesion for c in grafos[nombre]["cadenas"]))

        lab = pasos("LABEVENTS.csv")
        lab_ok = lab == ["CARGA", "TRANSFORMACION", "EXPORTACION"] and archivos_exportados("LABEVENTS.csv") == ["anexo_creatinina.csv"]
        adm, coh = pasos("ADMISSIONS.csv"), pasos("merge(ADMISSIONS.csv,PATIENTS.csv)")
        # La cohorte unida: desde la carga de ADMISSIONS y la de PATIENTS hasta el archivo exportado.
        g = grafos["merge(ADMISSIONS.csv,PATIENTS.csv)"]
        cargas = {n["dataset_nombre"]: n["id"] for n in g["nodes"] if n.get("tipo_accion") == "CARGA"
                  and n.get("sesion_id") == sesion}
        archivo = next((n["id"] for n in g["nodes"] if n.get("tipo") == "archivo"
                        and n["label"] == "reporte_clinico_cohorte.csv"), None)

        def alcanza(origen):
            vistos, pendientes = {origen}, [origen]
            while pendientes:
                actual = pendientes.pop()
                for e in g["edges"]:
                    if e["source"] == actual and e["target"] not in vistos:
                        vistos.add(e["target"])
                        pendientes.append(e["target"])
            return vistos

        cadena_completa_cohorte = bool(archivo) and all(
            archivo in alcanza(cargas[d]) for d in ("ADMISSIONS.csv", "PATIENTS.csv") if d in cargas)             and {"ADMISSIONS.csv", "PATIENTS.csv"} <= set(cargas)
        uniones = [e for e in g["edges"] if e["tipo"] == "union"]
        self._v("1.4a", C, "El grafo de linaje reconstruye la cadena de una tabla sin uniones "
                "(LABEVENTS: carga → limpieza → exportación).", lab_ok,
                f"Cadena LABEVENTS.csv en la sesión: {' → '.join(lab)} → archivo "
                f"{', '.join(archivos_exportados('LABEVENTS.csv'))}.", [ev_linaje])
        self._v("1.4b", C, "El grafo de linaje reconstruye la cadena completa de la cohorte "
                "(carga de ADMISSIONS y de PATIENTS → merge → limpieza → exportación del reporte).",
                cadena_completa_cohorte,
                f"Un solo grafo (dataset merge(ADMISSIONS.csv,PATIENTS.csv)) con {len(g['nodes'])} nodos y "
                f"{len(uniones)} aristas de unión; desde las cargas de {', '.join(sorted(cargas))} se llega al "
                f"archivo reporte_clinico_cohorte.csv.", [ev_linaje])

        # 1.5 Referencias normativas del reporte
        from audit_tracer.normative_mapping import SIN_REFERENCIA_NORMATIVA, referencia_normativa
        texto, filas, cabecera = auditor.csv("/reportes/exportar", reporte_usuario_id=self.usuario_cientifica,
                                             reporte_fecha_inicio=self.fecha.isoformat(),
                                             reporte_fecha_fin=self.fecha.isoformat())
        ev_rep = self._guardar("caso1/reporte_auditoria_sesion.csv", texto)
        ids_sesion = {str(e["event_id"]) for e in eventos}
        filas_sesion = [f for f in filas if f["event_id"] in ids_sesion]
        malas = [f for f in filas_sesion if f["referencia_normativa"] != referencia_normativa(f["tipo_accion"])]
        sin_ref = sorted({f["tipo_accion"] for f in filas_sesion if f["referencia_normativa"] == SIN_REFERENCIA_NORMATIVA})
        datos_ok = all("HIPAA §164.312(b)" in f["referencia_normativa"] and "Ley 1581" in f["referencia_normativa"]
                       for f in filas_sesion if f["tipo_accion"] in ("CARGA", "CONSULTA", "TRANSFORMACION", "EXPORTACION"))
        por_tipo = {}
        for f in filas_sesion:
            por_tipo.setdefault(f["tipo_accion"], f["referencia_normativa"])
        self._v("1.5", C, "El reporte incluye las referencias normativas correctas por tipo de evento.",
                len(filas_sesion) == len(eventos) and not malas and not sin_ref and datos_ok,
                f"{len(filas_sesion)} filas de la sesión en el CSV del dashboard; todas coinciden con la tabla "
                f"MAPEO_NORMATIVO (derivada de la matriz HU-6.6). Por tipo: "
                + " ; ".join(f"{t} = {r}" for t, r in por_tipo.items())
                + (f". Sin referencia: {sin_ref}" if sin_ref else ""), [ev_rep])
        self._caso1 = {"sesion": sesion, "eventos": eventos}
        return [v for v in self.verificaciones if v.caso == C]

    # ── CASO 2 ──────────────────────────────────────────────────
    def caso2(self) -> List[Verificacion]:
        C = "Caso 2 — Comportamiento anómalo"
        salida = self.base / "salidas_caso2"
        linea_base = []
        for i, filas in enumerate((120, 150, 180, 140, 160)):
            dia = self.fecha - timedelta(days=5 - i)
            ej = self._correr_script("caso2_muestra_habitual.py", str(salida), str(filas),
                                     hora_utc=self._utc(dia, f"{9 + i % 3}:{15 + 10 * i:02d}"))
            exp = next(e for e in ej["eventos_central"] if e["tipo_accion"] == "EXPORTACION")
            linea_base.append({"dia": dia.isoformat(), "sesion_id": ej["sesion_id"], "timestamp_utc": exp["timestamp"],
                               "filas_exportadas": exp["filas_exportadas"], "nivel_alerta": exp["nivel_alerta"]})
        ev_base = self._guardar("caso2/linea_base.json", linea_base)

        hora = self._utc(self.fecha, "03:10")
        ej = self._correr_script("caso2_exportacion_masiva.py", str(salida), hora_utc=hora)
        eventos = ej["eventos_central"]
        exp = next(e for e in eventos if e["tipo_accion"] == "EXPORTACION")
        ev_json = self._guardar("caso2/eventos_servidor_central.json", eventos)
        ev_script = self._guardar("caso2/caso2_exportacion_masiva.py",
                                  (SCRIPTS / "caso2_exportacion_masiva.py").read_text(encoding="utf-8"))

        # Lo que habría concluido el detector de anomalías sobre este mismo evento
        # (copia de la base central; el detector solo lee).
        detector = {
            # Lo que vería el detector si corriera al llegar el evento: todo el
            # historial anterior, incluidos INICIO_SESION y CARGA de esta misma sesión.
            "al_llegar_el_evento": self._evaluar_detector(exp),
            # El mismo cálculo con el historial previo a la sesión (sin los eventos de las 03:10).
            "historial_previo_a_la_sesion": self._evaluar_detector(exp, excluir_sesion=exp["sesion_id"]),
        }
        ev_det = self._guardar("caso2/evaluacion_detector_anomalias.json", detector)
        llegada, previo = detector["al_llegar_el_evento"], detector["historial_previo_a_la_sesion"]

        motivo = exp["motivo_alerta"] or ""
        anomalias = self.servidor.consultar(
            "SELECT * FROM audit_log WHERE tipo_accion = 'ANOMALIA_DETECTADA' AND sesion_id = ? ORDER BY event_id",
            (exp["sesion_id"],))
        ev_anom = self._guardar("caso2/eventos_anomalia_detectada.json", anomalias)
        con_las_dos = [a for a in anomalias if "Horario inusual" in a["motivo_alerta"]
                       and "Volumen anómalo" in a["motivo_alerta"]]
        anom = con_las_dos[0] if con_las_dos else (anomalias[0] if anomalias else {})
        motivo_anom = anom.get("motivo_alerta") or ""
        reglas_en_servidor = ("Horario inusual" in motivo_anom, "Volumen anómalo" in motivo_anom)
        self._v("2.1", C, "Se activan las dos reglas de anomalía (horario inusual y volumen anómalo) "
                "sobre la exportación registrada en el servidor.", all(reglas_en_servidor),
                f"La sesión de las 03:10 tiene {len(anomalias)} evento(s) ANOMALIA_DETECTADA (una por conjunto de "
                f"reglas y sesión). #{anom.get('event_id')}: «{motivo_anom}» — {anom.get('contexto_ejecucion')}.",
                [ev_json, ev_anom])
        self._v("2.1b", C, "El motor de detección, aplicado al evento con el historial que habría al recibirlo, "
                "activa las dos reglas.", llegada["regla_volumen"][0] and llegada["regla_horario"][0],
                f"Volumen: {llegada['regla_volumen'][1] or 'no se activa'}. Horario: "
                f"{llegada['regla_horario'][1] or 'no se activa'} (horario habitual calculado = "
                f"{llegada['horario_habitual_utc']} UTC; el historial excluye la sesión en curso).", [ev_det, ev_base])
        self._v("2.1c", C, "El motor de detección, con el historial previo a la sesión, activa las dos reglas.",
                previo["regla_volumen"][0] and previo["regla_horario"][0],
                f"Volumen: {previo['regla_volumen'][1] or 'no se activa'}. Horario: "
                f"{previo['regla_horario'][1] or 'no se activa'} (horario habitual = "
                f"{previo['horario_habitual_utc']} UTC).", [ev_det, ev_base])
        self._v("2.2", C, "El evento queda con su nivel de alerta.",
                exp["nivel_alerta"] == "CRITICO" and anom.get("nivel_alerta") == "ANOMALIA",
                f"La exportación #{exp['event_id']} conserva el nivel de la librería (nivel_alerta={exp['nivel_alerta']}, "
                f"motivo «{motivo}») porque está firmada y su nivel y motivo forman parte de la firma; el evento "
                f"#{anom.get('event_id')} que la acompaña tiene nivel_alerta={anom.get('nivel_alerta')}.", [ev_json, ev_anom])
        self._v("2.3", C, "Se genera la descripción del motivo de la alerta con las reglas de anomalía.",
                all(reglas_en_servidor) and motivo_anom.startswith("Anomalía (reglas: volumen anómalo, horario inusual)"),
                f"motivo_alerta del evento ANOMALIA_DETECTADA: «{motivo_anom}».", [ev_anom])

        # 2.4 Correo al oficial de cumplimiento
        notif = esperar(lambda: self.servidor.consultar(
            "SELECT * FROM alertas_notificaciones WHERE event_id = ? AND estado != 'PENDIENTE'", (exp["event_id"],)),
            timeout=60, descripcion="notificación del evento")[0]
        correos = []
        from email import policy
        from email.parser import BytesParser
        for eml in sorted(self.servidor.outbox.glob("*.eml")):
            msg = BytesParser(policy=policy.default).parse(open(eml, "rb"))
            cuerpo = msg.get_body(preferencelist=("plain",))
            texto = cuerpo.get_content() if cuerpo else ""
            if f"/eventos/{exp['event_id']}" in texto:
                correos.append((eml, msg, texto))
        ev_correo = []
        if correos:
            eml, msg, _ = correos[0]
            ev_correo.append(self._guardar("caso2/correo_oficial_cumplimiento.eml", eml.read_bytes()))
        ev_notif = self._guardar("caso2/notificacion.json", notif)
        para = ", ".join(str(correos[0][1][h]) for h in ("To", "Cc", "Bcc") if correos and correos[0][1][h])
        ok_correo = bool(notif["estado"] == "ENVIADA" and CORREO_OFICIAL in para and correos)
        self._v("2.4a", C, "Se envía automáticamente la notificación por correo al oficial de cumplimiento.",
                ok_correo,
                f"alertas_notificaciones: estado={notif['estado']}, tipos={notif.get('tipos_criticos')}, "
                f"severidad={notif.get('severidad')}, intentos={notif.get('intentos')}, destinatarios del "
                f"correo (To/Cc/Bcc)={para}; asunto «{correos[0][1]['Subject'] if correos else ''}». "
                f"El correo lo dispara la regla EXPORTACION_MASIVA (> 1000 filas), no una anomalía. "
                f"Entrega por la carpeta outbox (AUDIT_ALERTAS_OUTBOX), el modo sin SMTP del sistema; no se "
                f"probó contra un servidor SMTP real.", ev_correo + [ev_notif])

        # 2.4b Independencia: el registro no espera al correo, aunque el correo falle.
        indep = self._probar_independencia_correo(exp)
        ev_ind = self._guardar("caso2/independencia_correo.json", indep)
        self._v("2.4b", C, "El envío del correo es independiente del registro del evento "
                "(el evento se guarda aunque el correo falle o tarde).",
                indep["evento_persistido"] and indep["insercion_segundos"] < 1.0
                and indep["estado_notificacion"] == "FALLIDA",
                f"Con un servicio de correo que tarda 2 s y falla siempre, insert_event devolvió en "
                f"{indep['insercion_segundos']:.3f} s, el evento quedó en audit_log y la notificación terminó en "
                f"{indep['estado_notificacion']} tras {indep['intentos']} intentos, en otro hilo.", [ev_ind])
        self._caso2 = {"evento": exp, "eventos": eventos}
        return [v for v in self.verificaciones if v.caso == C]

    def _evaluar_detector(self, exp: Dict, excluir_sesion: Optional[str] = None) -> Dict:
        """
        Corre anomaly_detector sobre una copia de audit_log con solo los eventos
        anteriores a `exp` (y, opcionalmente, sin los de una sesión). El detector
        solo lee audit_log; la copia no tiene triggers ni toca la base central.
        """
        from audit_tracer.anomaly_detector import (
            calcular_promedios_historicos, evaluar_evento_anomalias, evaluar_regla_horario,
            evaluar_regla_volumen, obtener_horario_habitual)
        sufijo = "sin_sesion" if excluir_sesion else "al_llegar"
        copia = self.base / f"detector_{sufijo}_{exp['event_id']}.db"
        copia.unlink(missing_ok=True)
        with closing(sqlite3.connect(copia)) as conn:
            conn.execute("ATTACH DATABASE ? AS central", (str(self.servidor.db_path),))
            filtro = "event_id < ?" + (" AND sesion_id != ?" if excluir_sesion else "")
            params = (exp["event_id"], excluir_sesion) if excluir_sesion else (exp["event_id"],)
            conn.execute(f"CREATE TABLE audit_log AS SELECT * FROM central.audit_log WHERE {filtro}", params)
            conn.commit()
            conn.execute("DETACH DATABASE central")
            conn.row_factory = sqlite3.Row
            evento = dict(exp)
            vol = evaluar_regla_volumen(conn, dict(evento))
            hor = evaluar_regla_horario(conn, dict(evento))
            es_anomalo, evaluado, motivos = evaluar_evento_anomalias(conn, dict(evento))
            return {
                "eventos_en_historial": conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0],
                "promedios_historicos_usuario": calcular_promedios_historicos(
                    conn, exp["usuario_id"], excluir_fecha=exp["timestamp"][:10]),
                "horario_habitual_utc": obtener_horario_habitual(conn, exp["usuario_id"]),
                "regla_volumen": vol, "regla_horario": hor, "es_anomalo": es_anomalo, "motivos": motivos,
                "nivel_que_asignaria": evaluado.get("nivel_alerta"),
                "motivo_que_asignaria": evaluado.get("motivo_alerta"),
            }

    def _probar_independencia_correo(self, exp: Dict) -> Dict:
        from audit_tracer.alerts.dispatcher import DespachadorAlertas
        from audit_tracer.alerts.email_service import ServicioCorreoMemoria
        from audit_tracer.db import get_central_connection
        from audit_tracer.models import alertas as modelo
        from audit_tracer.models.audit_log import (
            eliminar_hook_post_insercion, get_event_by_id, insert_event, registrar_hook_post_insercion)
        db = self.base / "central_independencia.db"
        with closing(get_central_connection(str(db))) as conn:
            modelo.ensure_alert_tables(conn)
            modelo.crear_destinatario(conn, "EMAIL", CORREO_OFICIAL, "MEDIA", [], creado_por="validacion")
        servicio = ServicioCorreoMemoria(fallos=99, demora_segundos=2.0)
        d = DespachadorAlertas(str(db), servicio_correo=servicio, max_intentos=3, backoff_base_segundos=0.1)
        registrar_hook_post_insercion(d.hook_post_insercion)
        d.iniciar()
        try:
            campos = ("usuario_id", "sesion_id", "timestamp", "tipo_accion", "dataset_nombre", "ruta_destino",
                      "filas_exportadas", "sobrescritura", "contexto_ejecucion", "nivel_alerta", "motivo_alerta")
            evento = {c: exp.get(c) for c in campos}
            with closing(get_central_connection(str(db))) as conn:
                t0 = time.perf_counter()
                event_id = insert_event(conn, evento)
                dt = time.perf_counter() - t0
                persistido = get_event_by_id(conn, event_id) is not None
            esperar(lambda: d.esperar(timeout=1) or None, timeout=30, descripcion="cola del despachador vacía")
            with closing(get_central_connection(str(db))) as conn:
                notif = modelo.obtener_notificacion_por_evento(conn, event_id) or {}
        finally:
            eliminar_hook_post_insercion(d.hook_post_insercion)
            d.detener(timeout=2)
        return {"insercion_segundos": dt, "evento_persistido": persistido, "event_id": event_id,
                "estado_notificacion": notif.get("estado"), "intentos": notif.get("intentos"),
                "error": notif.get("error"), "intentos_servicio": servicio.intentos}

    # ── CASO 3 ──────────────────────────────────────────────────
    def caso3(self) -> List[Verificacion]:
        C = "Caso 3 — Evidencia para auditoría regulatoria"
        auditor = Navegador(self.servidor, "AUDITOR")
        hoy, ayer = self.fecha.isoformat(), (self.fecha - timedelta(days=1)).isoformat()
        hace5 = (self.fecha - timedelta(days=5)).isoformat()
        u = self.usuario_cientifica
        consultas = {
            "periodo_completo": dict(reporte_fecha_inicio=hace5, reporte_fecha_fin=hoy),
            "solo_ayer": dict(reporte_fecha_inicio=ayer, reporte_fecha_fin=ayer),
            "usuario_en_periodo": dict(reporte_usuario_id=u, reporte_fecha_inicio=hace5, reporte_fecha_fin=hoy),
            "accesos_carga_usuario_periodo": dict(reporte_usuario_id=u, reporte_tipo_accion="CARGA",
                                                  reporte_fecha_inicio=hace5, reporte_fecha_fin=hoy),
            "exportaciones_usuario_periodo": dict(reporte_usuario_id=u, reporte_tipo_accion="EXPORTACION",
                                                  reporte_fecha_inicio=hace5, reporte_fecha_fin=hoy),
            "sin_resultados": dict(reporte_usuario_id=self.usuario_auditor, reporte_tipo_accion="EXPORTACION",
                                   reporte_fecha_inicio=hace5, reporte_fecha_fin=hoy),
        }
        def descargas_reporte():
            return self.servidor.consultar(
                "SELECT contexto_ejecucion FROM audit_log WHERE tipo_accion = 'DESCARGA_REPORTE' AND usuario_id = ? "
                "AND contexto_ejecucion LIKE 'Vista: /reportes/exportar |%' ORDER BY event_id", (self.usuario_auditor,))

        previas = len(descargas_reporte())
        resultados, evid = {}, []
        for nombre, params in consultas.items():
            texto, filas, cabecera = auditor.csv("/reportes/exportar", **params)
            resultados[nombre] = (texto, filas, cabecera)
            evid.append(self._guardar(f"caso3/reporte_{nombre}.csv", texto))
        self._guardar("caso3/consultas.json", consultas)

        def esperado(sql_extra="", params=()):
            inicio = datetime(*(self.fecha - timedelta(days=5)).timetuple()[:3], tzinfo=COLOMBIA)
            fin = datetime(*self.fecha.timetuple()[:3], 23, 59, 59, 999999, tzinfo=COLOMBIA)
            a_utc = lambda d: d.astimezone(timezone.utc).replace(tzinfo=None).isoformat()
            # Desde el 21/11/2026 cada consulta y descarga del auditor queda en la bitácora
            # (DSH-R1): esos registros los agregan las propias descargas de este caso, así
            # que se comparan aparte y no forman parte del conjunto esperado.
            return {str(f["event_id"]) for f in self.servidor.consultar(
                f"SELECT event_id FROM audit_log WHERE timestamp >= ? AND timestamp <= ? "
                f"AND tipo_accion NOT IN ('DESCARGA_REPORTE', 'CONSULTA_BITACORA') {sql_extra}",
                (a_utc(inicio), a_utc(fin), *params))}

        def ids(nombre):
            return {f["event_id"] for f in resultados[nombre][1]
                    if f["tipo_accion"] not in ("DESCARGA_REPORTE", "CONSULTA_BITACORA")}

        descargas = descargas_reporte()[previas:]
        ok_descargas = len(descargas) == len(consultas) and all("SHA-256:" in d["contexto_ejecucion"] for d in descargas)

        dias_ayer = {f["timestamp"][:10] for f in resultados["solo_ayer"][1]}
        ok_fecha = ids("periodo_completo") == esperado() and dias_ayer == {ayer} and resultados["solo_ayer"][1]
        ok_usuario = ids("usuario_en_periodo") == esperado("AND usuario_id = ?", (u,)) \
            and {f["usuario_id"] for f in resultados["usuario_en_periodo"][1]} == {u}
        ok_tipo = all(ids(n) == esperado("AND usuario_id = ? AND tipo_accion = ?", (u, t)) and
                      {f["tipo_accion"] for f in resultados[n][1]} == {t}
                      for n, t in (("accesos_carga_usuario_periodo", "CARGA"),
                                   ("exportaciones_usuario_periodo", "EXPORTACION")))
        self._v("3.1", C, "Funcionan los filtros por fecha, usuario y tipo de operación (solos y combinados).",
                ok_fecha and ok_usuario and ok_tipo and ok_descargas,
                f"Período {hace5}–{hoy}: {len(ids('periodo_completo'))} eventos; solo {ayer}: "
                f"{len(ids('solo_ayer'))} (todos con fecha {', '.join(sorted(dias_ayer))}); usuario: "
                f"{len(ids('usuario_en_periodo'))}; usuario+CARGA: {len(ids('accesos_carga_usuario_periodo'))}; "
                f"usuario+EXPORTACION: {len(ids('exportaciones_usuario_periodo'))}. Cada conjunto es idéntico al "
                f"que devuelve una consulta SQL directa a la base central con los mismos criterios. Cada una de "
                f"las {len(consultas)} descargas quedó registrada como DESCARGA_REPORTE del auditor con el SHA-256 "
                f"del archivo ({len(descargas)} registros).", evid)

        cabecera = resultados["periodo_completo"][2]
        minimos = ["event_id", "usuario_id", "timestamp", "tipo_accion", "dataset_nombre", "referencia_normativa"]
        faltan_minimos = [c for c in minimos if c not in cabecera]
        trazabilidad = {"sesion_id": "sesión", "contexto_ejecucion": "origen de la solicitud (script, entorno, host)",
                        "hash_integridad": "huella para verificar el registro"}
        faltan_traza = [f"{c} ({d})" for c, d in trazabilidad.items() if c not in cabecera]
        self._v("3.2a", C, "El reporte incluye quién, qué, cuándo, sobre qué dataset y la base normativa "
                "(HIPAA §164.312(b) y Ley 1581).", not faltan_minimos,
                f"Columnas del CSV: {', '.join(cabecera)}.", evid[:1])
        self._v("3.2b", C, "El reporte incluye también la sesión, el origen de la solicitud y la huella de cada "
                "evento.", not faltan_traza,
                ("Columnas del CSV: " + ", ".join(cabecera) + "." if not faltan_traza else
                 "El CSV no trae: " + "; ".join(faltan_traza) + "."), evid[:1])

        texto, filas, cab = resultados["sin_resultados"]
        lector = list(csv.reader(io.StringIO(texto)))
        self._v("3.3", C, "El CSV exportado es válido aunque los filtros no den resultados.",
                filas == [] and lector == [cab] and cab == list(dict.fromkeys(cab)) and len(cab) >= len(minimos),
                f"Filtro sin coincidencias (auditor + EXPORTACION): respuesta con solo la cabecera "
                f"({len(cab)} columnas) y 0 filas; csv.reader la lee sin errores.", [evid[-1]])

        # 3.4 Integridad: hash por evento y prueba de Merkle del lote histórico
        from audit_tracer.models.audit_log import _HASHED_COLUMNS
        from audit_tracer.utils.hashing import hash_event
        exp2 = self._caso2["evento"]
        fila = self.servidor.consultar("SELECT * FROM audit_log WHERE event_id = ?", (exp2["event_id"],))[0]
        recalculado = hash_event({c: fila.get(c) for c in _HASHED_COLUMNS})
        alterado = dict(fila, filas_exportadas=120)
        hash_alterado = hash_event({c: alterado.get(c) for c in _HASHED_COLUMNS})
        r = auditor.post("/verificar-integridad", allow_redirects=True)
        integro = "Todos los registros son íntegros" in r.text
        integridad = {"event_id": fila["event_id"], "hash_almacenado": fila["hash_integridad"],
                      "hash_recalculado": recalculado, "coincide": recalculado == fila["hash_integridad"],
                      "hash_si_se_altera_filas_exportadas": hash_alterado,
                      "verificacion_dashboard_todos_integros": integro,
                      "campos_del_hash": _HASHED_COLUMNS}
        ev_int = self._guardar("caso3/integridad_hash.json", integridad)
        self._v("3.4a", C, "La integridad de un evento se puede verificar por su hash.",
                integridad["coincide"] and hash_alterado != fila["hash_integridad"] and integro,
                f"Evento #{fila['event_id']}: SHA-256 recalculado sobre los {len(_HASHED_COLUMNS)} campos = "
                f"almacenado ({recalculado[:16]}…). Si se cambia filas_exportadas el hash cambia. El botón "
                f"«Verificar integridad» del dashboard (POST /verificar-integridad) reporta todos los registros "
                f"íntegros.", [ev_int])

        lote = fila["timestamp"][:13]
        pub = auditor.post("/merkle/publicar", json={"batch_hour": lote})
        prueba = auditor.get(f"/merkle/verificar/{fila['event_id']}").json()
        r_ancla = auditor.post("/merkle/verificar-ancla", data={"batch_hour": lote})
        from audit_tracer.merkle import verify_external_anchor
        with closing(sqlite3.connect(f"file:{self.servidor.db_path.as_posix()}?mode=ro", uri=True)) as conn:
            ancla = verify_external_anchor(conn, lote, anchors_dir=str(self.servidor.anclas))
        archivo_ancla = next(self.servidor.anclas.glob(f"merkle_{lote.replace(':', '-')}.json"), None)
        merkle = {"lote": lote, "publicacion": pub.json() if pub.ok else pub.text, "prueba_evento": prueba,
                  "verificacion_ancla": ancla, "pagina_verificar_ancla_http": r_ancla.status_code,
                  "raiz_en_pagina": bool(ancla.get("published_root")) and ancla["published_root"] in r_ancla.text}
        ev_m = [self._guardar("caso3/merkle.json", merkle)]
        if archivo_ancla:
            ev_m.append(self._guardar(f"caso3/{archivo_ancla.name}", archivo_ancla.read_text(encoding="utf-8")))
        self._v("3.4b", C, "Para lotes históricos, la integridad se verifica con la prueba de Merkle y el ancla publicada.",
                prueba.get("integrity_ok") and ancla.get("integrity_ok") and ancla.get("signature_valid")
                and merkle["raiz_en_pagina"],
                f"Lote {lote} (hora UTC): publicado por el auditor (POST /merkle/publicar), prueba de inclusión del "
                f"evento #{fila['event_id']} con {prueba.get('proof_steps')} pasos = válida; raíz publicada = raíz "
                f"recalculada ({str(ancla.get('published_root'))[:16]}…), firma Ed25519 del ancla válida. El ancla "
                f"es un archivo JSON en la carpeta del servidor (AUDIT_MERKLE_ANCHORS_DIR), no un servicio externo.",
                ev_m)
        return [v for v in self.verificaciones if v.caso == C]

    # ── ejecución completa ──────────────────────────────────────
    def ejecutar(self) -> Dict:
        try:
            self.preparar()
            self.caso1()
            self.caso2()
            self.caso3()
        finally:
            self.cerrar()
        return self.finalizar()

    def finalizar(self) -> Dict:
        """Escribe resultados.json y RESULTADOS.md con todas las verificaciones."""
        info = dict(self._info)
        info["duracion_segundos"] = round(time.monotonic() - self._inicio, 1)
        resumen = {
            "entorno": info,
            "dataset": NOMBRE_DATASET,
            "reloj": {
                "fecha_de_los_eventos": self.fecha.isoformat(),
                "caso1_hora_colombia": "10:00",
                "caso2_linea_base": "5 días anteriores, entre 09:15 y 11:55 hora Colombia",
                "caso2_exportacion_masiva_hora_colombia": "03:10",
                "nota": "Hora del día fijada con validacion/reloj.py en el proceso del analista; "
                        "la fecha es la de ejecución.",
            },
            "verificaciones": [dict(asdict(v), estado=v.estado) for v in self.verificaciones],
            "totales": {"cumple": sum(v.cumple for v in self.verificaciones),
                        "no_cumple": sum(not v.cumple for v in self.verificaciones)},
        }
        self._guardar("resultados.json", resumen)
        self._guardar("RESULTADOS.md", tabla_markdown(resumen))
        return resumen


def tabla_markdown(resumen: Dict) -> str:
    e = resumen["entorno"]
    lineas = [
        f"# Resultados de la validación con MIMIC-III Demo",
        "",
        f"- Fecha de ejecución: {e['fecha_ejecucion']}",
        f"- Commit: `{e['commit']}` ({e['rama']}, {e['fecha_commit']})"
        + (" — con cambios sin commit" if e["cambios_sin_commit"] else ""),
        f"- Entorno: Python {e['python']}, pandas {e['pandas']}, {e['sistema']}, {e['cpus_logicas']} CPU lógicas",
        f"- Dataset: {resumen['dataset']}",
        f"- Duración: {e['duracion_segundos']} s",
        "",
        "| # | Caso | Afirmación | Estado | Detalle |",
        "|---|---|---|---|---|",
    ]
    for v in resumen["verificaciones"]:
        detalle = v["detalle"].replace("|", "\\|")
        lineas.append(f"| {v['id']} | {v['caso'].split(' — ')[0]} | {v['afirmacion']} | **{v['estado']}** | {detalle} |")
    t = resumen["totales"]
    lineas += ["", f"Total: {t['cumple']} CUMPLE, {t['no_cumple']} NO CUMPLE."]
    return "\n".join(lineas) + "\n"


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--evidencia", required=True, help="Carpeta donde se guarda la evidencia")
    p.add_argument("--datos", help="Carpeta con los CSV de MIMIC-III Demo (por defecto MIMIC_DEMO_DIR o validacion/datos/...)")
    args = p.parse_args()
    datos = Path(args.datos) if args.datos else carpeta_mimic()
    if datos is None:
        sys.exit("No están los CSV de MIMIC-III Demo. Ejecuta: python validacion/descargar_mimic.py")
    resumen = ValidacionMIMIC(Path(args.evidencia), datos).ejecutar()
    for v in resumen["verificaciones"]:
        print(f"{v['id']:5} {v['estado']:10} {v['afirmacion']}")
    print(f"Total: {resumen['totales']}")


if __name__ == "__main__":
    main()
