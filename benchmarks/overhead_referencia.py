"""
benchmarks/overhead_referencia.py
==================================
HU-6.7 — Benchmark de overhead de rendimiento
HU-5.1 CA3 — Overhead de `import audit_tracer` sobre script de referencia

Criterios de Aceptación:
  CA1: Mide el tiempo de operaciones comunes de pandas (lectura, transformación, exportación)
       con y sin audit_tracer activo (y con servidor de sincronización no disponible).
  CA2: Medición sobre tres tamaños distintos de dataset (pequeño, mediano, grande).
  CA3: Documenta los resultados indicando el porcentaje de overhead por operación y tamaño.
  CA4: Si el overhead supera el umbral aceptable (5%), lo documenta como hallazgo de
       optimización futura con diagnóstico de causa raíz y recomendaciones.

Uso CLI:
    python benchmarks/overhead_referencia.py --filas 50000 200000 1000000 \
        --corridas 5 --umbral-pct 5.0 --salida-json benchmarks/resultados_benchmark.json
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

# Reconfigurar stdout en Windows si la consola usa cp1252
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Umbral estándar definido en CA4 (5%)
UMBRAL_OVERHEAD_ACEPTABLE_DEFECTO = 5.0

# Tamaños estándar para cumplir CA2
TAMANOS_ESTANDAR = {
    50_000: "Pequeño (~4 MB)",
    200_000: "Mediano (~18 MB)",
    1_000_000: "Grande (~90 MB)",
}

# Flujo de referencia estructurado por operaciones (CA1)
FLUJO = '''
# ── FASE 1: LECTURA (pd.read_csv) ──────────────────────────────────
_tl0 = time.perf_counter()
pacientes = pd.read_csv("pacientes.csv")
diagnosticos = pd.read_csv("diagnosticos.csv")
_tl1 = time.perf_counter()

# ── FASE 2: TRANSFORMACIÓN (query, fillna, dropna, rename, drop, apply, merge, groupby)
_tt0 = time.perf_counter()
edades = pacientes["edad"]
adultos = pacientes.query("edad >= 18")
adultos = adultos.fillna({"glucosa": adultos["glucosa"].median(), "presion": 120})
adultos = adultos.dropna(subset=["sexo"])
adultos = adultos.rename(columns={"presion": "presion_sistolica"})
adultos = adultos.drop(columns=["notas"])
escaladas = adultos[["glucosa", "imc"]].apply(lambda c: (c - c.min()) / (c.max() - c.min()))
completo = adultos.merge(diagnosticos, on="diagnostico_id", how="left")
resumen = completo.groupby("categoria")["glucosa"].mean()
_tt1 = time.perf_counter()

# ── FASE 3: EXPORTACIÓN (to_csv) ───────────────────────────────────
_te0 = time.perf_counter()
completo.to_csv("salida_completa.csv", index=False)
resumen.to_frame().to_csv("salida_resumen.csv")
_te1 = time.perf_counter()
'''

PLANTILLA = '''
import time
_t0 = time.perf_counter()
{import_auditoria}
import pandas as pd
{config_sync}
_t1 = time.perf_counter()
{flujo}
_t2 = time.perf_counter()
import json
print(json.dumps({{
    "total": _t2 - _t0,
    "imports": _t1 - _t0,
    "cuerpo": _t2 - _t1,
    "lectura": _tl1 - _tl0,
    "transformacion": _tt1 - _tt0,
    "exportacion": _te1 - _te0,
}}))
'''

MODOS = {
    "sin_auditoria": ("", ""),
    "con_auditoria": ("import audit_tracer", ""),
    "con_sync_caido": (
        "import audit_tracer",
        'audit_tracer.configure_sync("http://127.0.0.1:9", "token-de-prueba")',
    ),
}

OPERACIONES = ("lectura", "transformacion", "exportacion", "cuerpo", "imports", "total", "proceso")


def categorizar_tamano(filas: int) -> str:
    """Clasifica el tamaño del dataset según las categorías de CA2."""
    if filas in TAMANOS_ESTANDAR:
        return TAMANOS_ESTANDAR[filas]
    if filas < 100_000:
        return f"Pequeño ({filas:,} filas)"
    elif filas <= 500_000:
        return f"Mediano ({filas:,} filas)"
    else:
        return f"Grande ({filas:,} filas)"


def generar_datos(carpeta: str, filas: int, semilla: int = 7) -> None:
    """Dataset sintético clínico estructurado para el benchmark."""
    rng = np.random.default_rng(semilla)
    pacientes = pd.DataFrame({
        "paciente_id": np.arange(filas),
        "edad": rng.integers(0, 95, filas),
        "sexo": rng.choice(["F", "M", None], filas, p=[0.49, 0.49, 0.02]),
        "glucosa": np.where(rng.random(filas) < 0.1, np.nan, rng.normal(100, 25, filas)),
        "presion": np.where(rng.random(filas) < 0.05, np.nan, rng.normal(120, 15, filas)),
        "imc": rng.normal(26, 4, filas),
        "diagnostico_id": rng.integers(0, 50, filas),
        "notas": rng.choice(["control", "urgencia", "seguimiento"], filas),
    })
    diagnosticos = pd.DataFrame({
        "diagnostico_id": np.arange(50),
        "categoria": [f"cat_{i % 8}" for i in range(50)],
    })
    pacientes.to_csv(os.path.join(carpeta, "pacientes.csv"), index=False)
    diagnosticos.to_csv(os.path.join(carpeta, "diagnosticos.csv"), index=False)


def correr_proceso(modo: str, carpeta: str, home: str) -> dict:
    """Ejecuta una corrida aislada en un subproceso de Python limpio."""
    import_auditoria, config_sync = MODOS[modo]
    codigo = PLANTILLA.format(
        import_auditoria=import_auditoria,
        config_sync=config_sync,
        flujo=FLUJO
    )
    env = dict(os.environ)
    env["HOME"] = home
    env["USERPROFILE"] = home
    env.pop("AUDIT_TRACER_API_URL", None)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")

    inicio = time.perf_counter()
    salida = subprocess.run(
        [sys.executable, "-c", codigo],
        cwd=carpeta,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    tiempos = json.loads(salida.stdout.strip().splitlines()[-1])
    # Proceso completo: arranque del intérprete + imports + flujo + cierre
    tiempos["proceso"] = time.perf_counter() - inicio
    return tiempos


def medir_tamano(filas: int, corridas: int = 5) -> dict:
    """
    HU-6.7 CA1 & CA2: Mide tiempos de lectura, transformación, exportación
    y proceso completo para un tamaño de dataset en cada modo.
    """
    with tempfile.TemporaryDirectory(prefix="audit_bench_") as carpeta:
        generar_datos(carpeta, filas)
        homes = {modo: os.path.join(carpeta, f"home_{modo}") for modo in MODOS}
        for home in homes.values():
            os.makedirs(home)

        # Corrida de calentamiento (no se contabiliza)
        for modo in MODOS:
            correr_proceso(modo, carpeta, homes[modo])

        # Recolección intercalada de corridas
        tiempos = {modo: [] for modo in MODOS}
        for _ in range(corridas):
            for modo in MODOS:
                tiempos[modo].append(correr_proceso(modo, carpeta, homes[modo]))

    # Cálculo estadístico base (sin_auditoria)
    base_stats = {}
    for op in OPERACIONES:
        vals = [t[op] for t in tiempos["sin_auditoria"]]
        base_stats[op] = {
            "promedio_s": statistics.mean(vals),
            "mediana_s": statistics.median(vals),
        }

    resultado = {
        "filas": filas,
        "categoria": categorizar_tamano(filas),
        "corridas": corridas,
        "modos": {},
    }

    # Procesar métricas por modo y por operación (CA3)
    for modo, ts in tiempos.items():
        op_stats = {}
        for op in OPERACIONES:
            vals = [t[op] for t in ts]
            prom = statistics.mean(vals)
            med = statistics.median(vals)
            base_p = base_stats[op]["promedio_s"]
            base_m = base_stats[op]["mediana_s"]

            overhead_p = ((prom - base_p) / base_p * 100) if base_p > 0 else 0.0
            overhead_m = ((med - base_m) / base_m * 100) if base_m > 0 else 0.0

            op_stats[op] = {
                "promedio_s": prom,
                "mediana_s": med,
                "desv_std_s": statistics.stdev(vals) if len(vals) > 1 else 0.0,
                "overhead_pct": overhead_p,
                "overhead_mediana_pct": overhead_m,
                "corridas_s": vals,
            }

        resultado["modos"][modo] = {
            "operaciones": op_stats,
            # Atajos compatibles con versión previa de overhead_referencia
            "promedio_s": op_stats["total"]["promedio_s"],
            "mediana_s": op_stats["total"]["mediana_s"],
            "desv_std_s": op_stats["total"]["desv_std_s"],
            "overhead_pct": op_stats["total"]["overhead_pct"],
            "overhead_mediana_pct": op_stats["total"]["overhead_mediana_pct"],
            "imports_promedio_s": op_stats["imports"]["promedio_s"],
            "cuerpo_promedio_s": op_stats["cuerpo"]["promedio_s"],
            "proceso_promedio_s": op_stats["proceso"]["promedio_s"],
            "overhead_proceso_pct": op_stats["proceso"]["overhead_pct"],
        }

    return resultado


def evaluar_hallazgos(
    resultados: List[dict],
    umbral_pct: float = UMBRAL_OVERHEAD_ACEPTABLE_DEFECTO
) -> List[dict]:
    """
    HU-6.7 CA4: Identifica operaciones donde el overhead supera el umbral
    aceptable y formula hallazgos con diagnósticos de causa raíz y recomendaciones.
    """
    hallazgos = []

    # Explicaciones técnicas predefinidas según la naturaleza del overhead
    diagnosticos_conocidos = {
        "imports": (
            "Costo fijo de importación de dependencias criptográficas (cryptography, ed25519) "
            "e inicialización perezosa de la base SQLite local.",
            "Implementar lazy-import para que cryptography y schemas solo se importen "
            "cuando se capture el primer evento, evitando demoras al arrancar scripts rápidos."
        ),
        "total": (
            "El tiempo total en scripts de ejecución corta está dominado por la inicialización fija "
            "de imports e interceptores, amplificando el overhead porcentual relativo.",
            "Optimizar la fase de bootstrap de la librería para reducir el tiempo de inicialización "
            "a menos de 80ms."
        ),
        "proceso": (
            "Tiempo de vida del proceso Python que incluye el arranque, la ejecución del script y el flush "
            "final de colas antes de atexit.",
            "Asegurar que el hilo de flush y sync cliente termine inmediatamente si la cola está vacía."
        ),
        "lectura": (
            "Intercepción síncrona de pd.read_csv: inspección del DataFrame, cálculo de SHA-256 e inserción SQLite.",
            "Diferir el hashing y persistencia de eventos de lectura a un hilo secundario en memoria."
        ),
        "transformacion": (
            "Envoltura de DataFrame (AuditedTransformDataFrame) e introspección de argumentos en pandas.",
            "Cachear metadatos de transformaciones repetidas para evitar resolución reflexiva continua."
        ),
        "exportacion": (
            "Validación de umbrales de exportación masiva y persistencia síncrona en SQLite.",
            "Desacoplar la persistencia del archivo final respecto a la escritura del evento de auditoría."
        ),
        "cuerpo": (
            "Acumulación de interceptores en la cadena de procesamiento de pandas.",
            "Agrupar eventos atómicos en lotes (batching) cuando se ejecuten múltiples operaciones consecutivas."
        ),
    }

    for res in resultados:
        filas = res["filas"]
        cat = res["categoria"]
        # Evaluamos principalmente el modo con_auditoria estándar
        for modo in ("con_auditoria", "con_sync_caido"):
            ops = res["modos"][modo]["operaciones"]
            for op, stats in ops.items():
                pct = stats["overhead_pct"]
                if pct > umbral_pct:
                    causa, rec = diagnosticos_conocidos.get(
                        op,
                        ("Sobrecarga de intercepción síncrona.", "Evaluar procesamiento asíncrono.")
                    )
                    base_prom = res["modos"]["sin_auditoria"]["operaciones"][op]["promedio_s"]
                    modo_prom = stats["promedio_s"]
                    diff_ms = (modo_prom - base_prom) * 1000

                    hallazgos.append({
                        "tamano_filas": filas,
                        "categoria": cat,
                        "modo": modo,
                        "operacion": op,
                        "overhead_pct": round(pct, 2),
                        "umbral_pct": umbral_pct,
                        "diferencia_ms": round(diff_ms, 2),
                        "tiempo_base_s": round(base_prom, 4),
                        "tiempo_modo_s": round(modo_prom, 4),
                        "supera_umbral": True,
                        "causa_raiz": causa,
                        "recomendacion": rec,
                    })

    return hallazgos


def imprimir_tabla_resultados(
    resultados: List[dict],
    hallazgos: List[dict],
    umbral_pct: float
) -> None:
    """Imprime en consola tablas formateadas con los resultados y hallazgos."""
    print("=" * 105)
    print("BENCHMARK DE OVERHEAD DE RENDIMIENTO -- AUDIT TRACER (HU-6.7)")
    print("=" * 105)

    for r in resultados:
        print(f"\n[>] DATASET: {r['categoria']} ({r['filas']:,} filas) - {r['corridas']} corridas por modo")
        print("-" * 105)
        print(f"{'Operacion':<16}{'Sin Audit (s)':>14}{'Con Audit (s)':>14}{'Overhead (%)':>14}{'Sync Caido (s)':>16}{'Overhead (%)':>14}{'Umbral':>12}")
        print("-" * 105)

        base_ops = r["modos"]["sin_auditoria"]["operaciones"]
        audit_ops = r["modos"]["con_auditoria"]["operaciones"]
        sync_ops = r["modos"]["con_sync_caido"]["operaciones"]

        for op in ("lectura", "transformacion", "exportacion", "cuerpo", "imports", "total", "proceso"):
            b_s = base_ops[op]["promedio_s"]
            a_s = audit_ops[op]["promedio_s"]
            a_oh = audit_ops[op]["overhead_pct"]
            s_s = sync_ops[op]["promedio_s"]
            s_oh = sync_ops[op]["overhead_pct"]

            flag = "[!] SUPERA" if a_oh > umbral_pct else "[OK]"
            op_label = op.capitalize()
            print(f"{op_label:<16}{b_s:>14.4f}{a_s:>14.4f}{a_oh:>13.2f}%{s_s:>16.4f}{s_oh:>13.2f}%{flag:>12}")

    print("\n" + "=" * 105)
    print(f"HALLAZGOS DE OPTIMIZACION FUTURA (CA4 -- Umbral: {umbral_pct}%)")
    print("=" * 105)

    if not hallazgos:
        print("[OK] Ninguna operacion supero el umbral de overhead aceptable.")
    else:
        for idx, h in enumerate(hallazgos, 1):
            if h["modo"] == "con_auditoria":
                print(f"\n[{idx}] {h['categoria']} -- Operacion: {h['operacion'].upper()}")
                print(f"    * Overhead detectado: {h['overhead_pct']}% (Diferencia absoluta: +{h['diferencia_ms']} ms)")
                print(f"    * Causa raiz: {h['causa_raiz']}")
                print(f"    * Recomendacion: {h['recomendacion']}")
    print("-" * 105)


def ejecutar_benchmark(
    tamanos: Optional[List[int]] = None,
    corridas: int = 5,
    umbral_pct: float = UMBRAL_OVERHEAD_ACEPTABLE_DEFECTO,
    salida_json: Optional[str] = None,
) -> dict:
    """Función de entrada programática y reusable para el benchmark completo."""
    if tamanos is None:
        tamanos = list(TAMANOS_ESTANDAR.keys())

    resultados = [medir_tamano(filas, corridas=corridas) for filas in tamanos]
    hallazgos = evaluar_hallazgos(resultados, umbral_pct=umbral_pct)

    informe_completo = {
        "benchmark": "HU-6.7 — Benchmark de overhead de rendimiento",
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "umbral_aceptable_pct": umbral_pct,
        "corridas_por_modo": corridas,
        "tamanos_evaluados": tamanos,
        "resultados": resultados,
        "hallazgos_optimizacion": hallazgos,
    }

    if salida_json:
        carpeta_salida = os.path.dirname(os.path.abspath(salida_json))
        if carpeta_salida and not os.path.exists(carpeta_salida):
            os.makedirs(carpeta_salida, exist_ok=True)
        with open(salida_json, "w", encoding="utf-8") as f:
            json.dump(informe_completo, f, indent=2, ensure_ascii=False)

    return informe_completo


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--filas",
        type=int,
        nargs="+",
        default=list(TAMANOS_ESTANDAR.keys()),
        help="Lista de cantidades de filas a medir (ej. 50000 200000 1000000)",
    )
    parser.add_argument(
        "--corridas",
        type=int,
        default=5,
        help="Número de corridas intercaladas por cada modo",
    )
    parser.add_argument(
        "--umbral-pct",
        type=float,
        default=UMBRAL_OVERHEAD_ACEPTABLE_DEFECTO,
        help="Umbral porcentual de overhead aceptable para CA4 (default: 5.0)",
    )
    parser.add_argument(
        "--salida-json",
        default="benchmarks/resultados_benchmark.json",
        help="Ruta para guardar los resultados detallados en JSON",
    )
    args = parser.parse_args()

    informe = ejecutar_benchmark(
        tamanos=args.filas,
        corridas=args.corridas,
        umbral_pct=args.umbral_pct,
        salida_json=args.salida_json,
    )
    imprimir_tabla_resultados(
        informe["resultados"],
        informe["hallazgos_optimizacion"],
        args.umbral_pct,
    )


if __name__ == "__main__":
    main()
