"""
benchmarks/overhead_referencia.py
==================================
HU-5.1 CA3 — Overhead de `import audit_tracer` sobre un script de
referencia: cargar, transformar y exportar un dataset de tamaño medio.

Cada corrida es un proceso Python nuevo (como un script real), con el
mismo flujo de trabajo y una sola diferencia: la línea `import audit_tracer`
al inicio. Se mide el tiempo total dentro del proceso, desde antes de los
imports hasta el final del script, y se reporta el promedio de N corridas
y el porcentaje de overhead.

Modos:
  sin_auditoria  — el script tal cual.
  con_auditoria  — `import audit_tracer` como primera línea (sin servidor
                   central configurado: solo captura local).
  con_sync_caido — además configura la sincronización contra un servidor
                   que no responde, para comprobar que el envío no frena
                   el script (HU-5.1 CA4).

Reutilizable para el benchmark formal de HU-6.7 (varios tamaños):

    python benchmarks/overhead_referencia.py --filas 50000 200000 1000000 \
        --corridas 7 --salida-json resultados.json
"""

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time

import numpy as np
import pandas as pd

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FLUJO = '''
pacientes = pd.read_csv("pacientes.csv")
diagnosticos = pd.read_csv("diagnosticos.csv")

edades = pacientes["edad"]
adultos = pacientes.query("edad >= 18")
adultos = adultos.fillna({"glucosa": adultos["glucosa"].median(), "presion": 120})
adultos = adultos.dropna(subset=["sexo"])
adultos = adultos.rename(columns={"presion": "presion_sistolica"})
adultos = adultos.drop(columns=["notas"])
escaladas = adultos[["glucosa", "imc"]].apply(lambda c: (c - c.min()) / (c.max() - c.min()))
completo = adultos.merge(diagnosticos, on="diagnostico_id", how="left")
resumen = completo.groupby("categoria")["glucosa"].mean()

completo.to_csv("salida_completa.csv", index=False)
resumen.to_frame().to_csv("salida_resumen.csv")
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
print(json.dumps({{"total": _t2 - _t0, "imports": _t1 - _t0, "cuerpo": _t2 - _t1}}))
'''

MODOS = {
    "sin_auditoria": ("", ""),
    "con_auditoria": ("import audit_tracer", ""),
    "con_sync_caido": (
        "import audit_tracer",
        'audit_tracer.configure_sync("http://127.0.0.1:9", "token-de-prueba")',
    ),
}


def generar_datos(carpeta: str, filas: int, semilla: int = 7) -> None:
    """Dataset sintético (no son datos reales) con nulos, como uno clínico."""
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


def correr(modo: str, carpeta: str, home: str) -> dict:
    import_auditoria, config_sync = MODOS[modo]
    codigo = PLANTILLA.format(import_auditoria=import_auditoria,
                              config_sync=config_sync, flujo=FLUJO)
    env = dict(os.environ)
    env["HOME"] = home
    env["USERPROFILE"] = home
    env.pop("AUDIT_TRACER_API_URL", None)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    inicio = time.perf_counter()
    salida = subprocess.run(
        [sys.executable, "-c", codigo], cwd=carpeta, env=env,
        capture_output=True, text=True, check=True,
    )
    tiempos = json.loads(salida.stdout.strip().splitlines()[-1])
    # Proceso completo: arranque del intérprete + script + cierre (atexit).
    tiempos["proceso"] = time.perf_counter() - inicio
    return tiempos


def medir(filas: int, corridas: int) -> dict:
    with tempfile.TemporaryDirectory(prefix="audit_bench_") as carpeta:
        generar_datos(carpeta, filas)
        homes = {modo: os.path.join(carpeta, f"home_{modo}") for modo in MODOS}
        for home in homes.values():
            os.makedirs(home)

        # Corrida de calentamiento por modo (caché de disco; base local y
        # llaves ya creadas, como en el uso real) — no se cuenta.
        for modo in MODOS:
            correr(modo, carpeta, homes[modo])

        tiempos = {modo: [] for modo in MODOS}
        for _ in range(corridas):
            for modo in MODOS:   # intercalados para no sesgar por deriva térmica
                tiempos[modo].append(correr(modo, carpeta, homes[modo]))

    base = statistics.mean(t["total"] for t in tiempos["sin_auditoria"])
    base_mediana = statistics.median(t["total"] for t in tiempos["sin_auditoria"])
    base_proceso = statistics.mean(t["proceso"] for t in tiempos["sin_auditoria"])
    resultado = {"filas": filas, "corridas": corridas, "modos": {}}
    for modo, ts in tiempos.items():
        total = [t["total"] for t in ts]
        promedio = statistics.mean(total)
        mediana = statistics.median(total)
        proceso = statistics.mean(t["proceso"] for t in ts)
        resultado["modos"][modo] = {
            "promedio_s": promedio,
            "mediana_s": mediana,
            "desv_std_s": statistics.stdev(total) if len(total) > 1 else 0.0,
            "imports_promedio_s": statistics.mean(t["imports"] for t in ts),
            "cuerpo_promedio_s": statistics.mean(t["cuerpo"] for t in ts),
            "overhead_pct": (promedio - base) / base * 100,
            "overhead_mediana_pct": (mediana - base_mediana) / base_mediana * 100,
            "proceso_promedio_s": proceso,
            "overhead_proceso_pct": (proceso - base_proceso) / base_proceso * 100,
            "corridas_s": total,
        }
    return resultado


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--filas", type=int, nargs="+", default=[200_000])
    parser.add_argument("--corridas", type=int, default=5)
    parser.add_argument("--salida-json", help="Guarda los resultados crudos en este archivo")
    args = parser.parse_args()

    resultados = [medir(filas, args.corridas) for filas in args.filas]
    for r in resultados:
        print(f"\nDataset: {r['filas']:,} filas · {r['corridas']} corridas por modo")
        print(f"{'modo':<16}{'promedio (s)':>13}{'desv. (s)':>11}{'overhead':>10}"
              f"{'mediana (s)':>13}{'overhead':>10}{'imports (s)':>13}{'cuerpo (s)':>12}"
              f"{'proceso (s)':>13}{'overhead':>10}")
        for modo, m in r["modos"].items():
            print(f"{modo:<16}{m['promedio_s']:>13.3f}{m['desv_std_s']:>11.3f}"
                  f"{m['overhead_pct']:>9.1f}%{m['mediana_s']:>13.3f}"
                  f"{m['overhead_mediana_pct']:>9.1f}%{m['imports_promedio_s']:>13.3f}"
                  f"{m['cuerpo_promedio_s']:>12.3f}{m['proceso_promedio_s']:>13.3f}"
                  f"{m['overhead_proceso_pct']:>9.1f}%")

    if args.salida_json:
        with open(args.salida_json, "w", encoding="utf-8") as f:
            json.dump(resultados, f, indent=2)


if __name__ == "__main__":
    main()
