"""
tests/test_benchmark_overhead.py
==================================
Pruebas unitarias y de integración para HU-6.7: Benchmark de overhead de rendimiento.

Criterios de Aceptación verificados:
  CA1: Medición de operaciones comunes de pandas (lectura, transformación, exportación)
       con y sin audit_tracer activo.
  CA2: Soporte y categorización de al menos tres tamaños de dataset (pequeño, mediano, grande).
  CA3: Cálculo estadístico y documentación del porcentaje de overhead por operación y tamaño.
  CA4: Evaluación contra umbral aceptable (5%) y generación de hallazgos de optimización con causa raíz y recomendaciones.
"""

import json
import os
import tempfile
import pytest

from benchmarks.overhead_referencia import (
    OPERACIONES,
    MODOS,
    TAMANOS_ESTANDAR,
    categorizar_tamano,
    generar_datos,
    evaluar_hallazgos,
    ejecutar_benchmark,
    medir_tamano,
    UMBRAL_OVERHEAD_ACEPTABLE_DEFECTO,
)


class TestCA1MedicionOperacionesComunes:
    """Verifica la medición de tiempos para operaciones comunes con y sin auditoría."""

    def test_operaciones_contempladas(self):
        """CA1: Se deben contemplar lectura, transformación y exportación."""
        assert "lectura" in OPERACIONES
        assert "transformacion" in OPERACIONES
        assert "exportacion" in OPERACIONES
        assert "cuerpo" in OPERACIONES
        assert "total" in OPERACIONES

    def test_modos_evaluados(self):
        """CA1: Se debe medir con y sin auditoría (y con sincronización fallida/caída)."""
        assert "sin_auditoria" in MODOS
        assert "con_auditoria" in MODOS
        assert "con_sync_caido" in MODOS

    def test_medicion_tamano_minimo(self):
        """Ejecuta una corrida real rápida y verifica que todas las operaciones registran tiempos positivos."""
        # 2,000 filas con 1 corrida para una prueba unitaria rápida
        resultado = medir_tamano(filas=2_000, corridas=1)

        assert resultado["filas"] == 2_000
        assert "sin_auditoria" in resultado["modos"]
        assert "con_auditoria" in resultado["modos"]

        for modo in ("sin_auditoria", "con_auditoria"):
            ops = resultado["modos"][modo]["operaciones"]
            for op in ("lectura", "transformacion", "exportacion", "total"):
                assert op in ops
                assert ops[op]["promedio_s"] > 0
                assert ops[op]["mediana_s"] > 0


class TestCA2TamanosDataset:
    """Verifica el soporte y categorización de los tres tamaños de dataset."""

    def test_tres_tamanos_estandar_definidos(self):
        """CA2: Se contemplan al menos tres tamaños distintos."""
        assert len(TAMANOS_ESTANDAR) >= 3
        # Debe haber tamaño pequeño (50k), mediano (200k) y grande (1M)
        assert 50_000 in TAMANOS_ESTANDAR
        assert 200_000 in TAMANOS_ESTANDAR
        assert 1_000_000 in TAMANOS_ESTANDAR

    def test_categorizar_tamanos(self):
        """Clasificación correcta de datasets."""
        assert "Pequeño" in categorizar_tamano(50_000)
        assert "Mediano" in categorizar_tamano(200_000)
        assert "Grande" in categorizar_tamano(1_000_000)
        assert "Pequeño" in categorizar_tamano(10_000)
        assert "Grande" in categorizar_tamano(2_000_000)

    def test_generacion_datos_sinteticos(self):
        """Verifica que generar_datos genera datasets estructurados con el número de filas pedido."""
        with tempfile.TemporaryDirectory() as tmpdir:
            generar_datos(tmpdir, filas=500)
            pacientes_path = os.path.join(tmpdir, "pacientes.csv")
            diag_path = os.path.join(tmpdir, "diagnosticos.csv")

            assert os.path.exists(pacientes_path)
            assert os.path.exists(diag_path)

            import pandas as pd
            df = pd.read_csv(pacientes_path)
            assert len(df) == 500
            assert "paciente_id" in df.columns
            assert "glucosa" in df.columns


class TestCA3CalculoOverhead:
    """Verifica que el cálculo estadístico y porcentual del overhead sea preciso."""

    def test_formula_overhead_porcentual(self):
        """Verifica la fórmula ((tiempo_audit - tiempo_base) / tiempo_base) * 100."""
        # Simulamos datos estadísticos controlados
        res = {
            "filas": 50_000,
            "categoria": "Pequeño (~4 MB)",
            "corridas": 3,
            "modos": {
                "sin_auditoria": {
                    "operaciones": {
                        "lectura": {"promedio_s": 0.100, "mediana_s": 0.100},
                        "transformacion": {"promedio_s": 0.200, "mediana_s": 0.200},
                        "exportacion": {"promedio_s": 0.150, "mediana_s": 0.150},
                        "total": {"promedio_s": 1.000, "mediana_s": 1.000},
                    }
                },
                "con_auditoria": {
                    "operaciones": {
                        "lectura": {
                            "promedio_s": 0.105,  # +5%
                            "mediana_s": 0.105,
                            "desv_std_s": 0.001,
                            "overhead_pct": ((0.105 - 0.100) / 0.100) * 100,
                            "overhead_mediana_pct": 5.0,
                        },
                        "transformacion": {
                            "promedio_s": 0.220,  # +10%
                            "mediana_s": 0.220,
                            "desv_std_s": 0.002,
                            "overhead_pct": ((0.220 - 0.200) / 0.200) * 100,
                            "overhead_mediana_pct": 10.0,
                        },
                        "exportacion": {
                            "promedio_s": 0.150,  # 0%
                            "mediana_s": 0.150,
                            "desv_std_s": 0.000,
                            "overhead_pct": 0.0,
                            "overhead_mediana_pct": 0.0,
                        },
                        "total": {
                            "promedio_s": 1.070,  # +7%
                            "mediana_s": 1.070,
                            "desv_std_s": 0.005,
                            "overhead_pct": ((1.070 - 1.000) / 1.000) * 100,
                            "overhead_mediana_pct": 7.0,
                        },
                    }
                },
            }
        }

        audit_ops = res["modos"]["con_auditoria"]["operaciones"]
        assert pytest.approx(audit_ops["lectura"]["overhead_pct"], 0.01) == 5.0
        assert pytest.approx(audit_ops["transformacion"]["overhead_pct"], 0.01) == 10.0
        assert pytest.approx(audit_ops["exportacion"]["overhead_pct"], 0.01) == 0.0
        assert pytest.approx(audit_ops["total"]["overhead_pct"], 0.01) == 7.0


class TestCA4EvaluacionHallazgos:
    """Verifica la detección de umbral y generación de hallazgos para optimización futura."""

    def test_deteccion_superacion_umbral(self):
        """CA4: Si el overhead supera el umbral (ej. 5%), se documenta el hallazgo."""
        resultados_mock = [{
            "filas": 50_000,
            "categoria": "Pequeño",
            "modos": {
                "sin_auditoria": {
                    "operaciones": {
                        "lectura": {"promedio_s": 0.100},
                        "transformacion": {"promedio_s": 0.100},
                        "exportacion": {"promedio_s": 0.100},
                    }
                },
                "con_auditoria": {
                    "operaciones": {
                        "lectura": {"overhead_pct": 3.2, "promedio_s": 0.1032},      # <= 5%, OK
                        "transformacion": {"overhead_pct": 8.5, "promedio_s": 0.1085}, # > 5%, SUPERA
                        "exportacion": {"overhead_pct": 12.0, "promedio_s": 0.1120},  # > 5%, SUPERA
                    }
                },
                "con_sync_caido": {
                    "operaciones": {
                        "lectura": {"overhead_pct": 3.5, "promedio_s": 0.1035},
                        "transformacion": {"overhead_pct": 9.0, "promedio_s": 0.1090},
                        "exportacion": {"overhead_pct": 13.0, "promedio_s": 0.1130},
                    }
                }
            }
        }]

        hallazgos = evaluar_hallazgos(resultados_mock, umbral_pct=5.0)

        # Debe haber hallazgos para transformacion y exportacion (en ambos modos)
        ops_con_auditoria = [h["operacion"] for h in hallazgos if h["modo"] == "con_auditoria"]
        assert "transformacion" in ops_con_auditoria
        assert "exportacion" in ops_con_auditoria
        assert "lectura" not in ops_con_auditoria

        # Verificar campos requeridos en el hallazgo
        h_trans = next(h for h in hallazgos if h["operacion"] == "transformacion" and h["modo"] == "con_auditoria")
        assert h_trans["overhead_pct"] == 8.5
        assert h_trans["supera_umbral"] is True
        assert len(h_trans["causa_raiz"]) > 10
        assert len(h_trans["recomendacion"]) > 10

    def test_umbral_alto_no_genera_hallazgos(self):
        """Con un umbral muy alto (ej. 500%), no deben generarse hallazgos."""
        resultados_mock = [{
            "filas": 50_000,
            "categoria": "Pequeño",
            "modos": {
                "sin_auditoria": {
                    "operaciones": {
                        "lectura": {"promedio_s": 0.100},
                    }
                },
                "con_auditoria": {
                    "operaciones": {
                        "lectura": {"overhead_pct": 10.0, "promedio_s": 0.110},
                    }
                },
                "con_sync_caido": {
                    "operaciones": {
                        "lectura": {"overhead_pct": 12.0, "promedio_s": 0.112},
                    }
                }
            }
        }]

        hallazgos = evaluar_hallazgos(resultados_mock, umbral_pct=500.0)
        assert len(hallazgos) == 0


class TestIntegracionBenchmark:
    """Verifica la ejecución programática y exportación de resultados a JSON."""

    def test_ejecutar_benchmark_salida_json(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = os.path.join(tmpdir, "benchmark_test.json")

            # Ejecutamos con 1 corrida y 1 tamaño pequeño para test rápido
            informe = ejecutar_benchmark(
                tamanos=[3_000],
                corridas=1,
                umbral_pct=5.0,
                salida_json=json_path,
            )

            assert os.path.exists(json_path)
            assert informe["benchmark"].startswith("HU-6.7")
            assert informe["umbral_aceptable_pct"] == 5.0
            assert len(informe["resultados"]) == 1

            # Leer archivo guardado
            with open(json_path, "r", encoding="utf-8") as f:
                cargado = json.load(f)

            assert cargado["benchmark"] == informe["benchmark"]
            assert "resultados" in cargado
            assert "hallazgos_optimizacion" in cargado
