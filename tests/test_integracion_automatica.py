"""
tests/test_integracion_automatica.py
=====================================
HU-5.1 — Integrar el sistema sin modificar scripts existentes.

  CA1: `import audit_tracer` activa toda la captura; reimportar o recargar
       no vuelve a parchear pandas ni duplica eventos.
  CA2: mismo comportamiento en script .py y en notebook (nbclient).
  CA4: un error interno de la auditoría no interrumpe la operación de
       pandas y queda en el log de errores del sistema, no en audit_log;
       los errores propios del usuario le llegan intactos; la
       sincronización nunca hace red en el hilo del usuario.

  Identificación (opción c acordada para HU-5.1): token cacheado → usuario
  identificado sin red; sin token → DESCONOCIDO + aviso; login() tardío →
  evento ATRIBUCION_SESION (audit_log es inmutable).

Las pruebas de import corren en un proceso Python nuevo: en el proceso de
pytest audit_tracer ya está importado.
"""

import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
import types
from pathlib import Path

import pandas as pd
import pytest
import requests

import audit_tracer  # noqa: F401  (activa los interceptores en este proceso)
from audit_tracer import data_capture, export_capture, failed_access, sync_client, transform_capture
from audit_tracer import device_login as device_login_mod
from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import insert_event_and_enqueue_sync
from audit_tracer.session_tracker import SessionTracker
from audit_tracer.utils.contexto import build_contexto, detect_environment
from audit_tracer.utils.error_log import error_log_path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Flujo de referencia compartido por el script .py y el notebook (CA2).
PASOS = [
    'import pandas as pd\n'
    'pd.DataFrame({"edad": [30, None, 70], "sexo": ["F", "M", None]}).to_csv("base.csv", index=False)',
    'df = pd.read_csv("base.csv")',
    'edades = df["edad"]\nmayores = df.query("edad > 40")',
    'limpio = df.fillna({"edad": 0}).dropna(subset=["sexo"])',
    'limpio.to_csv("salida.csv", index=False)',
    'try:\n    pd.read_csv("no_existe.csv")\nexcept FileNotFoundError:\n    pass',
]


# ──────────────────────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────────────────────

def _env_aislado(home: Path) -> dict:
    env = dict(os.environ)
    env["HOME"] = str(home)
    env["USERPROFILE"] = str(home)
    env.pop("AUDIT_TRACER_API_URL", None)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _correr_python(args, cwd: Path, home: Path, timeout: int = 120) -> subprocess.CompletedProcess:
    resultado = subprocess.run(
        [sys.executable, *args], cwd=cwd, env=_env_aislado(home),
        capture_output=True, text=True, timeout=timeout,
    )
    assert resultado.returncode == 0, resultado.stderr
    return resultado


def _eventos_de(home: Path) -> list:
    conn = sqlite3.connect(home / ".audit_tracer" / "audit_trail.db")
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute("SELECT * FROM audit_log ORDER BY event_id")]
    finally:
        conn.close()


def _carpetas(tmp_path: Path, nombre: str):
    trabajo, home = tmp_path / nombre, tmp_path / f"home_{nombre}"
    trabajo.mkdir()
    home.mkdir()
    return trabajo, home


def _boom(*args, **kwargs):
    raise RuntimeError("fallo interno simulado HU-5.1")


@pytest.fixture
def db(monkeypatch, tmp_path):
    """Base local temporal para todos los interceptores y la sesión."""
    ruta = str(tmp_path / "local.db")

    def factory():
        return get_connection(ruta)

    for modulo in ("data_capture", "transform_capture", "export_capture",
                   "failed_access", "session_tracker"):
        monkeypatch.setattr(f"audit_tracer.{modulo}.get_connection", factory)
    data_capture.activate()
    transform_capture.activate()
    export_capture.activate()
    return factory


@pytest.fixture
def csv_pacientes(tmp_path) -> Path:
    ruta = tmp_path / "pacientes.csv"
    ruta.write_text("id,edad,sexo\n1,30,F\n2,,M\n3,70,\n", encoding="utf-8")
    return ruta


def _filas(factory, where: str = "1=1", params=()) -> list:
    conn = factory()
    conn.row_factory = sqlite3.Row
    try:
        return [dict(r) for r in conn.execute(f"SELECT * FROM audit_log WHERE {where}", params)]
    finally:
        conn.close()


# ──────────────────────────────────────────────────────────────
# CA1 — Una sola línea de import activa toda la captura
# ──────────────────────────────────────────────────────────────

class TestImportActivaTodo:
    def test_import_activa_todos_los_interceptores_sin_llamar_nada_mas(self, tmp_path):
        trabajo, home = _carpetas(tmp_path, "import")
        codigo = (
            "import json, audit_tracer\n"
            "import pandas as pd\n"
            "from audit_tracer import data_capture as d, export_capture as e, transform_capture as t\n"
            "from audit_tracer.session_tracker import SessionTracker\n"
            "print(json.dumps({\n"
            "  'read_csv': pd.read_csv is d._audited_read_csv,\n"
            "  'read_excel': pd.read_excel is d._audited_read_excel,\n"
            "  'merge': pd.merge is t._audited_pd_merge,\n"
            "  'to_csv': pd.DataFrame.to_csv is e._audited_to_csv,\n"
            "  'to_excel': pd.DataFrame.to_excel is e._audited_to_excel,\n"
            "  'to_json': pd.DataFrame.to_json is e._audited_to_json,\n"
            "  'to_parquet': pd.DataFrame.to_parquet is e._audited_to_parquet,\n"
            "  'sesion_activa': SessionTracker.get_instance()._active,\n"
            "}))\n"
        )
        salida = _correr_python(["-c", codigo], trabajo, home)
        estado = json.loads(salida.stdout.strip().splitlines()[-1])
        assert all(estado.values()), estado

    def test_flujo_sin_wraps_registra_todos_los_tipos_de_evento(self, tmp_path):
        trabajo, home = _carpetas(tmp_path, "flujo")
        _correr_python(["-c", "import audit_tracer\n" + "\n".join(PASOS)], trabajo, home)

        tipos = {e["tipo_accion"] for e in _eventos_de(home)}
        assert {"INICIO_SESION", "CARGA", "CONSULTA", "TRANSFORMACION",
                "EXPORTACION", "ACCESO_FALLIDO", "CIERRE_SESION"} <= tipos

    def test_read_csv_devuelve_frame_auditado_con_nombre_que_se_propaga(self, db, csv_pacientes, tmp_path):
        df = pd.read_csv(csv_pacientes)
        assert isinstance(df, data_capture.AuditedFrame)

        derivado = df.fillna({"edad": 0}).query("edad >= 0")
        derivado.to_csv(tmp_path / "derivado.csv", index=False)

        exportacion = _filas(db, "tipo_accion = 'EXPORTACION'")[-1]
        assert exportacion["dataset_nombre"] == "pacientes.csv"

    def test_importar_y_recargar_no_duplica_parches_ni_eventos(self, tmp_path):
        trabajo, home = _carpetas(tmp_path, "reimport")
        codigo = (
            "import importlib, json\n"
            "import audit_tracer\n"
            "import audit_tracer\n"
            "importlib.reload(audit_tracer)\n"
            "from audit_tracer import data_capture, export_capture, transform_capture\n"
            "importlib.reload(data_capture)\n"
            "importlib.reload(transform_capture)\n"
            "importlib.reload(export_capture)\n"
            "importlib.reload(audit_tracer)\n"
            "import pandas as pd\n"
            "pd.DataFrame({'a': [1, 2]}).to_csv('x.csv', index=False)\n"
            "df = pd.read_csv('x.csv')\n"
            "pd.merge(df, df, on='a')\n"
            "orig = pd.read_csv._audit_tracer_original\n"
            "print(json.dumps({\n"
            "  'read_csv_un_solo_parche': not hasattr(orig, '_audit_tracer_original'),\n"
            "  'original_es_de_pandas': orig.__module__.startswith('pandas'),\n"
            "  'to_csv_un_solo_parche': not hasattr(pd.DataFrame.to_csv._audit_tracer_original, '_audit_tracer_original'),\n"
            "  'merge_un_solo_parche': not hasattr(pd.merge._audit_tracer_original, '_audit_tracer_original'),\n"
            "}))\n"
        )
        salida = _correr_python(["-c", codigo], trabajo, home)
        estado = json.loads(salida.stdout.strip().splitlines()[-1])
        assert all(estado.values()), estado

        conteo = {}
        for e in _eventos_de(home):
            conteo[e["tipo_accion"]] = conteo.get(e["tipo_accion"], 0) + 1
        assert conteo["INICIO_SESION"] == 1
        assert conteo["CARGA"] == 1
        assert conteo["EXPORTACION"] == 1
        assert conteo["TRANSFORMACION"] == 1

    def test_import_funciona_desde_cualquier_directorio(self, tmp_path):
        """CA2: el schema y la base local no dependen del directorio de trabajo."""
        trabajo, home = _carpetas(tmp_path, "otro_directorio")
        salida = _correr_python(["-c", "import audit_tracer"], trabajo, home)
        assert "Schema file not found" not in salida.stderr
        assert [e["tipo_accion"] for e in _eventos_de(home)][0] == "INICIO_SESION"
        assert not (trabajo / "audit_trail.db").exists()


# ──────────────────────────────────────────────────────────────
# CA4 — Errores internos aislados; errores del usuario intactos
# ──────────────────────────────────────────────────────────────

class TestAislamientoDeErrores:
    def test_error_interno_no_interrumpe_pandas_y_va_al_log_de_errores(
        self, db, csv_pacientes, tmp_path, monkeypatch, capsys
    ):
        monkeypatch.setattr(data_capture, "insert_event_and_enqueue_sync", _boom)
        monkeypatch.setattr(transform_capture, "build_contexto", _boom)
        monkeypatch.setattr(export_capture, "_resolve_export_path", _boom)

        df = pd.read_csv(csv_pacientes)
        esperado = data_capture._original_read_csv(csv_pacientes)
        pd.testing.assert_frame_equal(pd.DataFrame(df), esperado)

        rellenado = df.fillna({"edad": 0})
        assert rellenado["edad"].tolist() == [30.0, 0.0, 70.0]

        destino = tmp_path / "salida.csv"
        rellenado.to_csv(destino, index=False)
        assert destino.exists()

        log = Path(error_log_path()).read_text(encoding="utf-8")
        assert "fallo interno simulado HU-5.1" in log
        assert "fallo interno simulado" not in capsys.readouterr().out

        assert _filas(db, "tipo_accion = 'CARGA'") == []
        assert _filas(
            db, "motivo_fallo LIKE ? OR contexto_ejecucion LIKE ? OR motivo_alerta LIKE ?",
            ("%fallo interno%",) * 3,
        ) == []

    def test_error_interno_en_consulta_no_cambia_el_resultado(self, db, csv_pacientes, monkeypatch):
        df = pd.read_csv(csv_pacientes)
        monkeypatch.setattr(data_capture, "_log_event", _boom)
        assert df["edad"].tolist()[0] == 30.0
        assert len(df.query("edad > 40")) == 1

    def test_archivo_inexistente_llega_igual_que_sin_la_libreria(self, db, tmp_path):
        ruta = tmp_path / "no_existe.csv"
        with pytest.raises(FileNotFoundError) as con_libreria:
            pd.read_csv(ruta)
        with pytest.raises(FileNotFoundError) as sin_libreria:
            data_capture._original_read_csv(ruta)

        assert type(con_libreria.value) is type(sin_libreria.value)
        assert str(con_libreria.value) == str(sin_libreria.value)
        assert con_libreria.value.errno == sin_libreria.value.errno

        # HU-2.4: el intento fallido se sigue registrando.
        fallidos = _filas(db, "tipo_accion = 'ACCESO_FALLIDO' AND dataset_nombre = 'no_existe.csv'")
        assert len(fallidos) == 1

    def test_error_del_usuario_llega_intacto_aunque_la_auditoria_falle(self, db, tmp_path, monkeypatch):
        monkeypatch.setattr(failed_access, "insert_event_and_enqueue_sync", _boom)
        monkeypatch.setattr(data_capture, "log_failed_access", _boom)
        with pytest.raises(FileNotFoundError):
            pd.read_csv(tmp_path / "no_existe.csv")

    def test_columna_inexistente_lanza_keyerror_normal(self, db, csv_pacientes):
        df = pd.read_csv(csv_pacientes)
        with pytest.raises(KeyError):
            df["columna_que_no_existe"]

    def test_firmas_de_pandas_se_respetan(self, db, csv_pacientes):
        df = pd.read_csv(csv_pacientes)

        sin_nulos = df.dropna(subset=["sexo"], ignore_index=True)
        assert list(sin_nulos.index) == [0, 1]

        copia = df.copy()
        resultado = copia.fillna({"edad": 0}, inplace=True)
        esperado = pd.DataFrame(df.copy()).fillna({"edad": 0}, inplace=True)
        assert (resultado is None) == (esperado is None)   # pandas 2: None; pandas 3: el propio df
        assert copia["edad"].isna().sum() == 0

        mayus = df.rename(str.upper, axis="columns")
        assert list(mayus.columns) == ["ID", "EDAD", "SEXO"]

        sumado = df[["edad"]].apply(lambda c, extra: c + extra, args=(1,))
        assert sumado["edad"].tolist()[0] == 31.0

    def test_sincronizacion_nunca_hace_red_en_el_hilo_del_usuario(
        self, db, csv_pacientes, tmp_path, monkeypatch
    ):
        hilos = []

        def servidor_lento(*args, **kwargs):
            hilos.append(threading.current_thread().name)
            time.sleep(2)
            raise requests.exceptions.ConnectionError("servidor caído")

        monkeypatch.setattr(sync_client.requests, "post", servidor_lento)
        sync_client.configure_sync("https://central.example.org", "tk-prueba")
        try:
            inicio = time.perf_counter()
            df = pd.read_csv(csv_pacientes)
            df["edad"]
            df.fillna(0).to_csv(tmp_path / "salida.csv", index=False)
            transcurrido = time.perf_counter() - inicio
        finally:
            sync_client.stop_background_sync()
            sync_client.unconfigure_sync()
            sync_client._estado["servidor_caido"] = False

        assert transcurrido < 1.0, f"Las operaciones tardaron {transcurrido:.2f}s con el servidor caído"
        assert threading.main_thread().name not in hilos

    def test_desactivar_la_captura_queda_registrado_como_critico(self, db):
        export_capture.deactivate()
        try:
            filas = _filas(db, "tipo_accion = 'AUDITORIA_DESACTIVADA'")
        finally:
            export_capture.activate()
        assert len(filas) == 1
        assert filas[0]["nivel_alerta"] == "CRITICO"
        assert "export_capture" in filas[0]["motivo_alerta"]


# ──────────────────────────────────────────────────────────────
# Identificación del usuario (opción c)
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def home(monkeypatch, tmp_path):
    carpeta = tmp_path / "home"
    carpeta.mkdir()
    monkeypatch.setenv("HOME", str(carpeta))
    monkeypatch.setenv("USERPROFILE", str(carpeta))
    monkeypatch.delenv("AUDIT_TRACER_API_URL", raising=False)
    monkeypatch.setattr(SessionTracker, "_install_signal_handlers", lambda self: None)
    return carpeta


def _escribir_cache(home: Path, datos: dict) -> Path:
    ruta = home / ".audit_tracer" / "token_cache.json"
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_text(json.dumps(datos), encoding="utf-8")
    return ruta


class TestIdentificacion:
    def test_token_cacheado_identifica_sin_red(self, home, monkeypatch):
        _escribir_cache(home, {"token": "tk-1", "usuario_id": "u-123",
                               "api_url": "https://central.example.org"})
        configuraciones = []
        monkeypatch.setattr(sync_client, "configure_sync",
                            lambda url, token, auto=True: configuraciones.append((url, token)))
        monkeypatch.setattr(SessionTracker, "_validar_identidad_cacheada", lambda self, u, t: None)

        tracker = SessionTracker()
        assert tracker.identify_from_cache() is True
        assert tracker.usuario_id == "u-123"
        assert configuraciones == [("https://central.example.org", "tk-1")]

    def test_sin_token_cacheado_queda_desconocido(self, home):
        tracker = SessionTracker()
        assert tracker.identify_from_cache() is False
        assert tracker.usuario_id == "DESCONOCIDO"

    def test_cache_anterior_sin_api_url_usa_variable_de_entorno(self, home, monkeypatch):
        _escribir_cache(home, {"token": "tk-1", "usuario_id": "u-123"})
        assert device_login_mod.load_cached_identity() is None

        monkeypatch.setenv("AUDIT_TRACER_API_URL", "https://central.example.org/")
        identidad = device_login_mod.load_cached_identity()
        assert identidad["api_url"] == "https://central.example.org"

    def test_token_rechazado_por_el_servidor_vuelve_a_desconocido(self, home, monkeypatch):
        cache = _escribir_cache(home, {"token": "tk-1", "usuario_id": "u-123",
                                       "api_url": "https://central.example.org"})
        monkeypatch.setattr(device_login_mod, "token_status", lambda url, token: "INVALIDO")
        desconfigurado = []
        monkeypatch.setattr(sync_client, "unconfigure_sync", lambda: desconfigurado.append(True))

        tracker = SessionTracker()
        tracker.usuario_id = "u-123"
        tracker._validar_identidad_cacheada("https://central.example.org", "tk-1")

        assert tracker.usuario_id == "DESCONOCIDO"
        assert desconfigurado == [True]
        assert not cache.exists()

    def test_sin_conexion_conserva_la_identidad_cacheada(self, home, monkeypatch):
        monkeypatch.setattr(device_login_mod, "token_status", lambda url, token: "SIN_CONEXION")
        tracker = SessionTracker()
        tracker.usuario_id = "u-123"
        tracker._validar_identidad_cacheada("https://central.example.org", "tk-1")
        assert tracker.usuario_id == "u-123"

    def test_import_con_token_cacheado_atribuye_inicio_de_sesion(self, tmp_path):
        trabajo, home_proc = _carpetas(tmp_path, "cache")
        _escribir_cache(home_proc, {"token": "tk-1", "usuario_id": "u-123",
                                    "api_url": "http://127.0.0.1:9"})   # servidor inalcanzable
        salida = _correr_python(["-c", "import audit_tracer"], trabajo, home_proc)

        inicio = _eventos_de(home_proc)[0]
        assert inicio["tipo_accion"] == "INICIO_SESION"
        assert inicio["usuario_id"] == "u-123"
        assert "no hay un usuario identificado" not in salida.stderr

    def test_import_sin_token_avisa_y_sigue_capturando(self, tmp_path):
        trabajo, home_proc = _carpetas(tmp_path, "sin_cache")
        salida = _correr_python(["-c", "import audit_tracer"], trabajo, home_proc)
        assert "audit_tracer.login(" in salida.stderr
        assert _eventos_de(home_proc)[0]["usuario_id"] == "DESCONOCIDO"

    def test_login_tardio_registra_atribucion_sin_modificar_eventos(self, db, home, monkeypatch):
        tracker = SessionTracker()
        conn = db()
        for tipo in ("CARGA", "CONSULTA"):
            insert_event_and_enqueue_sync(conn, {
                "usuario_id": "DESCONOCIDO", "sesion_id": tracker.sesion_id,
                "tipo_accion": tipo, "dataset_nombre": "pacientes.csv",
            })
        conn.close()
        monkeypatch.setattr("audit_tracer.session_tracker._auth_login",
                            lambda conn, email, password, sesion_id: {"success": True, "usuario_id": "u-9"})

        assert tracker.login("ana@audit.com", "x")["success"] is True

        atribucion = _filas(db, "tipo_accion = 'ATRIBUCION_SESION'")
        assert len(atribucion) == 1
        assert atribucion[0]["usuario_id"] == "u-9"
        assert atribucion[0]["sesion_id"] == tracker.sesion_id
        assert "2 evento(s)" in atribucion[0]["contexto_ejecucion"]
        assert len(_filas(db, "usuario_id = 'DESCONOCIDO'")) == 2

    def test_login_sin_eventos_previos_no_registra_atribucion(self, db, home, monkeypatch):
        tracker = SessionTracker()
        monkeypatch.setattr("audit_tracer.session_tracker._auth_login",
                            lambda conn, email, password, sesion_id: {"success": True, "usuario_id": "u-9"})
        tracker.login("ana@audit.com", "x")
        assert _filas(db, "tipo_accion = 'ATRIBUCION_SESION'") == []


# ──────────────────────────────────────────────────────────────
# CA2 — Contexto de ejecución y compatibilidad de entornos
# ──────────────────────────────────────────────────────────────

class TestEntornos:
    def test_detecta_google_colab(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "google.colab", types.ModuleType("google.colab"))
        assert detect_environment() == "Google Colab"

    def test_contexto_en_script_usa_el_archivo_del_usuario(self):
        assert build_contexto().startswith(f"Script: {Path(__file__).name} |")

    def test_crear_la_sesion_fuera_del_hilo_principal_no_falla(self):
        errores = []

        def crear():
            try:
                SessionTracker()
            except Exception as exc:   # pragma: no cover - es lo que se verifica
                errores.append(exc)

        hilo = threading.Thread(target=crear)
        hilo.start()
        hilo.join()
        assert errores == []

    def test_notebook_y_script_generan_los_mismos_eventos(self, tmp_path, monkeypatch):
        nbformat = pytest.importorskip("nbformat")
        nbclient = pytest.importorskip("nbclient")
        pytest.importorskip("ipykernel")

        trabajo_s, home_s = _carpetas(tmp_path, "script")
        script = trabajo_s / "flujo_referencia.py"
        script.write_text("import audit_tracer\n" + "\n".join(PASOS) + "\n", encoding="utf-8")
        _correr_python([script.name], trabajo_s, home_s)

        trabajo_n, home_n = _carpetas(tmp_path, "notebook")
        for clave, valor in _env_aislado(home_n).items():
            monkeypatch.setenv(clave, valor)
        celdas = [nbformat.v4.new_code_cell("import audit_tracer")]
        celdas += [nbformat.v4.new_code_cell(paso) for paso in PASOS]
        nb = nbformat.v4.new_notebook(cells=celdas)
        nbclient.NotebookClient(
            nb, timeout=180, kernel_name="python3",
            resources={"metadata": {"path": str(trabajo_n)}},
        ).execute()

        def datos(eventos):
            return [(e["tipo_accion"], e["dataset_nombre"], e["motivo_fallo"], e["usuario_id"])
                    for e in eventos if e["tipo_accion"] not in ("INICIO_SESION", "CIERRE_SESION")]

        eventos_s, eventos_n = _eventos_de(home_s), _eventos_de(home_n)
        assert datos(eventos_s) == datos(eventos_n)
        assert eventos_n[0]["tipo_accion"] == "INICIO_SESION"

        carga_s = next(e for e in eventos_s if e["tipo_accion"] == "CARGA")
        carga_n = next(e for e in eventos_n if e["tipo_accion"] == "CARGA")
        assert carga_s["contexto_ejecucion"].startswith("Script: flujo_referencia.py | Env: Script (.py)")
        assert "[celda " in carga_n["contexto_ejecucion"]
        assert "Env: Jupyter" in carga_n["contexto_ejecucion"]
