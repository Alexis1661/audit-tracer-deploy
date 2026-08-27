"""
tests/test_central_db.py
=========================
Pruebas unitarias — HU-5.4: Base de datos central consolidada

Cubre:
  CA1: Esquema central compatible con los campos del audit_log local,
       más evento_uuid para idempotencia futura (HU-5.8) y capacidad de
       escribir en local + central sin duplicar el cálculo de hash.
  CA2: Escrituras concurrentes de múltiples usuarios sin bloquear ni
       perder eventos (WAL + busy_timeout).
  CA3: Mismos mecanismos de inmutabilidad que el local — hash por
       registro (ya cubierto en test_audit_log.py) y triggers que
       bloquean UPDATE/DELETE. Esto último cierra un faltante real de
       HU-3.3: esa HU sí se implementó (rama feature/HU-3.3-Juan-Pablo),
       pero nunca se mergeó a main, así que hasta esta HU no existía en
       ninguna base — ni local ni central. Ver README.md.
  CA4: cubierto en test_detalle_evento.py — verifica que el dashboard
       lee de la base central, no de la local.
"""

import sqlite3
import threading
import uuid

import pytest

from audit_tracer.db import get_connection, get_central_connection
from audit_tracer.models.audit_log import (
    insert_event,
    insert_event_dual,
    get_events,
    verify_integrity,
)


# ──────────────────────────────────────────────────────────────
# FIXTURES
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def central_conn(tmp_path):
    """Conexión a una base central aislada por test."""
    conn = get_central_connection(str(tmp_path / "audit_central_test.db"))
    yield conn
    conn.close()


@pytest.fixture
def local_conn(tmp_path):
    """Conexión a una base local aislada por test."""
    conn = get_connection(str(tmp_path / "audit_trail_test.db"))
    yield conn
    conn.close()


@pytest.fixture(params=["local", "central"])
def any_conn(request, tmp_path):
    """
    Parametriza sobre ambas conexiones: los mecanismos de inmutabilidad
    (CA3) deben comportarse exactamente igual en las dos bases.
    """
    if request.param == "local":
        conn = get_connection(str(tmp_path / "local.db"))
    else:
        conn = get_central_connection(str(tmp_path / "central.db"))
    yield conn
    conn.close()


# ──────────────────────────────────────────────────────────────
# CA1: Esquema central
# ──────────────────────────────────────────────────────────────

class TestEsquemaCentral:
    def test_incluye_las_columnas_del_audit_log_local(self, central_conn):
        columnas = {row[1] for row in central_conn.execute("PRAGMA table_info(audit_log)")}
        columnas_locales = {
            'event_id', 'usuario_id', 'sesion_id', 'timestamp', 'tipo_accion',
            'dataset_nombre', 'columnas_afectadas', 'ruta_destino',
            'filas_exportadas', 'sobrescritura', 'contexto_ejecucion',
            'motivo_fallo', 'nivel_alerta', 'motivo_alerta', 'hash_integridad',
        }
        assert columnas_locales <= columnas

    def test_incluye_evento_uuid_para_idempotencia_futura(self, central_conn):
        columnas = {row[1] for row in central_conn.execute("PRAGMA table_info(audit_log)")}
        assert 'evento_uuid' in columnas

    def test_evento_uuid_es_unico(self, central_conn):
        u = str(uuid.uuid4())
        insert_event(central_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'evento_uuid': u,
        })
        with pytest.raises(sqlite3.IntegrityError):
            insert_event(central_conn, {
                'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'CARGA', 'evento_uuid': u,
            })

    def test_modo_wal_activo(self, central_conn):
        modo = central_conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert modo.lower() == "wal"

    def test_insert_event_funciona_igual_que_en_local(self, central_conn):
        """insert_event()/get_events() no distinguen local vs. central: mismo esquema."""
        event_id = insert_event(central_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
            'dataset_nombre': 'PATIENTS.csv', 'nivel_alerta': 'NORMAL',
        })
        eventos = get_events(central_conn, usuario_id='u1')
        assert len(eventos) == 1
        assert eventos[0]['event_id'] == event_id
        assert eventos[0]['evento_uuid'] is not None
        assert eventos[0]['hash_integridad'] is not None

    def test_verify_integrity_funciona_sobre_la_base_central(self, central_conn):
        insert_event(central_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA'})
        assert verify_integrity(central_conn) == []


# ──────────────────────────────────────────────────────────────
# CA1/CA3: Persistencia dual (local + central) sin duplicar hashing
# ──────────────────────────────────────────────────────────────

class TestInsertEventDual:
    def test_mismo_hash_y_uuid_en_ambas_bases(self, local_conn, central_conn):
        resultado = insert_event_dual(local_conn, central_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
            'dataset_nombre': 'PATIENTS.csv', 'nivel_alerta': 'NORMAL',
        })

        local_row = get_events(local_conn, usuario_id='u1')[0]
        central_row = get_events(central_conn, usuario_id='u1')[0]

        assert local_row['hash_integridad'] == central_row['hash_integridad']
        assert local_row['evento_uuid'] == central_row['evento_uuid'] == resultado['evento_uuid']
        assert resultado['local_event_id'] is not None
        assert resultado['central_event_id'] is not None

    def test_hash_se_calcula_una_sola_vez(self, local_conn, central_conn, monkeypatch):
        """No se duplica lógica de hashing: hash_event() se invoca una sola vez por evento."""
        import audit_tracer.models.audit_log as audit_log_module
        llamadas = []
        original = audit_log_module.hash_event

        def contador(*args, **kwargs):
            llamadas.append(1)
            return original(*args, **kwargs)

        monkeypatch.setattr(audit_log_module, "hash_event", contador)

        insert_event_dual(local_conn, central_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
        })

        assert len(llamadas) == 1

    def test_si_falla_la_escritura_central_el_evento_no_se_pierde_localmente(self, local_conn):
        """Resiliencia del modelo híbrido: local nunca depende de que la central esté disponible."""
        central_no_disponible = get_central_connection(":memory:")
        central_no_disponible.close()  # simula servidor/central inalcanzable

        resultado = insert_event_dual(local_conn, central_no_disponible, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
        })

        assert resultado['local_event_id'] is not None
        assert resultado['central_event_id'] is None
        assert len(get_events(local_conn, usuario_id='u1')) == 1

    def test_solo_local_si_no_se_pasa_conexion_central(self, local_conn):
        resultado = insert_event_dual(local_conn, None, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
        })
        assert resultado['local_event_id'] is not None
        assert resultado['central_event_id'] is None


# ──────────────────────────────────────────────────────────────
# CA3: Inmutabilidad — triggers de UPDATE/DELETE (local y central)
# ──────────────────────────────────────────────────────────────

class TestInmutabilidad:
    """
    Cierra un faltante real de HU-3.3 (implementada en una rama que nunca
    se mergeó a main — ver git log --all -S "CREATE TRIGGER"). Se prueba
    parametrizado sobre local y central: deben comportarse idéntico.
    """

    def test_bloquea_update(self, any_conn):
        event_id = insert_event(any_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA'})

        with pytest.raises(sqlite3.IntegrityError):
            any_conn.execute("UPDATE audit_log SET tipo_accion = 'BORRADO' WHERE event_id = ?", (event_id,))

        tipo_accion = any_conn.execute(
            "SELECT tipo_accion FROM audit_log WHERE event_id = ?", (event_id,)
        ).fetchone()[0]
        assert tipo_accion == 'CARGA'  # la fila no cambió

    def test_bloquea_delete(self, any_conn):
        event_id = insert_event(any_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA'})

        with pytest.raises(sqlite3.IntegrityError):
            any_conn.execute("DELETE FROM audit_log WHERE event_id = ?", (event_id,))

        total = any_conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE event_id = ?", (event_id,)
        ).fetchone()[0]
        assert total == 1  # la fila sigue existiendo

    def test_intento_de_update_queda_registrado(self, any_conn):
        event_id = insert_event(any_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA'})

        with pytest.raises(sqlite3.IntegrityError):
            any_conn.execute("UPDATE audit_log SET tipo_accion = 'X' WHERE event_id = ?", (event_id,))

        intentos = any_conn.execute(
            "SELECT tipo_intento, event_id_objetivo FROM audit_intentos_bloqueados"
        ).fetchall()
        assert len(intentos) == 1
        assert intentos[0][0] == 'INTENTO_MODIFICACION'
        assert intentos[0][1] == event_id

    def test_intento_de_delete_queda_registrado(self, any_conn):
        event_id = insert_event(any_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA'})

        with pytest.raises(sqlite3.IntegrityError):
            any_conn.execute("DELETE FROM audit_log WHERE event_id = ?", (event_id,))

        intentos = any_conn.execute(
            "SELECT tipo_intento, event_id_objetivo FROM audit_intentos_bloqueados"
        ).fetchall()
        assert len(intentos) == 1
        assert intentos[0][0] == 'INTENTO_ELIMINACION'
        assert intentos[0][1] == event_id

    def test_no_afecta_insert_normal(self, any_conn):
        """Los triggers solo vigilan UPDATE/DELETE: insertar sigue funcionando sin fricción."""
        event_id = insert_event(any_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA'})
        assert event_id > 0
        assert get_events(any_conn, usuario_id='u1')[0]['event_id'] == event_id


# ──────────────────────────────────────────────────────────────
# CA2: Escrituras concurrentes de múltiples usuarios
# ──────────────────────────────────────────────────────────────

class TestConcurrencia:
    """
    ~20-30 usuarios concurrentes (rango que menciona CA2), cada uno con su
    propia conexión (patrón seguro para SQLite: no compartir un mismo
    objeto Connection entre hilos). El PRAGMA busy_timeout de
    get_central_connection() es lo que hace que un escritor espere su
    turno en vez de fallar con "database is locked".
    """

    NUM_USUARIOS = 25

    def test_ninguna_escritura_concurrente_se_pierde(self, tmp_path):
        db_path = str(tmp_path / "concurrencia.db")
        get_central_connection(db_path).close()  # crea el schema antes de concurrir

        errores = []

        def escribir(indice):
            try:
                conn = get_central_connection(db_path)
                insert_event(conn, {
                    'usuario_id': f'usuario_{indice}',
                    'sesion_id': f'sesion_{indice}',
                    'tipo_accion': 'CARGA',
                    'dataset_nombre': f'dataset_{indice}.csv',
                    'nivel_alerta': 'NORMAL',
                })
                conn.close()
            except Exception as exc:  # se recolecta para no perder el fallo dentro del hilo
                errores.append(exc)

        hilos = [threading.Thread(target=escribir, args=(i,)) for i in range(self.NUM_USUARIOS)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join(timeout=15)

        assert errores == [], f"Escrituras concurrentes fallaron: {errores}"

        conn = get_central_connection(db_path)
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        usuarios_distintos = conn.execute(
            "SELECT COUNT(DISTINCT usuario_id) FROM audit_log"
        ).fetchone()[0]
        conn.close()

        assert total == self.NUM_USUARIOS
        assert usuarios_distintos == self.NUM_USUARIOS

    def test_escrituras_concurrentes_no_corrompen_hashes(self, tmp_path):
        db_path = str(tmp_path / "concurrencia_hash.db")
        get_central_connection(db_path).close()

        def escribir(indice):
            conn = get_central_connection(db_path)
            insert_event(conn, {
                'usuario_id': f'usuario_{indice}', 'sesion_id': f'sesion_{indice}',
                'tipo_accion': 'CONSULTA', 'nivel_alerta': 'NORMAL',
            })
            conn.close()

        hilos = [threading.Thread(target=escribir, args=(i,)) for i in range(self.NUM_USUARIOS)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join(timeout=15)

        conn = get_central_connection(db_path)
        corruptos = verify_integrity(conn)
        conn.close()

        assert corruptos == []

    def test_evento_uuid_sigue_siendo_unico_bajo_concurrencia(self, tmp_path):
        db_path = str(tmp_path / "concurrencia_uuid.db")
        get_central_connection(db_path).close()

        def escribir(indice):
            conn = get_central_connection(db_path)
            insert_event(conn, {
                'usuario_id': f'usuario_{indice}', 'sesion_id': f'sesion_{indice}',
                'tipo_accion': 'CARGA', 'nivel_alerta': 'NORMAL',
            })
            conn.close()

        hilos = [threading.Thread(target=escribir, args=(i,)) for i in range(self.NUM_USUARIOS)]
        for h in hilos:
            h.start()
        for h in hilos:
            h.join(timeout=15)

        conn = get_central_connection(db_path)
        total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        uuids_distintos = conn.execute(
            "SELECT COUNT(DISTINCT evento_uuid) FROM audit_log"
        ).fetchone()[0]
        conn.close()

        assert total == uuids_distintos == self.NUM_USUARIOS
