import csv
import io
import pytest
import os
import sqlite3
import uuid
from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import (
    insert_event,
    get_events,
    verify_integrity,
    get_critical_events,
    contar_intentos_fallidos_recientes,
    export_critical_events_to_csv,
    generate_report,
    export_report_to_csv,
    REPORT_CSV_COLUMNS,
    NO_RESULTS_MESSAGE,
)
from audit_tracer.utils.hashing import hash_event
from datetime import datetime

@pytest.fixture
def db_conn():
    conn = get_connection(":memory:")
    yield conn
    conn.close()

def test_insert_event(db_conn):
    """insert_event() inserta y retorna event_id válido."""
    event = {
        'usuario_id': 'test_user',
        'sesion_id': 'test_session',
        'tipo_accion': 'CARGA',
        'dataset_nombre': 'test.csv',
        'nivel_alerta': 'NORMAL'
    }
    event_id = insert_event(db_conn, event)
    assert event_id > 0
    
    # Check that it was actually inserted
    events = get_events(db_conn, usuario_id='test_user')
    assert len(events) == 1
    assert events[0]['event_id'] == event_id
    assert events[0]['hash_integridad'] is not None
    assert len(events[0]['hash_integridad']) == 64  # SHA-256 hex length

def test_get_events_filters(db_conn):
    """get_events() funciona con distintas combinaciones de filtros."""
    insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'nivel_alerta': 'NORMAL'})
    insert_event(db_conn, {'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'CONSULTA', 'nivel_alerta': 'ADVERTENCIA'})

    assert len(get_events(db_conn, usuario_id='u1')) == 1
    assert len(get_events(db_conn, tipo_accion='CONSULTA')) == 1
    assert len(get_events(db_conn, nivel_alerta='NORMAL')) == 1
    assert len(get_events(db_conn, usuario_id='u3')) == 0


# ──────────────────────────────────────────────────────────────
# HU-4.2 — Filtrado de eventos de auditoría
# ──────────────────────────────────────────────────────────────

class TestFiltradoEventos:
    """
    CA1: filtrar por usuario_id.
    CA2: filtrar por rango de fechas (timestamp).
    CA3: filtrar por tipo_accion.
    CA4: filtrar por dataset_nombre.
    CA5: los filtros se pueden combinar.
    CA6: el resultado refleja únicamente los eventos que cumplen los criterios.
    """

    @pytest.fixture
    def eventos_variados(self, db_conn):
        """Set de eventos con distintas combinaciones de usuario/fecha/acción/dataset."""
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
            'dataset_nombre': 'PATIENTS.csv', 'timestamp': '2026-01-05T10:00:00',
            'nivel_alerta': 'NORMAL',
        })
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'PATIENTS.csv', 'timestamp': '2026-01-10T10:00:00',
            'nivel_alerta': 'NORMAL',
        })
        insert_event(db_conn, {
            'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'admissions.xlsx', 'timestamp': '2026-01-10T11:00:00',
            'nivel_alerta': 'CRITICO',
        })
        insert_event(db_conn, {
            'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'CONSULTA',
            'dataset_nombre': 'admissions.xlsx', 'timestamp': '2026-02-01T09:00:00',
            'nivel_alerta': 'NORMAL',
        })
        return db_conn

    # ── CA1 ──────────────────────────────────────────────────
    def test_filtra_por_usuario_id(self, eventos_variados):
        eventos = get_events(eventos_variados, usuario_id='u1')
        assert len(eventos) == 2
        assert all(e['usuario_id'] == 'u1' for e in eventos)

    # ── CA2 ──────────────────────────────────────────────────
    def test_filtra_por_rango_de_fechas(self, eventos_variados):
        eventos = get_events(
            eventos_variados,
            fecha_inicio='2026-01-06T00:00:00',
            fecha_fin='2026-01-31T23:59:59',
        )
        assert len(eventos) == 2
        assert all('2026-01-1' in e['timestamp'] for e in eventos)

    def test_filtra_por_fecha_solo_inicio(self, eventos_variados):
        eventos = get_events(eventos_variados, fecha_inicio='2026-02-01T00:00:00')
        assert len(eventos) == 1
        assert eventos[0]['tipo_accion'] == 'CONSULTA'

    # ── CA3 ──────────────────────────────────────────────────
    def test_filtra_por_tipo_accion(self, eventos_variados):
        eventos = get_events(eventos_variados, tipo_accion='EXPORTACION')
        assert len(eventos) == 2
        assert all(e['tipo_accion'] == 'EXPORTACION' for e in eventos)

    # ── CA4 ──────────────────────────────────────────────────
    def test_filtra_por_dataset_nombre(self, eventos_variados):
        eventos = get_events(eventos_variados, dataset_nombre='admissions.xlsx')
        assert len(eventos) == 2
        assert all(e['dataset_nombre'] == 'admissions.xlsx' for e in eventos)

    # ── CA5: combinación de filtros ────────────────────────────
    def test_combina_usuario_y_tipo_accion(self, eventos_variados):
        eventos = get_events(eventos_variados, usuario_id='u1', tipo_accion='EXPORTACION')
        assert len(eventos) == 1
        assert eventos[0]['dataset_nombre'] == 'PATIENTS.csv'

    def test_combina_usuario_fecha_y_tipo_accion(self, eventos_variados):
        eventos = get_events(
            eventos_variados,
            usuario_id='u2',
            tipo_accion='EXPORTACION',
            fecha_inicio='2026-01-01T00:00:00',
            fecha_fin='2026-01-31T23:59:59',
        )
        assert len(eventos) == 1
        assert eventos[0]['dataset_nombre'] == 'admissions.xlsx'

    def test_combina_dataset_y_tipo_accion(self, eventos_variados):
        eventos = get_events(eventos_variados, dataset_nombre='admissions.xlsx', tipo_accion='CONSULTA')
        assert len(eventos) == 1
        assert eventos[0]['usuario_id'] == 'u2'

    # ── CA6: el resultado refleja solo lo que cumple todos los criterios ──
    def test_combinacion_sin_coincidencias_devuelve_vacio(self, eventos_variados):
        eventos = get_events(eventos_variados, usuario_id='u1', tipo_accion='CONSULTA')
        assert eventos == []

    def test_filtros_no_alteran_datos_subyacentes(self, eventos_variados):
        """Aplicar filtros es de solo lectura: no modifica los registros."""
        total_antes = len(get_events(eventos_variados))
        get_events(eventos_variados, usuario_id='u1', tipo_accion='EXPORTACION')
        total_despues = len(get_events(eventos_variados))
        assert total_antes == total_despues == 4

def test_verify_integrity(db_conn):
    """verify_integrity() detecta un registro cuyo hash no corresponde a sus datos."""
    # Insert a valid event
    event = {
        'usuario_id': 'u1',
        'tipo_accion': 'CARGA',
        'nivel_alerta': 'NORMAL',
        'sesion_id': 's1'
    }
    insert_event(db_conn, event)

    # Check that it starts clean
    corrupted = verify_integrity(db_conn)
    assert len(corrupted) == 0

    # Simular alteración insertando directamente una fila con un hash que
    # no corresponde a sus propios datos. Ya no se puede simular esto con
    # un UPDATE sobre la fila existente: HU-5.4 agregó un trigger que
    # bloquea exactamente eso (ver TestInmutabilidad en test_central_db.py,
    # que prueba ese bloqueo directamente).
    cursor = db_conn.cursor()
    cursor.execute(
        "INSERT INTO audit_log "
        "(evento_uuid, usuario_id, sesion_id, timestamp, tipo_accion, nivel_alerta, hash_integridad) "
        "VALUES (?, 'u2', 's2', '2026-01-01T00:00:00', 'BORRADO', 'CRITICO', 'hash_invalido_manual')",
        (str(uuid.uuid4()),),
    )
    db_conn.commit()

    # Verify integrity should now detect it
    corrupted = verify_integrity(db_conn)
    assert len(corrupted) == 1
    assert corrupted[0]['tipo_accion'] == 'BORRADO'
    assert corrupted[0]['stored_hash'] == 'hash_invalido_manual'
    assert corrupted[0]['stored_hash'] != corrupted[0]['calculated_hash']


# ──────────────────────────────────────────────────────────────
# HU-4.4 — Identificación de eventos críticos
# ──────────────────────────────────────────────────────────────

class TestGetCriticalEvents:
    """CA2/CA4: consulta de eventos críticos y su contenido de contexto."""

    def test_get_critical_events_solo_devuelve_criticos(self, db_conn):
        insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'nivel_alerta': 'NORMAL'})
        insert_event(db_conn, {'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'ACCESO_FALLIDO', 'nivel_alerta': 'ADVERTENCIA'})
        insert_event(db_conn, {
            'usuario_id': 'u3', 'sesion_id': 's3', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'PATIENTS.csv', 'nivel_alerta': 'CRITICO',
            'motivo_alerta': 'Exportación masiva: 1500 filas (> 1000)',
        })

        eventos = get_critical_events(db_conn)
        assert len(eventos) == 1
        assert eventos[0]['nivel_alerta'] == 'CRITICO'

    def test_get_critical_events_equivalente_a_filtro_nivel_alerta(self, db_conn):
        insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'nivel_alerta': 'CRITICO', 'motivo_alerta': 'x'})
        assert get_critical_events(db_conn) == get_events(db_conn, nivel_alerta='CRITICO')

    def test_get_critical_events_combina_filtros(self, db_conn):
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'PATIENTS.csv', 'nivel_alerta': 'CRITICO', 'motivo_alerta': 'masiva',
        })
        insert_event(db_conn, {
            'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'admissions.xlsx', 'nivel_alerta': 'CRITICO', 'motivo_alerta': 'masiva',
        })

        eventos = get_critical_events(db_conn, usuario_id='u1', tipo_accion='EXPORTACION')
        assert len(eventos) == 1
        assert eventos[0]['dataset_nombre'] == 'PATIENTS.csv'

    def test_evento_critico_incluye_contexto_ca4(self, db_conn):
        """CA4: usuario_id, timestamp, tipo_accion y dataset_nombre presentes."""
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'PATIENTS.csv', 'nivel_alerta': 'CRITICO',
            'motivo_alerta': 'Exportación masiva: 1500 filas (> 1000)',
        })

        ev = get_critical_events(db_conn)[0]
        assert ev['usuario_id'] == 'u1'
        assert ev['timestamp'] is not None
        assert ev['tipo_accion'] == 'EXPORTACION'
        assert ev['dataset_nombre'] == 'PATIENTS.csv'
        assert ev['motivo_alerta'] is not None  # CA3


class TestContarIntentosFallidosRecientes:
    """CA1-a: conteo de intentos fallidos de un usuario en una ventana de tiempo."""

    def test_cuenta_solo_dentro_de_la_ventana(self, db_conn):
        ahora = datetime(2026, 1, 5, 10, 0, 0)
        insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'ACCESO_FALLIDO', 'timestamp': '2026-01-05T09:56:00', 'nivel_alerta': 'NORMAL'})
        insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'ACCESO_FALLIDO', 'timestamp': '2026-01-05T09:50:00', 'nivel_alerta': 'NORMAL'})

        # Solo el primero cae dentro de los últimos 5 minutos antes de `ahora`
        assert contar_intentos_fallidos_recientes(db_conn, 'u1', ahora, ventana_minutos=5) == 1

    def test_no_cuenta_otros_usuarios_ni_otros_tipos(self, db_conn):
        ahora = datetime(2026, 1, 5, 10, 0, 0)
        insert_event(db_conn, {'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'ACCESO_FALLIDO', 'timestamp': '2026-01-05T09:58:00', 'nivel_alerta': 'NORMAL'})
        insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'timestamp': '2026-01-05T09:58:00', 'nivel_alerta': 'NORMAL'})

        assert contar_intentos_fallidos_recientes(db_conn, 'u1', ahora, ventana_minutos=5) == 0


class TestExportCriticalEventsToCsv:
    """CA5: exportación de eventos críticos a formato CSV."""

    def _seed(self, db_conn):
        insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'nivel_alerta': 'NORMAL'})
        insert_event(db_conn, {
            'usuario_id': 'u2', 'sesion_id': 's2', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'PATIENTS.csv', 'filas_exportadas': 1500, 'nivel_alerta': 'CRITICO',
            'motivo_alerta': 'Exportación masiva: 1500 filas (> 1000)',
        })
        insert_event(db_conn, {
            'usuario_id': 'DESCONOCIDO', 'sesion_id': 's3', 'tipo_accion': 'CONSULTA',
            'dataset_nombre': 'labs.csv', 'nivel_alerta': 'CRITICO',
            'motivo_alerta': 'Operación ejecutada por usuario no identificado',
        })

    def test_exporta_a_archivo_y_retorna_conteo(self, db_conn, tmp_path):
        self._seed(db_conn)
        dest = tmp_path / "criticos.csv"

        total = export_critical_events_to_csv(db_conn, str(dest))
        assert total == 2
        assert dest.exists()

        with open(dest, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))
        assert len(rows) == 2
        assert all(row['nivel_alerta'] == 'CRITICO' for row in rows)

    def test_exporta_a_buffer_en_memoria(self, db_conn):
        """Soporta un objeto file-like (p. ej. para servir la descarga vía HTTP)."""
        self._seed(db_conn)
        buffer = io.StringIO()

        total = export_critical_events_to_csv(db_conn, buffer)
        assert total == 2

        buffer.seek(0)
        rows = list(csv.DictReader(buffer))
        assert len(rows) == 2

    def test_exporta_respetando_filtros(self, db_conn, tmp_path):
        self._seed(db_conn)
        dest = tmp_path / "criticos_u2.csv"

        total = export_critical_events_to_csv(db_conn, str(dest), usuario_id='u2')
        assert total == 1

        with open(dest, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))
        assert rows[0]['usuario_id'] == 'u2'
        assert rows[0]['dataset_nombre'] == 'PATIENTS.csv'

    def test_csv_incluye_columnas_de_contexto_y_motivo(self, db_conn, tmp_path):
        """CA3/CA4: el CSV conserva motivo_alerta y el contexto del evento."""
        self._seed(db_conn)
        dest = tmp_path / "criticos.csv"
        export_critical_events_to_csv(db_conn, str(dest))

        with open(dest, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))

        assert {'usuario_id', 'timestamp', 'tipo_accion', 'dataset_nombre', 'motivo_alerta'} <= set(rows[0].keys())
        assert all(row['motivo_alerta'] for row in rows)

    def test_sin_eventos_criticos_genera_csv_solo_con_encabezado(self, db_conn, tmp_path):
        insert_event(db_conn, {'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA', 'nivel_alerta': 'NORMAL'})
        dest = tmp_path / "vacio.csv"

        total = export_critical_events_to_csv(db_conn, str(dest))
        assert total == 0

        with open(dest, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))
        assert rows == []


# ──────────────────────────────────────────────────────────────
# HU-2.5 — Asociar cada evento a un usuario único identificable
# ──────────────────────────────────────────────────────────────

class TestAsociacionUsuarioEvento:
    """
    CA1: cada evento queda asociado a un usuario_id.
    CA2: usuario no identificado -> usuario_id=DESCONOCIDO, nivel_alerta=CRITICO,
         y el evento se registra igualmente (no se pierde).
    CA3: eventos de una misma sesión comparten sesion_id.
    """

    # ── CA1: usuario autenticado ────────────────────────────────
    def test_usuario_autenticado_queda_asociado_al_evento(self, db_conn):
        """Caso 1 del DoD: usuario123/sesion456 -> se persisten tal cual, sin alerta."""
        event_id = insert_event(db_conn, {
            'usuario_id': 'usuario123', 'sesion_id': 'sesion456', 'tipo_accion': 'CARGA',
        })
        eventos = get_events(db_conn, usuario_id='usuario123')
        assert len(eventos) == 1
        assert eventos[0]['event_id'] == event_id
        assert eventos[0]['usuario_id'] == 'usuario123'
        assert eventos[0]['sesion_id'] == 'sesion456'
        assert eventos[0]['nivel_alerta'] != 'CRITICO'

    # ── CA2: usuario no identificado ────────────────────────────
    def test_usuario_no_identificado_se_marca_desconocido_y_critico(self, db_conn):
        """Caso 2 del DoD: sin usuario -> DESCONOCIDO + CRITICO, evento sí se guarda."""
        event_id = insert_event(db_conn, {
            'sesion_id': 'sesion789', 'tipo_accion': 'CONSULTA',
        })
        eventos = get_events(db_conn, usuario_id='DESCONOCIDO')
        assert len(eventos) == 1
        assert eventos[0]['event_id'] == event_id
        assert eventos[0]['usuario_id'] == 'DESCONOCIDO'
        assert eventos[0]['nivel_alerta'] == 'CRITICO'
        assert eventos[0]['motivo_alerta']

    def test_evento_sin_usuario_ni_sesion_no_se_pierde(self, db_conn):
        """CA2: falta total de usuario_id/sesion_id -> igual se persiste (no NOT NULL error)."""
        event_id = insert_event(db_conn, {'tipo_accion': 'ACCESO_FALLIDO'})
        eventos = get_events(db_conn)
        assert any(e['event_id'] == event_id for e in eventos)
        evento = next(e for e in eventos if e['event_id'] == event_id)
        assert evento['usuario_id'] == 'DESCONOCIDO'
        assert evento['sesion_id'] == 'SIN_SESION'
        assert evento['nivel_alerta'] == 'CRITICO'

    def test_usuario_desconocido_explicito_tambien_se_fuerza_a_critico(self, db_conn):
        """Aun si el llamador manda nivel_alerta=NORMAL, DESCONOCIDO se reclasifica a CRITICO."""
        insert_event(db_conn, {
            'usuario_id': 'DESCONOCIDO', 'sesion_id': 's1', 'tipo_accion': 'ACCESO_FALLIDO',
            'nivel_alerta': 'NORMAL',
        })
        eventos = get_events(db_conn, usuario_id='DESCONOCIDO')
        assert eventos[0]['nivel_alerta'] == 'CRITICO'

    def test_motivo_alerta_explicito_se_respeta_para_desconocido(self, db_conn):
        """Si el llamador ya definió un motivo_alerta específico, no se sobreescribe."""
        insert_event(db_conn, {
            'sesion_id': 's1', 'tipo_accion': 'ACCESO_FALLIDO',
            'motivo_alerta': 'Motivo específico del llamador',
        })
        eventos = get_events(db_conn, usuario_id='DESCONOCIDO')
        assert eventos[0]['motivo_alerta'] == 'Motivo específico del llamador'

    # ── CA3: consistencia usuario_id + sesion_id ────────────────
    def test_multiples_eventos_misma_sesion_comparten_sesion_id(self, db_conn):
        """Caso 3 del DoD: varios eventos del mismo usuario en una sesión -> mismo sesion_id."""
        insert_event(db_conn, {'usuario_id': 'usuario123', 'sesion_id': 'sesion456', 'tipo_accion': 'CARGA'})
        insert_event(db_conn, {'usuario_id': 'usuario123', 'sesion_id': 'sesion456', 'tipo_accion': 'CONSULTA'})
        insert_event(db_conn, {'usuario_id': 'usuario123', 'sesion_id': 'sesion456', 'tipo_accion': 'EXPORTACION'})

        eventos = get_events(db_conn, usuario_id='usuario123')
        assert len(eventos) == 3
        sesion_ids = {e['sesion_id'] for e in eventos}
        assert sesion_ids == {'sesion456'}

    # ── CA5: consulta/filtrado por usuario_id ───────────────────
    def test_ca5_filtro_por_usuario_id_no_devuelve_eventos_de_otros_usuarios(self, db_conn):
        insert_event(db_conn, {'usuario_id': 'usuario123', 'sesion_id': 's1', 'tipo_accion': 'CARGA'})
        insert_event(db_conn, {'usuario_id': 'otro_usuario', 'sesion_id': 's2', 'tipo_accion': 'CARGA'})

        eventos = get_events(db_conn, usuario_id='usuario123')
        assert len(eventos) == 1
        assert eventos[0]['usuario_id'] == 'usuario123'


# ──────────────────────────────────────────────────────────────
# HU-4.5 — Reportes de auditoría por fechas y usuario + exportación CSV
# ──────────────────────────────────────────────────────────────

class TestGenerateReport:
    """
    CA1: filtros individuales y combinados (usuario_id, fechas, tipo_accion, dataset_nombre).
    CA2: columnas del reporte y orden cronológico ascendente.
    CA3: exportación a CSV con cabecera estandarizada.
    CA4: mensaje exacto cuando no hay resultados, sin errores ni CSV corrupto.
    """

    @pytest.fixture
    def eventos_reporte(self, db_conn):
        """Eventos con distintos usuarios, fechas, tipo_accion y dataset."""
        insert_event(db_conn, {
            'usuario_id': 'usuario123', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
            'dataset_nombre': 'PATIENTS.csv', 'columnas_afectadas': '["id","edad"]',
            'timestamp': '2026-01-01T08:00:00', 'nivel_alerta': 'NORMAL',
        })
        insert_event(db_conn, {
            'usuario_id': 'usuario123', 'sesion_id': 's1', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'PATIENTS.csv', 'columnas_afectadas': 'nombre,apellido,diagnostico',
            'timestamp': '2026-01-05T08:00:00', 'nivel_alerta': 'NORMAL',
        })
        insert_event(db_conn, {
            'usuario_id': 'usuario456', 'sesion_id': 's2', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'admissions.xlsx', 'columnas_afectadas': '["diagnosis"]',
            'timestamp': '2026-01-10T08:00:00', 'nivel_alerta': 'CRITICO',
        })
        insert_event(db_conn, {
            'usuario_id': 'usuario456', 'sesion_id': 's2', 'tipo_accion': 'CONSULTA',
            'dataset_nombre': 'admissions.xlsx', 'columnas_afectadas': '["age"]',
            'timestamp': '2026-01-15T08:00:00', 'nivel_alerta': 'NORMAL',
        })
        insert_event(db_conn, {
            'usuario_id': 'usuario789', 'sesion_id': 's3', 'tipo_accion': 'CARGA',
            'dataset_nombre': 'pacientes.csv', 'columnas_afectadas': '["subject_id"]',
            'timestamp': '2026-01-08T08:00:00', 'nivel_alerta': 'NORMAL',
        })
        return db_conn

    # ── Test 1: filtrado por usuario ────────────────────────────
    def test_filtrado_por_usuario(self, eventos_reporte):
        reporte = generate_report(eventos_reporte, usuario_id='usuario123')
        assert len(reporte) == 2
        assert all(e['usuario_id'] == 'usuario123' for e in reporte)

    # ── Test 2: filtrado por rango de fechas ────────────────────
    def test_filtrado_por_rango_de_fechas(self, eventos_reporte):
        reporte = generate_report(
            eventos_reporte,
            fecha_inicio='2026-01-04T00:00:00',
            fecha_fin='2026-01-09T23:59:59',
        )
        assert len(reporte) == 2
        timestamps = {e['timestamp'] for e in reporte}
        assert timestamps == {'2026-01-05T08:00:00', '2026-01-08T08:00:00'}

    # ── Test 3: filtros combinados ───────────────────────────────
    def test_filtros_combinados(self, eventos_reporte):
        reporte = generate_report(
            eventos_reporte,
            usuario_id='usuario456',
            fecha_inicio='2026-01-01T00:00:00',
            fecha_fin='2026-01-12T00:00:00',
            tipo_accion='EXPORTACION',
        )
        assert len(reporte) == 1
        assert reporte[0]['usuario_id'] == 'usuario456'
        assert reporte[0]['tipo_accion'] == 'EXPORTACION'
        assert reporte[0]['timestamp'] == '2026-01-10T08:00:00'

    # ── Test 4: filtrado por dataset ─────────────────────────────
    def test_filtrado_por_dataset(self, eventos_reporte):
        reporte = generate_report(eventos_reporte, dataset_nombre='pacientes.csv')
        assert len(reporte) == 1
        assert reporte[0]['dataset_nombre'] == 'pacientes.csv'
        assert reporte[0]['usuario_id'] == 'usuario789'

    # ── Test 5: sin resultados ───────────────────────────────────
    def test_sin_resultados(self, eventos_reporte):
        reporte = generate_report(eventos_reporte, usuario_id='usuario_inexistente')
        assert reporte == []
        assert NO_RESULTS_MESSAGE == "No se encontraron eventos para los filtros seleccionados."

    def test_sin_resultados_no_lanza_excepcion_con_filtros_combinados(self, eventos_reporte):
        """CA4: ninguna combinación de filtros sin coincidencias debe lanzar excepción."""
        reporte = generate_report(
            eventos_reporte,
            usuario_id='usuario123',
            tipo_accion='ACCESO_DENEGADO',
            dataset_nombre='no_existe.csv',
        )
        assert reporte == []

    # ── Test 6: orden cronológico ascendente ─────────────────────
    def test_orden_cronologico_ascendente(self, db_conn):
        """CA2: aunque se inserten desordenados, el reporte queda timestamp ASC."""
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
            'timestamp': '2026-03-01T10:00:00',
        })
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'CONSULTA',
            'timestamp': '2026-01-01T10:00:00',
        })
        insert_event(db_conn, {
            'usuario_id': 'u1', 'sesion_id': 's1', 'tipo_accion': 'EXPORTACION',
            'timestamp': '2026-02-01T10:00:00',
        })

        reporte = generate_report(db_conn, usuario_id='u1')
        timestamps = [e['timestamp'] for e in reporte]
        assert timestamps == sorted(timestamps)
        assert timestamps == ['2026-01-01T10:00:00', '2026-02-01T10:00:00', '2026-03-01T10:00:00']

    # ── CA2: forma exacta de las columnas del reporte ─────────────
    def test_columnas_del_reporte_son_exactamente_las_de_ca2(self, eventos_reporte):
        reporte = generate_report(eventos_reporte, usuario_id='usuario123')
        assert set(reporte[0].keys()) == set(REPORT_CSV_COLUMNS)
        assert REPORT_CSV_COLUMNS == [
            'event_id', 'usuario_id', 'timestamp', 'tipo_accion',
            'dataset_nombre', 'columnas_afectadas', 'nivel_alerta',
        ]


class TestExportReportToCsv:
    """CA3: exportación del reporte a CSV con cabecera estandarizada."""

    @pytest.fixture
    def eventos_reporte(self, db_conn):
        insert_event(db_conn, {
            'usuario_id': 'usuario123', 'sesion_id': 's1', 'tipo_accion': 'CARGA',
            'dataset_nombre': 'PATIENTS.csv', 'columnas_afectadas': 'nombre,apellido,diagnostico',
            'timestamp': '2026-01-01T08:00:00', 'nivel_alerta': 'NORMAL',
        })
        insert_event(db_conn, {
            'usuario_id': 'usuario456', 'sesion_id': 's2', 'tipo_accion': 'EXPORTACION',
            'dataset_nombre': 'admissions.xlsx', 'columnas_afectadas': '["diagnosis"]',
            'timestamp': '2026-01-10T08:00:00', 'nivel_alerta': 'CRITICO',
        })
        return db_conn

    # ── Test 7: CSV ───────────────────────────────────────────────
    def test_csv_tiene_cabecera_correcta_y_siete_columnas(self, eventos_reporte, tmp_path):
        dest = tmp_path / "reporte.csv"
        total = export_report_to_csv(eventos_reporte, str(dest))
        assert total == 2

        with open(dest, newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            header = next(reader)

        assert header == [
            'event_id', 'usuario_id', 'timestamp', 'tipo_accion',
            'dataset_nombre', 'columnas_afectadas', 'nivel_alerta',
        ]
        assert len(header) == 7

    def test_csv_respeta_orden_cronologico_y_solo_incluye_eventos_filtrados(self, eventos_reporte, tmp_path):
        dest = tmp_path / "reporte_u123.csv"
        total = export_report_to_csv(eventos_reporte, str(dest), usuario_id='usuario123')
        assert total == 1

        with open(dest, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == 1
        assert rows[0]['usuario_id'] == 'usuario123'

    def test_csv_escapa_correctamente_valores_con_comas(self, eventos_reporte, tmp_path):
        """columnas_afectadas='nombre,apellido,diagnostico' debe sobrevivir el round-trip como un solo campo."""
        dest = tmp_path / "reporte_comas.csv"
        export_report_to_csv(eventos_reporte, str(dest), usuario_id='usuario123')

        with open(dest, newline='', encoding='utf-8') as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == 1
        assert rows[0]['columnas_afectadas'] == 'nombre,apellido,diagnostico'

    def test_csv_sin_resultados_tiene_solo_cabecera_sin_error(self, eventos_reporte, tmp_path):
        """CA4: filtros sin coincidencias -> CSV válido con únicamente la cabecera, sin excepción."""
        dest = tmp_path / "reporte_vacio.csv"
        total = export_report_to_csv(eventos_reporte, str(dest), usuario_id='usuario_inexistente')
        assert total == 0

        with open(dest, newline='', encoding='utf-8') as f:
            rows = list(csv.reader(f))

        assert len(rows) == 1  # solo la cabecera
        assert rows[0] == [
            'event_id', 'usuario_id', 'timestamp', 'tipo_accion',
            'dataset_nombre', 'columnas_afectadas', 'nivel_alerta',
        ]

    def test_csv_exporta_a_buffer_en_memoria(self, eventos_reporte):
        """Soporta un objeto file-like, igual que export_critical_events_to_csv (patrón reutilizado)."""
        buffer = io.StringIO()
        total = export_report_to_csv(eventos_reporte, buffer)
        assert total == 2

        buffer.seek(0)
        rows = list(csv.DictReader(buffer))
        assert len(rows) == 2
