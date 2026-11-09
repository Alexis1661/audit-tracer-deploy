"""
tests/test_anomaly_detector.py — Pruebas unitarias y de integración para HU-6.3.
Detección de anomalías sobre eventos centralizados.

Criterios de Aceptación:
  - CA1 / PDGTRAZDSA-153: Cálculo de promedios históricos por usuario.
  - CA2 / PDGTRAZDSA-154: Regla de volumen anómalo (marca nivel_alerta = ANOMALIA).
  - CA3 / PDGTRAZDSA-155: Regla de horario inusual (marca nivel_alerta = ANOMALIA).
  - CA4 / PDGTRAZDSA-156: Regla de correlación entre usuarios sobre el mismo dataset.
  - CA5 / PDGTRAZDSA-157: Indicador visual y filtro de "solo anomalías" en el dashboard.
"""

import os
import sqlite3
from conftest import clonar_bd_web, crear_sesion_web
import pytest
from datetime import datetime, timedelta

from audit_tracer.models.audit_log import (
    insert_event,
    get_events,
    get_anomaly_events,
)
from audit_tracer.anomaly_detector import (
    calcular_promedios_historicos,
    evaluar_regla_volumen,
    obtener_horario_habitual,
    evaluar_regla_horario,
    evaluar_regla_correlacion,
    evaluar_evento_anomalias,
)


@pytest.fixture
def db_conn():
    """Crea una base de datos SQLite en memoria con el esquema de audit_log."""
    conn = sqlite3.connect(":memory:")
    schema_path = os.path.join(
        os.path.dirname(__file__), "..", "audit_tracer", "schema", "audit_log_central.sql"
    )
    with open(schema_path, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.row_factory = sqlite3.Row
    yield conn
    conn.close()


def _insertar_evento_base(conn, usuario_id, tipo_accion, timestamp, dataset=None, filas=None, alerta='NORMAL'):
    return insert_event(conn, {
        'usuario_id': usuario_id,
        'sesion_id': f'SES_{usuario_id}',
        'timestamp': timestamp,
        'tipo_accion': tipo_accion,
        'dataset_nombre': dataset,
        'filas_exportadas': filas,
        'nivel_alerta': alerta,
    })


# ─────────────────────────────────────────────────────────────────────────────
# PRUEBAS CA1 / PDGTRAZDSA-153: Cálculo de promedios históricos por usuario
# ─────────────────────────────────────────────────────────────────────────────

def test_calculo_promedios_historicos_usuario_sin_eventos(db_conn):
    """CA1: Un usuario sin eventos debe tener métricas en 0 sin errores."""
    promedios = calcular_promedios_historicos(db_conn, usuario_id="usr_nuevo")
    assert promedios['usuario_id'] == "usr_nuevo"
    assert promedios['total_operaciones'] == 0
    assert promedios['total_accesos'] == 0
    assert promedios['total_transformaciones'] == 0
    assert promedios['total_exportaciones'] == 0
    assert promedios['promedio_total_diario'] == 0.0
    assert promedios['promedio_filas_exportadas'] == 0.0


def test_calculo_promedios_historicos_con_datos_multidias(db_conn):
    """
    CA1: El sistema calcula correctamente los promedios de accesos, transformaciones
    y exportaciones divididos por los días activos observados.
    """
    usr = "dra_garcia"

    # Día 1 (2026-05-10): 2 consultas, 1 transformación, 1 exportación (100 filas)
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-10T09:00:00', dataset='pacientes.csv')
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-10T10:00:00', dataset='pacientes.csv')
    _insertar_evento_base(db_conn, usr, 'TRANSFORMACION', '2026-05-10T11:00:00', dataset='pacientes.csv')
    _insertar_evento_base(db_conn, usr, 'EXPORTACION', '2026-05-10T12:00:00', dataset='pacientes.csv', filas=100)

    # Día 2 (2026-05-11): 1 carga, 1 transformación, 1 exportación (200 filas)
    _insertar_evento_base(db_conn, usr, 'CARGA', '2026-05-11T09:30:00', dataset='laboratorios.csv')
    _insertar_evento_base(db_conn, usr, 'TRANSFORMACION', '2026-05-11T11:30:00', dataset='laboratorios.csv')
    _insertar_evento_base(db_conn, usr, 'EXPORTACION', '2026-05-11T14:00:00', dataset='laboratorios.csv', filas=200)

    promedios = calcular_promedios_historicos(db_conn, usuario_id=usr)

    assert promedios['usuario_id'] == usr
    assert promedios['dias_activos'] == 2
    assert promedios['total_accesos'] == 3       # 2 consultas + 1 carga
    assert promedios['total_transformaciones'] == 2
    assert promedios['total_exportaciones'] == 2
    assert promedios['total_operaciones'] == 7

    # Promedios diarios
    assert promedios['promedio_accesos_diarios'] == 1.5      # 3 / 2
    assert promedios['promedio_transformaciones_diarias'] == 1.0  # 2 / 2
    assert promedios['promedio_exportaciones_diarias'] == 1.0  # 2 / 2
    assert promedios['promedio_total_diario'] == 3.5        # 7 / 2

    # Promedio de filas exportadas: (100 + 200) / 2 = 150.0
    assert promedios['promedio_filas_exportadas'] == 150.0


# ─────────────────────────────────────────────────────────────────────────────
# PRUEBAS CA2 / PDGTRAZDSA-154: Regla de volumen anómalo
# ─────────────────────────────────────────────────────────────────────────────

def test_regla_volumen_anomalo_filas_exportadas(db_conn):
    """
    CA2: Un evento de exportación que supere significativamente (ej. > 3x) el promedio
    histórico de filas exportadas del usuario se detecta como ANOMALIA.
    """
    usr = "dr_perez"
    # Histórico de exportaciones habituales: promedio 100 filas
    _insertar_evento_base(db_conn, usr, 'EXPORTACION', '2026-05-01T10:00:00', filas=100)
    _insertar_evento_base(db_conn, usr, 'EXPORTACION', '2026-05-02T10:00:00', filas=120)
    _insertar_evento_base(db_conn, usr, 'EXPORTACION', '2026-05-03T10:00:00', filas=80)

    # Evento normal: 150 filas (1.5x, dentro del límite habitual)
    evento_normal = {
        'usuario_id': usr,
        'tipo_accion': 'EXPORTACION',
        'timestamp': '2026-05-04T11:00:00',
        'filas_exportadas': 150,
        'dataset_nombre': 'diagnosticos.csv'
    }
    anomalo_norm, motivo_norm = evaluar_regla_volumen(db_conn, evento_normal, factor_umbral=3.0)
    assert not anomalo_norm
    assert motivo_norm is None

    # Evento anómalo: 800 filas (8x sobre el promedio de 100 filas)
    evento_anomalo = {
        'usuario_id': usr,
        'tipo_accion': 'EXPORTACION',
        'timestamp': '2026-05-04T12:00:00',
        'filas_exportadas': 800,
        'dataset_nombre': 'diagnosticos.csv'
    }
    anomalo, motivo = evaluar_regla_volumen(db_conn, evento_anomalo, factor_umbral=3.0)
    assert anomalo
    assert "Volumen anómalo" in motivo
    assert "800" in motivo


def test_regla_volumen_anomalo_operaciones_diarias(db_conn):
    """
    CA2: Si el usuario realiza una cantidad inusualmente alta de operaciones en un día
    en comparación con su promedio diario histórico, se detecta como ANOMALIA.
    """
    usr = "investigador_1"
    # Histórico: promedio 2 operaciones por día a lo largo de 3 días
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-01T10:00:00')
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-01T11:00:00')
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-02T10:00:00')
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-02T11:00:00')
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-03T10:00:00')
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-03T11:00:00')

    # En el día 2026-05-04 el usuario ya ejecutó 8 operaciones
    for i in range(8):
        _insertar_evento_base(db_conn, usr, 'CONSULTA', f'2026-05-04T10:{i:02d}:00')

    evento_actual = {
        'usuario_id': usr,
        'tipo_accion': 'CONSULTA',
        'timestamp': '2026-05-04T10:30:00',
        'dataset_nombre': 'pacientes.csv'
    }
    anomalo, motivo = evaluar_regla_volumen(db_conn, evento_actual, factor_umbral=3.0, min_ops_dia=5)
    assert anomalo
    assert "operaciones en el día supera significativamente el promedio diario histórico" in motivo


# ─────────────────────────────────────────────────────────────────────────────
# PRUEBAS CA3 / PDGTRAZDSA-155: Regla de horario inusual
# ─────────────────────────────────────────────────────────────────────────────

def test_regla_horario_habitual_usuario_detecta_madrugada(db_conn):
    """
    CA3: Un usuario con horario habitual de 08:00 a 17:00 que accede a las 02:30 AM
    es detectado como ANOMALIA por horario inusual.
    """
    usr = "enfermera_ana"
    # Histórico de eventos habituales entre las 08:00 y las 16:00
    for h in [8, 9, 11, 14, 16]:
        _insertar_evento_base(db_conn, usr, 'CONSULTA', f'2026-05-01T{h:02d}:15:00')

    # Acceso dentro de su horario habitual (10:00 AM)
    evento_diurno = {
        'usuario_id': usr,
        'tipo_accion': 'CONSULTA',
        'timestamp': '2026-05-02T10:00:00',
        'dataset_nombre': 'camas.csv'
    }
    anomalo_diurno, motivo_diurno = evaluar_regla_horario(db_conn, evento_diurno)
    assert not anomalo_diurno
    assert motivo_diurno is None

    # Acceso atípico en la madrugada (02:30 AM)
    evento_madrugada = {
        'usuario_id': usr,
        'tipo_accion': 'CONSULTA',
        'timestamp': '2026-05-02T02:30:00',
        'dataset_nombre': 'camas.csv'
    }
    anomalo_madrugada, motivo_madrugada = evaluar_regla_horario(db_conn, evento_madrugada)
    assert anomalo_madrugada
    assert "Horario inusual" in motivo_madrugada
    assert "02:30" in motivo_madrugada


def test_regla_horario_institucional_por_defecto_sin_historico(db_conn):
    """
    CA3: Si el usuario no tiene histórico, se evalúa contra la ventana institucional
    (07:00 a 19:00). Un acceso a las 23:45 debe marcarse como horario inusual.
    """
    usr = "usuario_nuevo"
    evento_noche = {
        'usuario_id': usr,
        'tipo_accion': 'CONSULTA',
        'timestamp': '2026-05-10T23:45:00',
        'dataset_nombre': 'datos.csv'
    }
    anomalo, motivo = evaluar_regla_horario(db_conn, evento_noche)
    assert anomalo
    assert "Horario inusual" in motivo
    assert "23:45" in motivo


# ─────────────────────────────────────────────────────────────────────────────
# PRUEBAS CA4 / PDGTRAZDSA-156: Regla de correlación entre usuarios sobre el mismo dataset
# ─────────────────────────────────────────────────────────────────────────────

def test_regla_correlacion_mismo_dataset_multiples_usuarios(db_conn):
    """
    CA4: Cuando el mismo dataset es accedido por múltiples usuarios distintos
    en una ventana corta (ej. 15 minutos), se genera una alerta de correlación.
    """
    dataset = "HISTORIAS_CLINICAS_CRITICAS.csv"
    ts_base = datetime(2026, 5, 10, 14, 0, 0)

    # Usuario 1 accede a las 14:00
    _insertar_evento_base(db_conn, "usr_medico1", 'CONSULTA', ts_base.isoformat(), dataset=dataset)

    # Usuario 2 accede 5 minutos después a las 14:05 sobre el MISMO dataset
    evento_usuario2 = {
        'usuario_id': 'usr_medico2',
        'tipo_accion': 'CONSULTA',
        'timestamp': (ts_base + timedelta(minutes=5)).isoformat(),
        'dataset_nombre': dataset
    }

    # Evaluar correlación con umbral de 2 usuarios en ventana de 15 min
    anomalo, motivo = evaluar_regla_correlacion(
        db_conn, evento_usuario2, ventana_minutos=15, umbral_usuarios=2
    )
    assert anomalo
    assert "Alerta de correlación" in motivo
    assert dataset in motivo
    assert "usr_medico1" in motivo
    assert "usr_medico2" in motivo


def test_regla_correlacion_no_se_dispara_con_un_solo_usuario(db_conn):
    """
    CA4: Si un único usuario realiza varios accesos al mismo dataset, no debe
    dispararse una alerta de correlación multiusuario.
    """
    dataset = "dataset_comun.csv"
    ts_base = datetime(2026, 5, 10, 10, 0, 0)
    usr = "usr_solo"

    _insertar_evento_base(db_conn, usr, 'CONSULTA', ts_base.isoformat(), dataset=dataset)

    evento_mismo_usuario = {
        'usuario_id': usr,
        'tipo_accion': 'CONSULTA',
        'timestamp': (ts_base + timedelta(minutes=2)).isoformat(),
        'dataset_nombre': dataset
    }
    anomalo, motivo = evaluar_regla_correlacion(
        db_conn, evento_mismo_usuario, ventana_minutos=15, umbral_usuarios=2
    )
    assert not anomalo
    assert motivo is None


# ─────────────────────────────────────────────────────────────────────────────
# PRUEBAS INTEGRADAS: Evaluación completa y marcado de nivel_alerta = ANOMALIA
# ─────────────────────────────────────────────────────────────────────────────

def test_evaluacion_integrada_marca_nivel_alerta_anomalia(db_conn):
    """
    DOD / CA2-CA4: La función integrada evalúa las reglas y asigna automáticamente
    nivel_alerta = 'ANOMALIA' con el motivo explicativo correspondiente.
    """
    usr = "dr_especialista"
    # Histórico de horario diurno y exportación promedio de 50 filas
    _insertar_evento_base(db_conn, usr, 'EXPORTACION', '2026-05-01T10:00:00', filas=50)
    _insertar_evento_base(db_conn, usr, 'EXPORTACION', '2026-05-02T10:00:00', filas=50)
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-03T11:00:00')
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-04T12:00:00')
    _insertar_evento_base(db_conn, usr, 'CONSULTA', '2026-05-05T13:00:00')

    # Evento con anomalía de volumen (500 filas vs 50 promedio) y horario inusual (03:00 AM)
    evento_sospechoso = {
        'usuario_id': usr,
        'tipo_accion': 'EXPORTACION',
        'timestamp': '2026-05-06T03:00:00',
        'dataset_nombre': 'pacientes_oncologia.csv',
        'filas_exportadas': 500,
        'nivel_alerta': 'NORMAL'
    }

    es_anomalo, evento_enriquecido, motivos = evaluar_evento_anomalias(
        db_conn, evento_sospechoso
    )

    assert es_anomalo is True
    assert evento_enriquecido['nivel_alerta'] == 'ANOMALIA'
    assert len(motivos) >= 2  # Disparó volumen y horario
    assert "Volumen anómalo" in evento_enriquecido['motivo_alerta']
    assert "Horario inusual" in evento_enriquecido['motivo_alerta']


def test_persistencia_y_consulta_eventos_anomalos_ca5(db_conn):
    """
    CA5 / PDGTRAZDSA-157: Los eventos marcados como ANOMALIA se insertan correctamente
    con su hash de integridad válido y pueden ser consultados y filtrados.
    """
    evento_anomalo = {
        'usuario_id': 'auditor_test',
        'sesion_id': 'SES_ANOMALIA_01',
        'timestamp': '2026-05-15T02:00:00',
        'tipo_accion': 'EXPORTACION',
        'dataset_nombre': 'vih_confidencial.csv',
        'filas_exportadas': 2500,
        'nivel_alerta': 'ANOMALIA',
        'motivo_alerta': 'Volumen anómalo: 2,500 filas | Horario inusual: 02:00'
    }

    event_id = insert_event(db_conn, evento_anomalo)
    assert event_id is not None

    # Consulta filtrando por nivel_alerta = ANOMALIA
    anomalias = get_anomaly_events(db_conn)
    assert len(anomalias) == 1
    assert anomalias[0]['nivel_alerta'] == 'ANOMALIA'
    assert anomalias[0]['dataset_nombre'] == 'vih_confidencial.csv'
    assert anomalias[0]['hash_integridad'] is not None


# ─────────────────────────────────────────────────────────────────────────────
# PRUEBAS DE VISTA FLASK Y FILTRADO POR SOLO ANOMALÍAS (CA5)
# ─────────────────────────────────────────────────────────────────────────────

def test_endpoint_eventos_filtro_solo_anomalias(monkeypatch, db_conn, tmp_path):
    """
    CA5: Verifica que la ruta /eventos con ?solo_anomalias=1 o ?nivel_alerta=ANOMALIA
    filtre únicamente los eventos clasificados con nivel_alerta='ANOMALIA'.
    """
    from app import app

    # Insertar eventos con distintos niveles de alerta
    insert_event(db_conn, {
        'usuario_id': 'u_norm', 'sesion_id': 's1', 'timestamp': '2026-05-01T10:00:00',
        'tipo_accion': 'CONSULTA', 'nivel_alerta': 'NORMAL'
    })
    insert_event(db_conn, {
        'usuario_id': 'u_crit', 'sesion_id': 's2', 'timestamp': '2026-05-01T11:00:00',
        'tipo_accion': 'ACCESO_DENEGADO', 'nivel_alerta': 'CRITICO'
    })
    insert_event(db_conn, {
        'usuario_id': 'u_anom', 'sesion_id': 's3', 'timestamp': '2026-05-01T03:00:00',
        'tipo_accion': 'EXPORTACION', 'dataset_nombre': 'pacientes.csv',
        'nivel_alerta': 'ANOMALIA', 'motivo_alerta': 'Horario inusual'
    })

    clonar_bd_web(db_conn, tmp_path, monkeypatch)

    app.config['TESTING'] = True
    client = app.test_client()

    crear_sesion_web(client, 'admin_tester', 'ADMIN', 'Admin Tester')

    # 1. Petición con solo_anomalias=1
    response = client.get('/eventos?solo_anomalias=1')
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Debe contener el evento anómalo y la etiqueta visual
    assert "u_anom" in html
    assert "badge-anomalia" in html
    assert "fila-anomalia" in html

    # No debe contener el usuario normal ni el crítico
    assert "u_norm" not in html
    assert "u_crit" not in html


def test_simulacion_completa_tres_reglas_datos_de_prueba(db_conn):
    """
    DOD: Las tres reglas de detección funcionan sobre datos de prueba simulados.
    Se simula la actividad habitual de una institución de salud y se introducen
    eventos anómalos para cada una de las tres reglas.
    """
    # 1. Simulación de actividad normal previa de un grupo de médicos e investigadores
    medicos = ["dr_alvarez", "dra_betancur", "dr_castro"]
    for idx, med in enumerate(medicos):
        # 5 días de actividad diurna con consultas normales y exportaciones pequeñas (~40 filas)
        for dia in range(1, 6):
            fecha = f"2026-05-{dia:02d}"
            _insertar_evento_base(db_conn, med, 'CONSULTA', f"{fecha}T09:00:00", dataset=f"pacientes_{med}.csv")
            _insertar_evento_base(db_conn, med, 'TRANSFORMACION', f"{fecha}T11:00:00", dataset=f"pacientes_{med}.csv")
            _insertar_evento_base(db_conn, med, 'EXPORTACION', f"{fecha}T15:00:00", dataset=f"pacientes_{med}.csv", filas=40)

    # 2. Evento simulado para Regla 1 (Volumen anómalo): dr_alvarez exporta 5,000 registros
    ev_volumen = {
        'usuario_id': 'dr_alvarez',
        'sesion_id': 'SES_SIM_VOL',
        'timestamp': '2026-05-06T10:00:00',
        'tipo_accion': 'EXPORTACION',
        'dataset_nombre': 'pacientes_dr_alvarez.csv',
        'filas_exportadas': 5000,
        'nivel_alerta': 'NORMAL'
    }
    es_anom_vol, ev_res_vol, motivos_vol = evaluar_evento_anomalias(db_conn, ev_volumen)
    assert es_anom_vol is True
    assert ev_res_vol['nivel_alerta'] == 'ANOMALIA'
    assert any("Volumen anómalo" in m for m in motivos_vol)
    insert_event(db_conn, ev_res_vol)

    # 3. Evento simulado para Regla 2 (Horario inusual): dra_betancur accede a la 01:15 AM
    ev_horario = {
        'usuario_id': 'dra_betancur',
        'sesion_id': 'SES_SIM_HOR',
        'timestamp': '2026-05-06T01:15:00',
        'tipo_accion': 'CONSULTA',
        'dataset_nombre': 'pacientes_dra_betancur.csv',
        'nivel_alerta': 'NORMAL'
    }
    es_anom_hor, ev_res_hor, motivos_hor = evaluar_evento_anomalias(db_conn, ev_horario)
    assert es_anom_hor is True
    assert ev_res_hor['nivel_alerta'] == 'ANOMALIA'
    assert any("Horario inusual" in m for m in motivos_hor)
    insert_event(db_conn, ev_res_hor)

    # 4. Evento simulado para Regla 3 (Correlación sobre mismo dataset):
    # dr_castro accede al dataset crítico 'GENETICA_ONCOLOGICA.csv'
    dataset_sensible = "GENETICA_ONCOLOGICA.csv"
    _insertar_evento_base(db_conn, "dr_alvarez", 'CONSULTA', '2026-05-06T14:10:00', dataset=dataset_sensible)
    
    # dra_betancur accede 3 minutos después al mismo dataset sensible
    ev_correlacion = {
        'usuario_id': 'dra_betancur',
        'sesion_id': 'SES_SIM_CORR',
        'timestamp': '2026-05-06T14:13:00',
        'tipo_accion': 'CONSULTA',
        'dataset_nombre': dataset_sensible,
        'nivel_alerta': 'NORMAL'
    }
    es_anom_corr, ev_res_corr, motivos_corr = evaluar_evento_anomalias(
        db_conn, ev_correlacion, ventana_correlacion_minutos=15, umbral_usuarios_correlacion=2
    )
    assert es_anom_corr is True
    assert ev_res_corr['nivel_alerta'] == 'ANOMALIA'
    assert any("Alerta de correlación" in m for m in motivos_corr)
    insert_event(db_conn, ev_res_corr)

    # 5. Verificación de persistencia de las 3 anomalías en la base central
    anomalias_detectadas = get_anomaly_events(db_conn)
    assert len(anomalias_detectadas) == 3
    for anomalia in anomalias_detectadas:
        assert anomalia['nivel_alerta'] == 'ANOMALIA'
        assert anomalia['motivo_alerta'] is not None


def test_dashboard_metrica_anomalias(monkeypatch, db_conn, tmp_path):
    """
    CA5: Verifica que el dashboard principal calcule y renderice correctamente
    la tarjeta de métricas con el total de anomalías detectadas.
    """
    from app import app

    insert_event(db_conn, {
        'usuario_id': 'dr_test1', 'sesion_id': 's1', 'timestamp': '2026-05-01T10:00:00',
        'tipo_accion': 'CONSULTA', 'nivel_alerta': 'ANOMALIA', 'motivo_alerta': 'Volumen anómalo'
    })
    insert_event(db_conn, {
        'usuario_id': 'dr_test2', 'sesion_id': 's2', 'timestamp': '2026-05-01T02:00:00',
        'tipo_accion': 'CONSULTA', 'nivel_alerta': 'ANOMALIA', 'motivo_alerta': 'Horario inusual'
    })

    clonar_bd_web(db_conn, tmp_path, monkeypatch)

    app.config['TESTING'] = True
    client = app.test_client()

    crear_sesion_web(client, 'auditor_jefe', 'ADMIN', 'Auditor Jefe')

    response = client.get('/dashboard')
    assert response.status_code == 200
    html = response.get_data(as_text=True)

    # Debe contener la tarjeta de Anomalías Detectadas con el conteo
    assert "Anomalías Detectadas" in html
    assert "2 detectadas" in html

