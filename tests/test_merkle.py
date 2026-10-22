"""
tests/test_merkle.py
====================
Pruebas exhaustivas para la Historia de Usuario HU-6.2:
Estructura de Merkle tree y ancla externa de integridad.

Criterios de Aceptación:
  - CA1 (PDGTRAZDSA-146): Construcción del árbol de Merkle agrupado por lotes horarios.
  - CA2 (PDGTRAZDSA-147): Generación y verificación de prueba de Merkle por evento O(log n).
  - CA3 (PDGTRAZDSA-148): Publicación periódica de la raíz en canal externo firmado con Ed25519.
  - CA4 (PDGTRAZDSA-149): Verificación externa que compara raíz recalculada vs publicada y detecta alteraciones.
  - PDGTRAZDSA-150: Endpoints HTTP y control de acceso para auditor/admin.
"""

import json
import os
import shutil
import tempfile
import pytest

from audit_tracer.db import get_connection
from audit_tracer.models.audit_log import insert_event, get_event_by_id
from audit_tracer.merkle import (
    build_merkle_tree,
    generate_merkle_proof,
    verify_merkle_proof,
    build_batch_tree,
    generate_proof_for_event,
    publish_batch_root,
    verify_external_anchor,
    verify_all_anchors,
    get_pending_batch_hours,
    publish_all_pending,
)
from app import app


@pytest.fixture
def temp_anchors_dir():
    """Directorio temporal aislado para archivos de anclaje externo."""
    tmpdir = tempfile.mkdtemp(prefix="test_merkle_anchors_")
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def db_conn():
    """Conexión SQLite en memoria con esquema central."""
    conn = get_connection(":memory:")
    yield conn
    conn.close()


@pytest.fixture
def flask_client():
    """Cliente de prueba Flask autenticado como AUDITOR."""
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    with app.test_client() as client:
        with client.session_transaction() as sess:
            sess["usuario_id"] = "auditor_test"
            sess["rol"] = "AUDITOR"
            sess["nombre"] = "Auditor Externo"
            sess["sesion_id"] = "s_merkle_auditor"
        yield client


@pytest.fixture
def seeded_db(db_conn):
    """
    Base de datos con eventos en dos lotes horarios diferentes:
      - 2026-10-22T10:00:00 (4 eventos)
      - 2026-10-22T11:00:00 (3 eventos)
    """
    eventos_lote_1 = [
        {"usuario_id": "u1", "sesion_id": "s1", "tipo_accion": "LOGIN", "timestamp": "2026-10-22T10:05:00"},
        {"usuario_id": "u1", "sesion_id": "s1", "tipo_accion": "LECTURA", "timestamp": "2026-10-22T10:15:00"},
        {"usuario_id": "u2", "sesion_id": "s2", "tipo_accion": "TRANSFORMA", "timestamp": "2026-10-22T10:30:00"},
        {"usuario_id": "u1", "sesion_id": "s1", "tipo_accion": "EXPORTA", "timestamp": "2026-10-22T10:55:00"},
    ]
    eventos_lote_2 = [
        {"usuario_id": "u3", "sesion_id": "s3", "tipo_accion": "LOGIN", "timestamp": "2026-10-22T11:10:00"},
        {"usuario_id": "u3", "sesion_id": "s3", "tipo_accion": "LECTURA", "timestamp": "2026-10-22T11:25:00"},
        {"usuario_id": "u3", "sesion_id": "s3", "tipo_accion": "EXPORTA", "timestamp": "2026-10-22T11:50:00"},
    ]

    ids_1 = [insert_event(db_conn, ev) for ev in eventos_lote_1]
    ids_2 = [insert_event(db_conn, ev) for ev in eventos_lote_2]

    return {
        "conn": db_conn,
        "lote_1": {"batch_hour": "2026-10-22T10", "ids": ids_1},
        "lote_2": {"batch_hour": "2026-10-22T11", "ids": ids_2},
    }


# ============================================================================
# CA1: Construcción del árbol de Merkle (PDGTRAZDSA-146)
# ============================================================================

class TestCA1ConstruccionMerkleTree:
    """Verifica que los eventos se organicen en estructura de árbol de Merkle."""

    def test_arbol_vacio_retorna_raiz_valida(self):
        """Un árbol sin eventos retorna un hash consistente y 0 hojas."""
        tree = build_merkle_tree([])
        assert tree["leaf_count"] == 0
        assert len(tree["root"]) == 64
        assert isinstance(tree["levels"], list)

    def test_arbol_con_un_elemento(self):
        """Con un solo evento, la raíz coincide con el hash del único evento."""
        h1 = "a" * 64
        tree = build_merkle_tree([h1])
        assert tree["leaf_count"] == 1
        assert tree["root"] == h1

    def test_arbol_par_e_impar_hojas(self):
        """
        Verifica construcción con número par e impar de hojas
        (en número impar duplica la última hoja como en Bitcoin/Ethereum).
        """
        h_par = [f"{i:064x}" for i in range(1, 5)]   # 4 hojas
        h_impar = [f"{i:064x}" for i in range(1, 4)] # 3 hojas

        tree_par = build_merkle_tree(h_par)
        tree_impar = build_merkle_tree(h_impar)

        assert tree_par["leaf_count"] == 4
        assert len(tree_par["root"]) == 64
        assert len(tree_par["levels"]) == 3  # nivel 0 (4), nivel 1 (2), nivel 2 (1)

        assert tree_impar["leaf_count"] == 3
        assert len(tree_impar["root"]) == 64

    def test_build_batch_tree_desde_bd(self, seeded_db):
        """Agrupa los eventos por lote horario y construye el árbol."""
        conn = seeded_db["conn"]
        tree_1 = build_batch_tree(conn, "2026-10-22T10")
        assert tree_1["leaf_count"] == 4
        assert len(tree_1["root"]) == 64

        tree_2 = build_batch_tree(conn, "2026-10-22T11")
        assert tree_2["leaf_count"] == 3
        assert len(tree_2["root"]) == 64
        assert tree_1["root"] != tree_2["root"]


# ============================================================================
# CA2: Prueba de Merkle por evento sin recorrer todo el historial (PDGTRAZDSA-147)
# ============================================================================

class TestCA2PruebaMerkleIndividual:
    """Verifica la generación y validación de la prueba de Merkle por evento."""

    def test_generar_y_verificar_prueba_valida(self, seeded_db):
        """Genera la prueba de un evento y la verifica exitosamente."""
        conn = seeded_db["conn"]
        event_id = seeded_db["lote_1"]["ids"][2]

        proof = generate_proof_for_event(conn, event_id)
        assert proof is not None
        assert proof["event_id"] == event_id
        assert proof["batch_hour"] == "2026-10-22T10"
        assert len(proof["proof"]) > 0  # longitud O(log n)
        assert "root" in proof

        # Verificación O(log n) sin consultar BD ni recorrer historial
        es_valido = verify_merkle_proof(proof)
        assert es_valido is True

    def test_prueba_falla_si_se_altera_leaf_hash(self, seeded_db):
        """Si un atacante altera el hash de la hoja, la prueba de Merkle falla."""
        conn = seeded_db["conn"]
        event_id = seeded_db["lote_1"]["ids"][0]
        proof = generate_proof_for_event(conn, event_id)

        # Alteración maliciosa del leaf_hash
        proof["leaf_hash"] = "f" * 64
        assert verify_merkle_proof(proof) is False

    def test_prueba_falla_si_se_altera_hermano_en_camino(self, seeded_db):
        """Si un nodo intermedio de la prueba es alterado, la verificación falla."""
        conn = seeded_db["conn"]
        event_id = seeded_db["lote_1"]["ids"][1]
        proof = generate_proof_for_event(conn, event_id)

        # Alteración de un paso del camino
        step = proof["proof"][0]
        step["sibling"] = "0" * 64
        assert verify_merkle_proof(proof) is False


# ============================================================================
# CA3: Publicación periódica en canal externo (PDGTRAZDSA-148)
# ============================================================================

class TestCA3PublicacionCanalExterno:
    """Verifica que la raíz se publique y firme en un canal externo."""

    def test_publicar_raiz_lote_crea_archivo_firmado(self, seeded_db, temp_anchors_dir):
        """Publica el anclaje en el directorio externo con firma digital."""
        conn = seeded_db["conn"]
        batch_hour = "2026-10-22T10"

        anchor = publish_batch_root(conn, batch_hour, anchors_dir=temp_anchors_dir)
        assert anchor["batch_hour"] == batch_hour
        assert anchor["leaf_count"] == 4
        assert len(anchor["root"]) == 64
        assert anchor["signature"] is not None

        # Verificar que el archivo existe en el canal externo
        archivo_esperado = os.path.join(temp_anchors_dir, f"merkle_{batch_hour}.json")
        assert os.path.isfile(archivo_esperado)
        assert os.path.isfile(anchor["_file_path"])

        with open(archivo_esperado, "r", encoding="utf-8") as f:
            contenido = json.load(f)
        assert contenido["batch_hour"] == batch_hour
        assert contenido["root"] == anchor["root"]

    def test_get_pending_batch_hours_detecta_lotes_sin_publicar(self, seeded_db, temp_anchors_dir):
        """Detecta qué lotes horarios tienen eventos pero aún no tienen ancla externa."""
        conn = seeded_db["conn"]
        pendientes = get_pending_batch_hours(conn, anchors_dir=temp_anchors_dir)
        assert "2026-10-22T10" in pendientes
        assert "2026-10-22T11" in pendientes

        # Publicar uno de ellos
        publish_batch_root(conn, "2026-10-22T10", anchors_dir=temp_anchors_dir)
        pendientes_post = get_pending_batch_hours(conn, anchors_dir=temp_anchors_dir)
        assert "2026-10-22T10" not in pendientes_post
        assert "2026-10-22T11" in pendientes_post

    def test_publish_all_pending(self, seeded_db, temp_anchors_dir):
        """Publica de una sola pasada todos los lotes pendientes."""
        conn = seeded_db["conn"]
        publicados = publish_all_pending(conn, anchors_dir=temp_anchors_dir)
        assert len(publicados) == 2

        pendientes = get_pending_batch_hours(conn, anchors_dir=temp_anchors_dir)
        assert len(pendientes) == 0


# ============================================================================
# CA4: Verificación externa contra raíz recalculada y detección de alteraciones (PDGTRAZDSA-149)
# ============================================================================

class TestCA4VerificacionExternaYAlteracion:
    """Verifica que la función externa detecte alteraciones posteriores."""

    def test_verificacion_exitosa_sin_alteraciones(self, seeded_db, temp_anchors_dir):
        """Cuando no hay modificaciones, la verificación externa es exitosa."""
        conn = seeded_db["conn"]
        batch_hour = "2026-10-22T10"
        publish_batch_root(conn, batch_hour, anchors_dir=temp_anchors_dir)

        resultado = verify_external_anchor(conn, batch_hour, anchors_dir=temp_anchors_dir)
        assert resultado["integrity_ok"] is True
        assert resultado["leaf_count_match"] is True
        assert resultado["signature_valid"] is True
        assert resultado["published_root"] == resultado["recalculated_root"]

    def test_detecta_modificacion_de_evento_en_bd(self, seeded_db, temp_anchors_dir):
        """
        Simula que un atacante con acceso administrativo directo desactiva
        los triggers de la BD y modifica un evento. La verificación externa contra
        el anclaje independiente debe detectar la alteración inmediatamente.
        """
        conn = seeded_db["conn"]
        batch_hour = "2026-10-22T10"
        publish_batch_root(conn, batch_hour, anchors_dir=temp_anchors_dir)

        # Ataque con privilegios administrativos (bypasseando triggers)
        event_id = seeded_db["lote_1"]["ids"][1]
        cursor = conn.cursor()
        cursor.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_update")
        cursor.execute("DROP TRIGGER IF EXISTS trg_audit_log_central_no_update")
        cursor.execute(
            "UPDATE audit_log SET hash_integridad = 'badc0ffee' WHERE event_id = ?",
            (event_id,)
        )
        conn.commit()

        # Verificación externa debe detectar la discordancia
        resultado = verify_external_anchor(conn, batch_hour, anchors_dir=temp_anchors_dir)
        assert resultado["integrity_ok"] is False
        assert resultado["published_root"] != resultado["recalculated_root"]
        assert "ALTERACIÓN DETECTADA" in resultado["details"]

    def test_detecta_eliminacion_de_evento_en_bd(self, seeded_db, temp_anchors_dir):
        """
        Simula que un atacante administrativo elimina un registro para ocultar su rastro.
        La verificación externa detecta la disparidad en número de hojas y raíz.
        """
        conn = seeded_db["conn"]
        batch_hour = "2026-10-22T10"
        publish_batch_root(conn, batch_hour, anchors_dir=temp_anchors_dir)

        # Ataque con privilegios administrativos (bypasseando triggers)
        event_id = seeded_db["lote_1"]["ids"][0]
        cursor = conn.cursor()
        cursor.execute("DROP TRIGGER IF EXISTS trg_audit_log_no_delete")
        cursor.execute("DROP TRIGGER IF EXISTS trg_audit_log_central_no_delete")
        cursor.execute("DELETE FROM audit_log WHERE event_id = ?", (event_id,))
        conn.commit()

        resultado = verify_external_anchor(conn, batch_hour, anchors_dir=temp_anchors_dir)
        assert resultado["integrity_ok"] is False
        assert resultado["leaf_count_match"] is False
        assert resultado["current_leaf_count"] == 3
        assert resultado["published_leaf_count"] == 4


# ============================================================================
# PDGTRAZDSA-150: Endpoints Flask y Vistas
# ============================================================================

class TestEndpointsMerkle:
    """Verifica los endpoints HTTP para consulta y verificación de Merkle."""

    def test_endpoint_verificar_evento_individual(self, flask_client, seeded_db, monkeypatch):
        """GET /merkle/verificar/<event_id> retorna la prueba y su validez."""
        monkeypatch.setattr("app.get_db", lambda: seeded_db["conn"])
        event_id = seeded_db["lote_1"]["ids"][0]

        res = flask_client.get(f"/merkle/verificar/{event_id}")
        assert res.status_code == 200
        data = res.get_json()
        assert data["event_id"] == event_id
        assert data["integrity_ok"] is True
        assert data["batch_hour"] == "2026-10-22T10"
        assert "merkle_root" in data

    def test_endpoint_lote_merkle(self, flask_client, seeded_db, monkeypatch):
        """GET /merkle/lote/<batch_hour> retorna la raíz y total de hojas."""
        monkeypatch.setattr("app.get_db", lambda: seeded_db["conn"])

        res = flask_client.get("/merkle/lote/2026-10-22T10")
        assert res.status_code == 200
        data = res.get_json()
        assert data["batch_hour"] == "2026-10-22T10"
        assert data["leaf_count"] == 4
        assert len(data["root"]) == 64

    def test_endpoint_publicar_restringido_a_roles_autorizados(self, seeded_db, monkeypatch):
        """POST /merkle/publicar rechaza usuarios sin rol ADMIN ni AUDITOR (ej. ANALISTA)."""
        app.config["TESTING"] = True
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["usuario_id"] = "analista_test"
                sess["rol"] = "ANALISTA"

            res = client.post("/merkle/publicar", json={"batch_hour": "2026-10-22T10"})
            assert res.status_code == 403

    def test_endpoint_verificar_ancla_vista_get(self, flask_client, seeded_db, monkeypatch):
        """GET /merkle/verificar-ancla renderiza la pantalla de integridad Merkle."""
        monkeypatch.setattr("app.get_db", lambda: seeded_db["conn"])

        res = flask_client.get("/merkle/verificar-ancla")
        assert res.status_code == 200
        assert b"Integridad Merkle" in res.data
        assert b"Verificar ancla" in res.data
