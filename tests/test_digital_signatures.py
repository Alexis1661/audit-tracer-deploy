"""
tests/test_digital_signatures.py
==================================
HU-6.1 — Pruebas unitarias para el módulo de firmas digitales Ed25519.

Criterios de Aceptación cubiertos:
  CA2 — firma_válida: sign_event() y add_signature_to_event() producen una
         firma que verify_event_signature() acepta.
  CA3 — firma_inválida: verify_event_signature() rechaza firmas inválidas
         (llave incorrecta) y eventos manipulados tras la firma.
  CA4 — firma_almacenada: _execute_insert incluye firma_digital en el INSERT.
  CA5 — verify_signature(): función de verificación posterior sobre la BD.

Sub-tareas cubiertas:
  PDGTRAZDSA-140: generación y carga del par de llaves.
  PDGTRAZDSA-141: sign_event() / add_signature_to_event().
  PDGTRAZDSA-142: verify_event_signature().
  PDGTRAZDSA-143: verify_signature().

DOD — Pruebas unitarias cubren: firma válida, firma inválida,
       evento manipulado tras la firma.
"""

import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from audit_tracer.digital_signatures import (
    _canonical_message,
    add_signature_to_event,
    generate_keypair,
    get_or_create_user_keypair,
    load_private_key,
    load_public_key,
    public_key_from_pem,
    public_key_to_pem,
    save_private_key,
    save_public_key,
    sign_event,
    verify_event_signature,
    verify_signature,
)
from audit_tracer.models.audit_log import insert_event


# ──────────────────────────────────────────────────────────────
# FIXTURES
# ──────────────────────────────────────────────────────────────

@pytest.fixture
def keypair():
    """Par de llaves Ed25519 generado fresco para cada test."""
    return generate_keypair()


@pytest.fixture
def evento_base():
    """Evento mínimo válido con evento_uuid."""
    return {
        "evento_uuid": str(uuid.uuid4()),
        "usuario_id": "usuario-test-123",
        "sesion_id": str(uuid.uuid4()),
        "timestamp": datetime.utcnow().isoformat(),
        "tipo_accion": "CONSULTA",
        "dataset_nombre": "PATIENTS.csv",
        "columnas_afectadas": '["subject_id","diagnosis"]',
        "ruta_destino": None,
        "filas_exportadas": None,
        "sobrescritura": None,
        "contexto_ejecucion": "test_digital_signatures.py",
        "motivo_fallo": None,
        "nivel_alerta": "NORMAL",
        "motivo_alerta": None,
    }


@pytest.fixture
def db_conn(tmp_path):
    """Conexión SQLite en memoria con schema audit_log que incluye firma_digital."""
    conn = sqlite3.connect(":memory:")
    conn.executescript("""
        CREATE TABLE audit_log (
            event_id          INTEGER PRIMARY KEY AUTOINCREMENT,
            evento_uuid       TEXT    UNIQUE NOT NULL,
            usuario_id        TEXT    NOT NULL,
            sesion_id         TEXT    NOT NULL,
            timestamp         TEXT    NOT NULL,
            tipo_accion       TEXT    NOT NULL,
            dataset_nombre    TEXT,
            columnas_afectadas TEXT,
            ruta_destino      TEXT,
            filas_exportadas  INTEGER,
            sobrescritura     INTEGER,
            contexto_ejecucion TEXT,
            motivo_fallo      TEXT,
            nivel_alerta      TEXT    DEFAULT 'NORMAL',
            motivo_alerta     TEXT,
            hash_integridad   TEXT    NOT NULL,
            firma_digital     TEXT
        );
    """)
    conn.commit()
    return conn


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-140 — Generación y almacenamiento de llaves
# ──────────────────────────────────────────────────────────────

class TestGeneracionLlaves:
    """PDGTRAZDSA-140 — Generación y almacenamiento seguro del par de llaves."""

    def test_generate_keypair_returns_valid_pair(self):
        """generate_keypair() devuelve un par de llaves Ed25519 funcional."""
        private_key, public_key = generate_keypair()
        assert private_key is not None
        assert public_key is not None

    def test_public_key_from_private(self):
        """La llave pública derivada de la privada puede verificar firmas de esa privada."""
        private_key, public_key = generate_keypair()
        mensaje = b"test-message"
        raw_sig = private_key.sign(mensaje)
        # No debe lanzar si la firma es correcta
        public_key.verify(raw_sig, mensaje)

    def test_save_and_load_private_key(self, tmp_path):
        """La llave privada guardada en disco se carga correctamente."""
        private_key, _ = generate_keypair()
        save_private_key(private_key, tmp_path)
        loaded = load_private_key(tmp_path)
        assert loaded is not None
        # La llave cargada debe producir las mismas firmas que la original.
        mensaje = b"prueba-carga-privada"
        assert private_key.sign(mensaje) == loaded.sign(mensaje)

    def test_save_and_load_public_key(self, tmp_path):
        """La llave pública guardada en disco se carga correctamente."""
        _, public_key = generate_keypair()
        save_public_key(public_key, tmp_path)
        loaded = load_public_key(tmp_path)
        assert loaded is not None
        pem_original = public_key_to_pem(public_key)
        pem_cargada = public_key_to_pem(loaded)
        assert pem_original == pem_cargada

    def test_load_private_key_returns_none_if_missing(self, tmp_path):
        """load_private_key() devuelve None si no existe el archivo."""
        assert load_private_key(tmp_path) is None

    def test_get_or_create_generates_on_first_call(self, tmp_path):
        """get_or_create_user_keypair() genera un par nuevo si no existe."""
        private_key, public_key = get_or_create_user_keypair(tmp_path)
        assert private_key is not None
        assert public_key is not None

    def test_get_or_create_reuses_existing_key(self, tmp_path):
        """get_or_create_user_keypair() reutiliza el par existente en llamadas posteriores."""
        priv1, pub1 = get_or_create_user_keypair(tmp_path)
        priv2, pub2 = get_or_create_user_keypair(tmp_path)
        # Misma llave privada → mismo PEM de llave pública
        assert public_key_to_pem(pub1) == public_key_to_pem(pub2)

    def test_public_key_pem_roundtrip(self):
        """public_key_to_pem / public_key_from_pem son operaciones inversas."""
        _, public_key = generate_keypair()
        pem = public_key_to_pem(public_key)
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        restored = public_key_from_pem(pem)
        assert public_key_to_pem(restored) == pem


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-141 — Firma de eventos
# ──────────────────────────────────────────────────────────────

class TestFirmaEventos:
    """PDGTRAZDSA-141 — Lógica de firma en la librería antes del envío."""

    def test_sign_event_returns_string(self, keypair, evento_base):
        """sign_event() devuelve un string no vacío."""
        private_key, _ = keypair
        firma = sign_event(evento_base, private_key)
        assert isinstance(firma, str)
        assert len(firma) > 0

    def test_sign_event_is_base64url(self, keypair, evento_base):
        """La firma es Base64url válido (sin padding)."""
        import base64
        private_key, _ = keypair
        firma = sign_event(evento_base, private_key)
        # No debe tener '=' de padding
        assert '=' not in firma
        # Debe decodificarse correctamente con padding restaurado
        padding = '=' * (-len(firma) % 4)
        decoded = base64.urlsafe_b64decode(firma + padding)
        assert len(decoded) == 64  # Ed25519 firma = 64 bytes

    def test_sign_event_determinista(self, keypair, evento_base):
        """Ed25519 produce la misma firma para el mismo mensaje y llave."""
        private_key, _ = keypair
        firma1 = sign_event(evento_base, private_key)
        firma2 = sign_event(evento_base, private_key)
        assert firma1 == firma2

    def test_sign_event_falla_sin_evento_uuid(self, keypair):
        """sign_event() lanza ValueError si el evento no tiene evento_uuid."""
        private_key, _ = keypair
        evento_sin_uuid = {"usuario_id": "u1", "tipo_accion": "CONSULTA"}
        with pytest.raises(ValueError, match="evento_uuid"):
            sign_event(evento_sin_uuid, private_key)

    def test_add_signature_to_event_no_muta_original(self, keypair, evento_base):
        """add_signature_to_event() devuelve una copia: no muta el dict original."""
        private_key, _ = keypair
        original = dict(evento_base)
        firmado = add_signature_to_event(evento_base, private_key)
        assert "firma_digital" not in evento_base  # no mutado
        assert evento_base == original
        assert "firma_digital" in firmado

    def test_add_signature_to_event_incluye_campo(self, keypair, evento_base):
        """add_signature_to_event() añade el campo firma_digital al evento."""
        private_key, _ = keypair
        firmado = add_signature_to_event(evento_base, private_key)
        assert firmado.get("firma_digital") is not None

    def test_firma_diferente_para_eventos_distintos(self, keypair, evento_base):
        """Dos eventos con distintos campos producen firmas distintas."""
        private_key, _ = keypair
        evento2 = dict(evento_base)
        evento2["evento_uuid"] = str(uuid.uuid4())
        firma1 = sign_event(evento_base, private_key)
        firma2 = sign_event(evento2, private_key)
        assert firma1 != firma2


# ──────────────────────────────────────────────────────────────
# PDGTRAZDSA-142 — Validación de firma en el servidor
# ──────────────────────────────────────────────────────────────

class TestValidacionFirma:
    """PDGTRAZDSA-142 — Lógica de validación de firma en el servidor central."""

    # ── CA2: firma válida ──────────────────────────────────────────────────

    def test_firma_valida_verificacion_exitosa(self, keypair, evento_base):
        """CA2/CA3 — Un evento firmado con la llave privada correcta se verifica."""
        private_key, public_key = keypair
        firmado = add_signature_to_event(evento_base, private_key)
        pem = public_key_to_pem(public_key)
        assert verify_event_signature(firmado, pem) is True

    # ── CA3: firma inválida (llave incorrecta) ─────────────────────────────

    def test_firma_invalida_llave_incorrecta(self, evento_base):
        """CA3 — Una firma producida con llave A no se verifica con llave B."""
        private_key_a, _ = generate_keypair()
        _, public_key_b = generate_keypair()

        firmado = add_signature_to_event(evento_base, private_key_a)
        pem_b = public_key_to_pem(public_key_b)

        assert verify_event_signature(firmado, pem_b) is False

    # ── CA3: evento manipulado tras la firma ──────────────────────────────

    def test_evento_manipulado_tras_firma(self, keypair, evento_base):
        """CA3/DOD — Si el evento se modifica tras firmar, la verificación falla."""
        private_key, public_key = keypair
        firmado = add_signature_to_event(evento_base, private_key)
        pem = public_key_to_pem(public_key)

        # Verificación pasa antes de la manipulación
        assert verify_event_signature(firmado, pem) is True

        # Manipular un campo del evento (simula tampering)
        firmado["tipo_accion"] = "EXPORTACION"
        assert verify_event_signature(firmado, pem) is False

    def test_manipulacion_usuario_id(self, keypair, evento_base):
        """CA3 — Cambiar usuario_id tras firmar invalida la firma."""
        private_key, public_key = keypair
        firmado = add_signature_to_event(evento_base, private_key)
        firmado["usuario_id"] = "atacante-99"
        pem = public_key_to_pem(public_key)
        assert verify_event_signature(firmado, pem) is False

    def test_manipulacion_timestamp(self, keypair, evento_base):
        """CA3 — Cambiar timestamp tras firmar invalida la firma."""
        private_key, public_key = keypair
        firmado = add_signature_to_event(evento_base, private_key)
        firmado["timestamp"] = "1970-01-01T00:00:00"
        pem = public_key_to_pem(public_key)
        assert verify_event_signature(firmado, pem) is False

    def test_firma_ausente_retorna_false(self, keypair, evento_base):
        """verify_event_signature() retorna False si no hay firma_digital."""
        _, public_key = keypair
        pem = public_key_to_pem(public_key)
        # Sin firma_digital
        assert verify_event_signature(evento_base, pem) is False

    def test_firma_vacia_retorna_false(self, keypair, evento_base):
        """verify_event_signature() retorna False si firma_digital es string vacío."""
        _, public_key = keypair
        pem = public_key_to_pem(public_key)
        evento_base["firma_digital"] = ""
        assert verify_event_signature(evento_base, pem) is False

    def test_firma_corrupta_retorna_false(self, keypair, evento_base):
        """verify_event_signature() retorna False si la firma está truncada/corrupta."""
        private_key, public_key = keypair
        firmado = add_signature_to_event(evento_base, private_key)
        firmado["firma_digital"] = firmado["firma_digital"][:20]  # truncar
        pem = public_key_to_pem(public_key)
        assert verify_event_signature(firmado, pem) is False

    def test_pem_malformado_retorna_false(self, keypair, evento_base):
        """verify_event_signature() retorna False si el PEM está malformado."""
        private_key, _ = keypair
        firmado = add_signature_to_event(evento_base, private_key)
        assert verify_event_signature(firmado, "no-es-un-pem-valido") is False


# ──────────────────────────────────────────────────────────────
# CA4 — Firma almacenada junto al evento en audit_log
# ──────────────────────────────────────────────────────────────

class TestAlmacenamientoFirma:
    """CA4 — La firma se almacena junto con el evento en audit_log."""

    def test_insert_event_almacena_firma_digital(self, keypair, evento_base, db_conn):
        """CA4 — insert_event() persiste firma_digital en la fila de audit_log."""
        private_key, _ = keypair
        evento_firmado = add_signature_to_event(evento_base, private_key)

        event_id = insert_event(db_conn, evento_firmado)

        db_conn.row_factory = sqlite3.Row
        row = db_conn.execute(
            "SELECT firma_digital FROM audit_log WHERE event_id = ?", (event_id,)
        ).fetchone()
        assert row is not None
        assert row["firma_digital"] == evento_firmado["firma_digital"]

    def test_insert_event_sin_firma_acepta_null(self, evento_base, db_conn):
        """CA4 — insert_event() acepta eventos sin firma (firma_digital = NULL)."""
        event_id = insert_event(db_conn, evento_base)
        db_conn.row_factory = sqlite3.Row
        row = db_conn.execute(
            "SELECT firma_digital FROM audit_log WHERE event_id = ?", (event_id,)
        ).fetchone()
        assert row is not None
        assert row["firma_digital"] is None  # NULL es aceptado


# ──────────────────────────────────────────────────────────────
# CA5 / PDGTRAZDSA-143 — verify_signature() verificación posterior
# ──────────────────────────────────────────────────────────────

class TestVerifySignature:
    """CA5 / PDGTRAZDSA-143 — verify_signature() para verificación posterior."""

    def test_verify_signature_firma_valida(self, keypair, evento_base, db_conn):
        """CA5 — verify_signature() retorna firma_valida=True para firma correcta."""
        private_key, public_key = keypair
        evento_firmado = add_signature_to_event(evento_base, private_key)
        event_id = insert_event(db_conn, evento_firmado)

        pem = public_key_to_pem(public_key)
        resultado = verify_signature(db_conn, event_id, pem)

        assert resultado["event_id"] == event_id
        assert resultado["firma_presente"] is True
        assert resultado["firma_valida"] is True
        assert "válida" in resultado["mensaje"]

    def test_verify_signature_llave_incorrecta(self, keypair, evento_base, db_conn):
        """CA5 — verify_signature() detecta llave pública incorrecta."""
        private_key, _ = keypair
        _, public_key_otra = generate_keypair()

        evento_firmado = add_signature_to_event(evento_base, private_key)
        event_id = insert_event(db_conn, evento_firmado)

        pem_otra = public_key_to_pem(public_key_otra)
        resultado = verify_signature(db_conn, event_id, pem_otra)

        assert resultado["firma_presente"] is True
        assert resultado["firma_valida"] is False
        assert "INVÁLIDA" in resultado["mensaje"]

    def test_verify_signature_sin_firma(self, evento_base, db_conn):
        """CA5 — verify_signature() reporta firma_presente=False si el evento no tiene firma."""
        _, public_key = generate_keypair()
        event_id = insert_event(db_conn, evento_base)

        pem = public_key_to_pem(public_key)
        resultado = verify_signature(db_conn, event_id, pem)

        assert resultado["firma_presente"] is False
        assert resultado["firma_valida"] is False
        assert "no tiene firma" in resultado["mensaje"]

    def test_verify_signature_event_id_inexistente(self, db_conn):
        """CA5 — verify_signature() lanza ValueError para event_id inexistente."""
        _, public_key = generate_keypair()
        pem = public_key_to_pem(public_key)

        with pytest.raises(ValueError, match="event_id=99999"):
            verify_signature(db_conn, 99999, pem)

    def test_verify_signature_devuelve_usuario_id(self, keypair, evento_base, db_conn):
        """CA5 — verify_signature() incluye usuario_id en el resultado."""
        private_key, public_key = keypair
        evento_firmado = add_signature_to_event(evento_base, private_key)
        event_id = insert_event(db_conn, evento_firmado)

        pem = public_key_to_pem(public_key)
        resultado = verify_signature(db_conn, event_id, pem)

        assert resultado["usuario_id"] == evento_base["usuario_id"]
        assert resultado["evento_uuid"] == evento_base["evento_uuid"]


# ──────────────────────────────────────────────────────────────
# DOD extra — Propiedad del mensaje canónico
# ──────────────────────────────────────────────────────────────

class TestMensajeCanónico:
    """Invariantes del mensaje canónico que garantizan determinismo."""

    def test_canonical_message_determinista(self, evento_base):
        """El mismo evento siempre produce el mismo mensaje canónico."""
        m1 = _canonical_message(evento_base)
        m2 = _canonical_message(evento_base)
        assert m1 == m2

    def test_canonical_message_sensible_al_contenido(self, evento_base):
        """Cambiar cualquier campo produce un mensaje distinto."""
        m1 = _canonical_message(evento_base)
        evento2 = dict(evento_base)
        evento2["tipo_accion"] = "EXPORTACION"
        m2 = _canonical_message(evento2)
        assert m1 != m2

    def test_canonical_message_es_bytes_utf8(self, evento_base):
        """_canonical_message() devuelve bytes UTF-8 decodificables."""
        msg = _canonical_message(evento_base)
        assert isinstance(msg, bytes)
        decoded = msg.decode("utf-8")
        assert "usuario_id" in decoded
