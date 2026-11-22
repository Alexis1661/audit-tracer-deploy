-- ============================================================
-- Tabla: usuarios
-- Descripción: Registro de usuarios del sistema con roles
--              y control de acceso.
-- ============================================================

CREATE TABLE IF NOT EXISTS usuarios (

    usuario_id        TEXT     PRIMARY KEY,
    -- ID único del usuario. Generado con UUID.

    email             TEXT     NOT NULL UNIQUE,
    -- Correo electrónico del usuario. No puede repetirse.

    password_hash     TEXT     NOT NULL,
    -- Contraseña almacenada con hash bcrypt. Nunca en texto plano.

    rol               TEXT     NOT NULL,
    -- Roles válidos: 'ADMIN', 'ANALISTA', 'AUDITOR', 'CIENTIFICO_DATOS'

    activo            INTEGER  NOT NULL DEFAULT 1,
    -- 1 = activo, 0 = inactivo/bloqueado

    intentos_fallidos INTEGER  NOT NULL DEFAULT 0,
    -- Contador de intentos fallidos consecutivos.
    -- Al llegar a 5 se bloquea la cuenta 15 minutos (bloqueado_hasta).

    llave_publica     TEXT,
    -- HU-6.1 CA1/CA3: PEM Ed25519 SubjectPublicKeyInfo de la última llave
    -- registrada. El historial completo, con su vigencia, vive en
    -- llaves_publicas (SRV-R2).

    bloqueado_hasta   TEXT
    -- B6 / DSH-D1: fin (UTC ISO 8601) del bloqueo temporal por intentos
    -- fallidos. NULL con activo = 0 significa cuenta deshabilitada por un
    -- ADMIN (no se reactiva sola).

);

-- ============================================================
-- Tabla: llaves_publicas (SRV-S2 / SRV-R2)
-- Historial de llaves Ed25519 por usuario: un usuario puede tener una por
-- equipo (portátil, cada runtime de Colab). Nada se borra: una llave
-- revocada conserva su vigencia para verificar los eventos que firmó.
-- ============================================================
CREATE TABLE IF NOT EXISTS llaves_publicas (
    llave_id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    usuario_id        TEXT     NOT NULL REFERENCES usuarios(usuario_id),
    llave_publica     TEXT     NOT NULL,
    huella            TEXT     NOT NULL,
    -- SHA-256 de la llave (primeros 16 hex) para mostrarla en el dashboard.
    token_id          TEXT,
    -- Token con el que se registró (sin el valor del token).
    registrada_en     TEXT     NOT NULL,
    revocada_en       TEXT,
    revocada_por      TEXT,
    UNIQUE (usuario_id, huella)
);
CREATE INDEX IF NOT EXISTS idx_llaves_usuario ON llaves_publicas(usuario_id);