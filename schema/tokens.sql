-- ============================================================
-- Tabla: tokens_acceso
-- Descripción: Almacenamiento y control de ciclo de vida de
--              tokens personales de acceso de usuarios.
-- ============================================================

CREATE TABLE IF NOT EXISTS tokens_acceso (

    token_id          TEXT     PRIMARY KEY,
    -- Identificador único del token (UUID).

    usuario_id        TEXT     NOT NULL,
    -- ID del usuario propietario del token.
    
    token             TEXT     NOT NULL UNIQUE,
    -- Token criptográficamente seguro (ej. tk_...).

    fecha_creacion    TEXT     NOT NULL,
    -- Fecha y hora de creación en formato ISO 8601 UTC.

    fecha_expiracion  TEXT     NOT NULL,
    -- Fecha y hora de expiración en formato ISO 8601 UTC (por defecto +30 días).

    estado            TEXT     NOT NULL DEFAULT 'ACTIVO',
    -- Estado del token: 'ACTIVO', 'REVOCADO', 'EXPIRADO'.

    creado_por        TEXT     NOT NULL DEFAULT 'LOGIN',
    -- Origen o actor de generación: 'LOGIN', 'ADMIN', 'SISTEMA', etc.

    FOREIGN KEY (usuario_id) REFERENCES usuarios(usuario_id)
);

CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens_acceso(token);
CREATE INDEX IF NOT EXISTS idx_tokens_usuario ON tokens_acceso(usuario_id);
CREATE INDEX IF NOT EXISTS idx_tokens_estado ON tokens_acceso(estado);
