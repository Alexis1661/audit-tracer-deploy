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
    -- Al llegar a 5 se bloquea la cuenta 15 minutos.

    llave_publica     TEXT
    -- HU-6.1 CA1/CA3: PEM Ed25519 SubjectPublicKeyInfo del usuario.
    -- Null hasta que el usuario se autentique con la libreria actualizada.

);