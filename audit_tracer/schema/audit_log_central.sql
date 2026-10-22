-- ============================================================
-- SISTEMA DE AUDITORÍA DE TRAZABILIDAD
-- Base de datos CENTRAL consolidada (HU-5.4)
-- Motor: SQLite en modo WAL (ver README.md — Base de datos central)
-- ============================================================
-- Esta tabla es estructuralmente compatible con schema/audit_log.sql
-- (el audit_log LOCAL): mismos 13 campos funcionales sobre los que se
-- calcula hash_integridad, para que insert_event()/verify_integrity()
-- operen igual sobre cualquiera de las dos conexiones sin distinguir
-- de cuál se trata.
--
-- Diferencias respecto al schema local:
--   evento_uuid — identificador único global del evento (CA1), generado
--                 en Python al momento de insertar (ver
--                 audit_tracer/models/audit_log.py::_prepare_event()).
--                 No participa del cálculo de hash_integridad: es
--                 metadata de transporte/deduplicación para la futura
--                 sincronización HU-5.8, no parte del evento auditado.
--                 Sirve para reintentos idempotentes: si el mismo
--                 evento se reenvía dos veces, el UNIQUE evita duplicarlo.
--
-- Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_log (

    -- IDENTIFICADOR ÚNICO DEL EVENTO (en esta base)
    event_id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    -- Autoincremental y único solo dentro de ESTA base. No sirve como
    -- clave de deduplicación entre orígenes distintos — para eso existe
    -- evento_uuid.

    -- IDENTIFICADOR ÚNICO GLOBAL DEL EVENTO (HU-5.4 CA1)
    evento_uuid       TEXT     UNIQUE NOT NULL,
    -- UUID4 generado en Python al construir el evento (mismo valor si el
    -- evento también se escribió en la base local — ver insert_event_dual()).
    -- Permite que HU-5.8 reintente una sincronización fallida sin crear
    -- eventos duplicados en la central (idempotencia).

    -- IDENTIFICACIÓN DEL ACTOR
    usuario_id        TEXT     NOT NULL,
    -- ID único del usuario que ejecutó la acción.
    -- Si no es identificable: 'DESCONOCIDO'.
    -- Con múltiples orígenes consolidados en una sola tabla, este campo
    -- es lo que permite trazar el usuario emisor de cada evento (HU-5.4 CA1).
    -- Exigido por HIPAA §164.312(b)

    sesion_id         TEXT     NOT NULL,
    -- UUID único por sesión de trabajo.
    -- Vincula todos los eventos de una misma ejecución.

    -- TEMPORALIDAD
    timestamp         TEXT     NOT NULL,
    -- Fecha y hora en formato ISO 8601: 'YYYY-MM-DDTHH:MM:SS.ffffff'
    -- Exigido por HIPAA §164.312(b)

    -- TIPO DE EVENTO
    tipo_accion       TEXT     NOT NULL,
    -- Mismos valores que en el audit_log local: CARGA, CONSULTA,
    -- TRANSFORMACION, EXPORTACION, MODELADO, MODELADO_FALLIDO,
    -- ACCESO_FALLIDO, INICIO_SESION, CIERRE_SESION, SESION_INTERRUMPIDA,
    -- CAMBIO_ROL/MODIFICACION_ROL, CREACION_USUARIO, ACCESO_DENEGADO,
    -- INTENTO_MODIFICACION, INTENTO_ELIMINACION.

    -- CONTEXTO DEL DATO AFECTADO
    dataset_nombre    TEXT,
    columnas_afectadas TEXT,
    ruta_destino      TEXT,

    filas_exportadas  INTEGER,
    -- Número de filas incluidas en una exportación (HU-2.3 CA2).

    sobrescritura     INTEGER,
    -- Indicador de sobrescritura de archivo en exportaciones (0/1) (HU-2.3 CA3).

    -- CONTEXTO DE EJECUCIÓN
    contexto_ejecucion TEXT,

    -- INFORMACIÓN DE FALLOS Y ALERTAS
    motivo_fallo      TEXT,

    nivel_alerta      TEXT     DEFAULT 'NORMAL',
    -- Valores: 'NORMAL', 'ADVERTENCIA', 'CRITICO'

    motivo_alerta     TEXT,

    -- INTEGRIDAD DEL REGISTRO (HU-5.4 CA3 — mismo mecanismo que el local)
    hash_integridad   TEXT     NOT NULL,
    -- SHA-256 calculado en Python (hash_event()) sobre los 13 campos
    -- funcionales. evento_uuid y event_id quedan fuera del cálculo,
    -- igual que en el audit_log local — así el hash de un evento es
    -- idéntico sin importar en qué base se calculó o insertó.

    firma_digital     TEXT
    -- HU-6.1 CA4: Firma digital Ed25519 generada por la llave privada del usuario.
    -- Base64url sin padding, ~86 caracteres. Almacenada para verificación forense.
);

-- ============================================================
-- TABLA DE INTENTOS BLOQUEADOS (HU-5.4 — cierra faltante de HU-3.3)
-- Registra cada intento de UPDATE/DELETE sobre audit_log que fue
-- rechazado por los triggers de inmutabilidad de abajo.
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_intentos_bloqueados (
    intento_id        INTEGER  PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT     NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    tipo_intento      TEXT     NOT NULL,   -- 'INTENTO_MODIFICACION' | 'INTENTO_ELIMINACION'
    event_id_objetivo INTEGER  NOT NULL,
    usuario_id        TEXT,
    sesion_id         TEXT,
    nivel_alerta      TEXT     NOT NULL DEFAULT 'CRITICO',
    motivo_alerta     TEXT
);

-- ============================================================
-- TRIGGERS DE INMUTABILIDAD (HU-5.4 CA3, patrón tomado de HU-3.3)
-- Bloquean UPDATE/DELETE sobre audit_log y dejan constancia del
-- intento en audit_intentos_bloqueados antes de rechazar la operación.
--
-- RAISE(FAIL, ...) en lugar de RAISE(ABORT, ...): FAIL aborta la
-- sentencia sin deshacer los efectos de sentencias/triggers previos
-- dentro de la misma transacción, así que el INSERT en
-- audit_intentos_bloqueados sobrevive aunque el UPDATE/DELETE original
-- sea rechazado. Con ABORT, ese INSERT también se revertiría y el
-- intento quedaría sin rastro.
-- ============================================================

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    INSERT INTO audit_intentos_bloqueados (
        tipo_intento, event_id_objetivo, usuario_id, sesion_id, motivo_alerta
    )
    VALUES (
        'INTENTO_MODIFICACION',
        OLD.event_id,
        COALESCE(OLD.usuario_id, 'DESCONOCIDO'),
        COALESCE(OLD.sesion_id, 'SISTEMA'),
        'Intento de UPDATE sobre event_id=' || OLD.event_id || ' bloqueado por trigger de inmutabilidad.'
    );
    SELECT RAISE(FAIL, 'INMUTABILIDAD: No se permite modificar registros de auditoría.');
END;

CREATE TRIGGER IF NOT EXISTS trg_audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    INSERT INTO audit_intentos_bloqueados (
        tipo_intento, event_id_objetivo, usuario_id, sesion_id, motivo_alerta
    )
    VALUES (
        'INTENTO_ELIMINACION',
        OLD.event_id,
        COALESCE(OLD.usuario_id, 'DESCONOCIDO'),
        COALESCE(OLD.sesion_id, 'SISTEMA'),
        'Intento de DELETE sobre event_id=' || OLD.event_id || ' bloqueado por trigger de inmutabilidad.'
    );
    SELECT RAISE(FAIL, 'INMUTABILIDAD: No se permite eliminar registros de auditoría.');
END;

-- ÍNDICES
CREATE INDEX IF NOT EXISTS idx_audit_usuario
    ON audit_log(usuario_id);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp
    ON audit_log(timestamp);

CREATE INDEX IF NOT EXISTS idx_audit_tipo_accion
    ON audit_log(tipo_accion);

CREATE INDEX IF NOT EXISTS idx_audit_sesion
    ON audit_log(sesion_id);

CREATE INDEX IF NOT EXISTS idx_audit_nivel_alerta
    ON audit_log(nivel_alerta);

CREATE INDEX IF NOT EXISTS idx_audit_evento_uuid
    ON audit_log(evento_uuid);
