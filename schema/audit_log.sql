-- ============================================================
-- SISTEMA DE AUDITORÍA DE TRAZABILIDAD
-- Tabla: audit_log
-- Versión: 1.0
-- Descripción: Registro centralizado de todos los eventos
--              auditables sobre datos clínicos sensibles.
-- Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_log (

    -- IDENTIFICADOR ÚNICO DEL EVENTO (en esta base)
    event_id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    -- Clave primaria autogenerada. Nunca puede repetirse ni ser nula.
    -- Única solo dentro de ESTA base; para deduplicar entre esta base
    -- local y la central (HU-5.4) se usa evento_uuid, no este campo.

    -- IDENTIFICADOR ÚNICO GLOBAL DEL EVENTO (HU-5.4 CA1)
    evento_uuid       TEXT     UNIQUE NOT NULL,
    -- UUID4 generado en Python al construir el evento (ver
    -- audit_tracer/models/audit_log.py::_prepare_event()). No participa
    -- del cálculo de hash_integridad. Permite que la futura sincronización
    -- HU-5.8 reintente sin duplicar eventos en la base central.

    -- IDENTIFICACIÓN DEL ACTOR
    usuario_id        TEXT     NOT NULL,
    -- ID único del usuario que ejecutó la acción.
    -- Si no es identificable: 'DESCONOCIDO'
    -- Exigido por HIPAA §164.312(b)

    sesion_id         TEXT     NOT NULL,
    -- UUID único por sesión de trabajo.
    -- Vincula todos los eventos de una misma ejecución.

    -- TEMPORALIDAD
    timestamp         TEXT     NOT NULL,
    -- Fecha y hora en formato ISO 8601: 'YYYY-MM-DDTHH:MM:SS.ffffff'
    -- Ejemplo: '2026-04-14T10:32:15.123456'
    -- Exigido por HIPAA §164.312(b)

    -- TIPO DE EVENTO
    tipo_accion       TEXT     NOT NULL,
    -- Valores permitidos:
    -- CARGA              → pd.read_csv(), pd.read_excel()
    -- CONSULTA           → df[], df.query()
    -- TRANSFORMACION     → dropna(), fillna(), drop(), rename(), apply(), merge()
    -- EXPORTACION        → to_csv(), to_excel(), to_json(), to_parquet()
    -- MODELADO           → model.fit()
    -- MODELADO_FALLIDO   → error durante entrenamiento
    -- ACCESO_FALLIDO     → PermissionError, FileNotFoundError
    -- INICIO_SESION      → import audit_tracer
    -- CIERRE_SESION      → fin normal de script/kernel
    -- SESION_INTERRUMPIDA → cierre abrupto del kernel
    -- CAMBIO_ROL         → asignación/modificación de rol
    -- CREACION_USUARIO   → registro de nuevo usuario
    -- ACCESO_DENEGADO    → intento sin permisos

    -- CONTEXTO DEL DATO AFECTADO
    dataset_nombre    TEXT,
    -- Nombre del archivo o dataset sobre el que se operó.
    -- Ejemplo: 'PATIENTS.csv', 'admissions_clean.csv'

    columnas_afectadas TEXT,
    -- Lista de columnas involucradas (JSON array o string separado por comas).
    -- Ejemplo: '["subject_id", "diagnosis", "age"]'

    ruta_destino      TEXT,
    -- Ruta del archivo de destino en operaciones de exportación.
    -- Ejemplo: '/outputs/resultados_modelo.csv'

    filas_exportadas  INTEGER,
    -- Número de filas incluidas en una exportación (tipo_accion = EXPORTACION).
    -- Exigido por HU-2.3 CA2.

    sobrescritura     INTEGER,
    -- Indicador de sobrescritura de archivo en exportaciones (0/1).
    -- 1 = el archivo de destino ya existía y fue sobreescrito.
    -- Exigido por HU-2.3 CA3.

    -- CONTEXTO DE EJECUCIÓN
    contexto_ejecucion TEXT,
    -- Nombre del script o notebook desde el cual se ejecutó la operación.
    -- Ejemplo: 'analisis_readmision.ipynb', 'preprocesamiento.py'

    -- INFORMACIÓN DE FALLOS Y ALERTAS
    motivo_fallo      TEXT,
    -- Causa del fallo en eventos ACCESO_FALLIDO o MODELADO_FALLIDO.
    -- Ejemplo: 'PermissionError', 'FileNotFoundError', 'usuario no autorizado'

    nivel_alerta      TEXT     DEFAULT 'NORMAL',
    -- Clasificación de severidad del evento.
    -- Valores: 'NORMAL', 'ADVERTENCIA', 'CRITICO'
    -- CRITICO: >3 intentos fallidos en <5 min, exportaciones masivas >1000 filas

    motivo_alerta     TEXT,
    -- Descripción de la causa de clasificación crítica.
    -- Ejemplo: '3 intentos fallidos en 4 minutos'

    -- INTEGRIDAD DEL REGISTRO
    hash_integridad   TEXT     NOT NULL,
    -- Hash SHA-256 calculado sobre los campos del evento.
    -- Permite detectar alteraciones posteriores al registro.
    -- Exigido por HIPAA §164.312(c)(1)

    firma_digital     TEXT
    -- HU-6.1 CA4: Firma digital Ed25519 generada por la llave privada del usuario.
    -- Base64url sin padding, ~86 caracteres. Almacenada para verificación forense.
);

-- ============================================================
-- TABLA DE INTENTOS BLOQUEADOS (HU-5.4 — cierra faltante de HU-3.3,
-- que implementó esto en la rama feature/HU-3.3-Juan-Pablo pero nunca
-- se mergeó a main)
-- Registra cada intento de UPDATE/DELETE sobre audit_log rechazado
-- por los triggers de inmutabilidad de abajo.
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
-- TRIGGERS DE INMUTABILIDAD (HU-5.4 CA3, mismo patrón en la base central)
-- RAISE(FAIL, ...) en vez de RAISE(ABORT, ...): FAIL aborta la sentencia
-- sin deshacer los efectos de sentencias/triggers previos en la misma
-- transacción, así que el INSERT en audit_intentos_bloqueados sobrevive
-- aunque el UPDATE/DELETE original sea rechazado.
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

-- ÍNDICES para optimizar consultas de auditoría
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

-- ============================================================
-- COLA LOCAL DE SINCRONIZACIÓN (HU-5.8)
-- Solo existe en la base LOCAL (no en audit_log_central): cada fila de
-- audit_log capturada por la librería (Colab u otro entorno) tiene una
-- fila espejo aquí que rastrea su envío al servidor central.
--
-- Se modela como tabla separada — y no como columnas nuevas en
-- audit_log — a propósito: audit_log tiene triggers que bloquean TODO
-- UPDATE (inmutabilidad, HU-5.4 CA3), y el estado de sincronización
-- necesita mutar (PENDIENTE -> SINCRONIZADO). Es metadata operativa de
-- transporte, no parte del evento auditado — mismo criterio ya usado
-- para justificar que evento_uuid quede fuera del hash_integridad.
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_sync_queue (

    event_id        INTEGER PRIMARY KEY REFERENCES audit_log(event_id),
    -- Mismo event_id de la fila local que representa. Uno a uno.

    evento_uuid     TEXT    NOT NULL UNIQUE,
    -- Copia de audit_log.evento_uuid: identificador estable enviado al
    -- servidor central en cada intento, nunca regenerado entre reintentos.

    estado          TEXT    NOT NULL DEFAULT 'PENDIENTE',
    -- 'PENDIENTE' | 'SINCRONIZADO' | 'FALLIDO'

    intentos        INTEGER NOT NULL DEFAULT 0,
    -- Número de intentos de envío realizados hasta ahora.

    ultimo_intento  TEXT,
    -- Timestamp ISO 8601 del último intento de envío (exitoso o no).

    ultimo_error    TEXT,
    -- Motivo del último fallo (sin datos sensibles: nunca el token).

    sincronizado_en TEXT
    -- Timestamp ISO 8601 de la confirmación positiva del servidor central.

);

CREATE INDEX IF NOT EXISTS idx_sync_queue_estado
    ON audit_sync_queue(estado);