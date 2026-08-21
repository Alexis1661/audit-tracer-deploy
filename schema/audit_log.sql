-- ============================================================
-- SISTEMA DE AUDITORÍA DE TRAZABILIDAD
-- Tabla: audit_log
-- Versión: 1.0
-- Descripción: Registro centralizado de todos los eventos
--              auditables sobre datos clínicos sensibles.
-- Normas: HIPAA §164.312(b) · Ley 1581/2012 · ISO/IEC 27001
-- ============================================================

CREATE TABLE IF NOT EXISTS audit_log (

    -- IDENTIFICADOR ÚNICO DEL EVENTO
    event_id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    -- Clave primaria autogenerada. Nunca puede repetirse ni ser nula.

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
    hash_integridad   TEXT     NOT NULL
    -- Hash SHA-256 calculado sobre los campos del evento.
    -- Permite detectar alteraciones posteriores al registro.
    -- Exigido por HIPAA §164.312(c)(1)

);

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