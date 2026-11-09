BEGIN IMMEDIATE;

CREATE TABLE IF NOT EXISTS audit_saved_filters (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    usuario_id TEXT NOT NULL REFERENCES usuarios(usuario_id),
    nombre TEXT NOT NULL,
    filtros TEXT NOT NULL,
    UNIQUE (usuario_id, nombre COLLATE NOCASE)
);

CREATE TABLE IF NOT EXISTS audit_alert_reviews (
    event_id INTEGER PRIMARY KEY REFERENCES audit_log(event_id),
    estado TEXT NOT NULL DEFAULT 'PENDIENTE' CHECK (estado IN ('PENDIENTE', 'EN_REVISION', 'RESUELTA')),
    responsable_id TEXT REFERENCES usuarios(usuario_id),
    version INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_alert_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES audit_log(event_id),
    autor_id TEXT NOT NULL REFERENCES usuarios(usuario_id),
    fecha TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%f', 'now')),
    estado TEXT NOT NULL,
    responsable_id TEXT REFERENCES usuarios(usuario_id),
    comentario TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_alert_history_event ON audit_alert_history(event_id, id DESC);

CREATE TABLE IF NOT EXISTS audit_notification_settings (
    usuario_id TEXT PRIMARY KEY REFERENCES usuarios(usuario_id),
    en_panel INTEGER NOT NULL DEFAULT 1,
    por_correo INTEGER NOT NULL DEFAULT 0,
    leido_hasta INTEGER NOT NULL DEFAULT 0,
    correo_hasta INTEGER NOT NULL DEFAULT 0,
    correo_reserva TEXT,
    correo_reserva_hasta INTEGER NOT NULL DEFAULT 0
);

COMMIT;
