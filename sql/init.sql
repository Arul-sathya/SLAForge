-- SLAForge database schema
-- Persists anomalies and runbook entries across restarts

CREATE TABLE IF NOT EXISTS anomalies (
    id              TEXT PRIMARY KEY,
    detected_at     TIMESTAMPTZ NOT NULL,
    anomaly_type    TEXT NOT NULL,
    severity        TEXT NOT NULL,
    metric_name     TEXT NOT NULL,
    current_value   DOUBLE PRECISION,
    baseline_value  DOUBLE PRECISION,
    cusum_score     DOUBLE PRECISION,
    description     TEXT,
    resolved        BOOLEAN DEFAULT FALSE,
    resolved_at     TIMESTAMPTZ,
    diagnosis       JSONB,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_anomalies_detected_at ON anomalies (detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_anomalies_resolved ON anomalies (resolved);

CREATE TABLE IF NOT EXISTS runbook_entries (
    id          SERIAL PRIMARY KEY,
    anomaly_id  TEXT REFERENCES anomalies(id),
    content     TEXT NOT NULL,
    created_at  TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS sync_state (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ DEFAULT NOW()
);
