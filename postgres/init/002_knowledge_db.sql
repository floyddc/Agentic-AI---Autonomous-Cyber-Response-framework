SELECT 'CREATE DATABASE knowledge'
WHERE NOT EXISTS (
    SELECT FROM pg_database WHERE datname = 'knowledge'
)\gexec

\connect knowledge

CREATE TABLE IF NOT EXISTS kb_documents (
    id SERIAL PRIMARY KEY,
    source_path TEXT NOT NULL UNIQUE,
    category TEXT NOT NULL,             -- mitre_attack / attack_patterns / observables / procedures
    title TEXT,
    content TEXT NOT NULL,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_kb_documents_category ON kb_documents (category);

CREATE TABLE IF NOT EXISTS incident_history (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER,               -- original id from the operational incident_registry database
    source TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary TEXT,
    description TEXT,
    severity TEXT,
    resolution TEXT,
    lessons_learned TEXT,
    raw_payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incident_history_created_at ON incident_history (created_at);

CREATE TABLE IF NOT EXISTS index_cursors (
    source TEXT PRIMARY KEY,
    last_id BIGINT NOT NULL DEFAULT 0 CHECK (last_id >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
