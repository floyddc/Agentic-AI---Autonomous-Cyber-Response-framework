CREATE TABLE IF NOT EXISTS incidents (
    id SERIAL PRIMARY KEY,
    source TEXT NOT NULL,              -- EDR / XDR / SIEM
    external_id TEXT,                  -- id from the source system
    summary TEXT,
    description TEXT,
    severity TEXT,                     -- low / medium / high / critical
    status TEXT NOT NULL DEFAULT 'new', -- new / triaged / validated / responded / closed
    raw_payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at);

CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents (id) ON DELETE SET NULL,
    agent TEXT NOT NULL,               -- logging_agent, retrieve_agent, response_agent, triage_agent
    action TEXT NOT NULL,              -- "classified", "retrieved_context", "proposed_action"
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_incident_id ON audit_log (incident_id);
