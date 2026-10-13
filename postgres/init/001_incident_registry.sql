CREATE TABLE IF NOT EXISTS incidents (

    id SERIAL PRIMARY KEY,
    source TEXT NOT NULL, -- EDR / XDR / SIEM / manual / etc.
    external_id TEXT, -- ID dell'alert nel sistema sorgente
    summary TEXT,
    description TEXT,
    severity TEXT,   -- low / medium / high / critical
    status TEXT NOT NULL DEFAULT 'new',
    raw_payload JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT incidents_status_check
        CHECK (
            status IN (
                'new',
                'triage',
                'triaged',
                'retrieve',
                'validation',
                'validated',
                'awaiting_human_approval',
                'response',
                'responded',
                'failed',
                'closed'
            )
        ),

    CONSTRAINT incidents_severity_check
        CHECK (
            severity IS NULL
            OR severity IN (
                'low',
                'medium',
                'high',
                'critical'
            )
        )
);

CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents (status);

CREATE INDEX IF NOT EXISTS idx_incidents_created_at ON incidents (created_at);

CREATE INDEX IF NOT EXISTS idx_incidents_external_id ON incidents (external_id);


CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents (id) ON DELETE SET NULL,
    agent TEXT NOT NULL,
        -- router_agent
        -- orchestrator
        -- triage_agent
        -- retrieve_agent
        -- action_planner_agent
        -- validation_agent
        -- response_layer
        -- incident_registry
    action TEXT NOT NULL,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_log_incident_id
    ON audit_log (incident_id);

CREATE INDEX IF NOT EXISTS idx_audit_log_created_at
    ON audit_log (created_at);

CREATE INDEX IF NOT EXISTS idx_audit_log_agent
    ON audit_log (agent);

CREATE INDEX IF NOT EXISTS idx_audit_log_action
    ON audit_log (action);
