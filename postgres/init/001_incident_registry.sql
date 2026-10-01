-- INCIDENTS -------------------------------------------------------------------------------------
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
                'retrieve',
                'retrieved',
                'triage',
                'triaged',
                'planning',
                'action_proposed',
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


-- AUDIT LOG -------------------------------------------------------------------------------------
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


-- EVENT INBOX -------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_inbox (
    id BIGSERIAL PRIMARY KEY,

    event_id UUID NOT NULL,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,

    event_type TEXT NOT NULL,
    correlation_id UUID NOT NULL,
    producer TEXT NOT NULL,

    payload JSONB NOT NULL,

    status TEXT NOT NULL DEFAULT 'received',

    attempts INTEGER NOT NULL DEFAULT 0,

    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    processing_started_at TIMESTAMPTZ,
    processed_at TIMESTAMPTZ,

    last_error TEXT,

    CONSTRAINT event_inbox_status_check
        CHECK (
            status IN (
                'received',
                'processing',
                'processed',
                'failed'
            )
        )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_event_inbox_event_id
    ON event_inbox(event_id);

CREATE INDEX IF NOT EXISTS idx_event_inbox_status
    ON event_inbox(status);

CREATE INDEX IF NOT EXISTS idx_event_inbox_incident_id
    ON event_inbox(incident_id);

CREATE INDEX IF NOT EXISTS idx_event_inbox_pending
    ON event_inbox(received_at)
    WHERE status = 'received';

CREATE INDEX IF NOT EXISTS idx_event_inbox_processing
    ON event_inbox(processing_started_at)
    WHERE status = 'processing';



-- EVENT OUTBOX -------------------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS event_outbox (
    id BIGSERIAL PRIMARY KEY,

    event_id UUID NOT NULL,
    incident_id INTEGER REFERENCES incidents(id) ON DELETE CASCADE,

    event_type TEXT NOT NULL,
    correlation_id UUID NOT NULL,
    producer TEXT NOT NULL,

    topic TEXT NOT NULL,
    payload JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    published_at TIMESTAMPTZ,

    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMPTZ,
    last_error TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_event_outbox_event_id
    ON event_outbox(event_id);

CREATE INDEX IF NOT EXISTS idx_event_outbox_unpublished
    ON event_outbox(published_at, created_at)
    WHERE published_at IS NULL;
