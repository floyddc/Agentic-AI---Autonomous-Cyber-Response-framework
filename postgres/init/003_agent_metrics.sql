CREATE TABLE IF NOT EXISTS agent_metrics (
    id SERIAL PRIMARY KEY,
    component TEXT NOT NULL,           -- retrieve_agent, action_planner_agent, incident_registry...
    action TEXT NOT NULL,              -- retrieve, ask, create_incident, close_incident...
    status TEXT NOT NULL DEFAULT 'success', -- success / error
    duration_ms DOUBLE PRECISION,
    incident_id INTEGER REFERENCES incidents (id) ON DELETE SET NULL,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_agent_metrics_component ON agent_metrics (component);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_created_at ON agent_metrics (created_at);
CREATE INDEX IF NOT EXISTS idx_agent_metrics_incident_id ON agent_metrics (incident_id);
