CREATE TABLE IF NOT EXISTS index_cursors (
    source TEXT PRIMARY KEY,
    last_id BIGINT NOT NULL DEFAULT 0 CHECK (last_id >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
