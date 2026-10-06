CREATE TABLE IF NOT EXISTS vulnerability_sync_state (
    source TEXT PRIMARY KEY,
    status TEXT NOT NULL DEFAULT 'idle',
    last_attempt_at TIMESTAMPTZ,
    last_success_at TIMESTAMPTZ,
    last_error TEXT,
    records_processed BIGINT NOT NULL DEFAULT 0,
    sync_cursor TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);