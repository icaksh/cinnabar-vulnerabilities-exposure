CREATE TABLE IF NOT EXISTS pending_kev (
    cve_id TEXT PRIMARY KEY,
    date_added DATE,
    due_date DATE,
    required_action TEXT,
    known_ransomware_campaign_use BOOLEAN NOT NULL DEFAULT FALSE,
    raw_json JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);