CREATE TABLE IF NOT EXISTS vulnerability_cpe_matches (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE,
    match_criteria_id TEXT NOT NULL DEFAULT '',
    criteria TEXT NOT NULL,
    part TEXT NOT NULL,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including TEXT,
    version_end_excluding TEXT,
    vulnerable BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id, criteria)
);

CREATE INDEX IF NOT EXISTS idx_cpe_lookup ON vulnerability_cpe_matches (part, vendor, product);
CREATE INDEX IF NOT EXISTS idx_cpe_cve_id ON vulnerability_cpe_matches (cve_id);
CREATE INDEX IF NOT EXISTS idx_cpe_match_criteria_id ON vulnerability_cpe_matches (match_criteria_id);