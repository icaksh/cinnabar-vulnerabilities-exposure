CREATE TABLE IF NOT EXISTS vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    published_at TIMESTAMPTZ,
    modified_at TIMESTAMPTZ,
    cvss_version TEXT,
    cvss_score DOUBLE PRECISION,
    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
    cvss_vector TEXT,
    cwe_ids JSONB NOT NULL DEFAULT '[]',
    references_json JSONB NOT NULL DEFAULT '[]',
    is_kev BOOLEAN NOT NULL DEFAULT FALSE,
    kev_date_added DATE,
    kev_due_date DATE,
    kev_required_action TEXT,
    kev_known_ransomware_campaign_use BOOLEAN NOT NULL DEFAULT FALSE,
    source_updated_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vulnerabilities_cve_id ON vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_modified_at ON vulnerabilities (modified_at);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_severity ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vulnerabilities_is_kev ON vulnerabilities (is_kev);