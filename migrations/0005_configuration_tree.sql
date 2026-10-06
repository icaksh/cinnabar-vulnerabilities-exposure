-- Preserve NVD applicability structure (configuration -> nodes -> cpe matches)
-- so the resolver can evaluate AND/OR/negate expressions instead of flattening.

CREATE TABLE IF NOT EXISTS vulnerability_configurations (
    id BIGSERIAL PRIMARY KEY,
    cve_id TEXT NOT NULL REFERENCES vulnerabilities (cve_id) ON DELETE CASCADE,
    operator TEXT NOT NULL DEFAULT 'OR',
    negate BOOLEAN NOT NULL DEFAULT FALSE,
    position INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (cve_id, position)
);

CREATE INDEX IF NOT EXISTS idx_configurations_cve_id ON vulnerability_configurations (cve_id);

CREATE TABLE IF NOT EXISTS vulnerability_configuration_nodes (
    id BIGSERIAL PRIMARY KEY,
    configuration_id BIGINT NOT NULL REFERENCES vulnerability_configurations (id) ON DELETE CASCADE,
    parent_node_id BIGINT NULL REFERENCES vulnerability_configuration_nodes (id) ON DELETE CASCADE,
    operator TEXT NOT NULL DEFAULT 'OR',
    negate BOOLEAN NOT NULL DEFAULT FALSE,
    position INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_config_nodes_cfg ON vulnerability_configuration_nodes (configuration_id);
CREATE INDEX IF NOT EXISTS idx_config_nodes_parent ON vulnerability_configuration_nodes (parent_node_id);

-- Extend the flat match table with node membership and full CPE components.
ALTER TABLE vulnerability_cpe_matches
    ADD COLUMN IF NOT EXISTS node_id BIGINT NULL REFERENCES vulnerability_configuration_nodes (id) ON DELETE CASCADE,
    ADD COLUMN IF NOT EXISTS cpe_update TEXT NOT NULL DEFAULT '*',
    ADD COLUMN IF NOT EXISTS edition TEXT NOT NULL DEFAULT '*',
    ADD COLUMN IF NOT EXISTS language TEXT NOT NULL DEFAULT '*',
    ADD COLUMN IF NOT EXISTS sw_edition TEXT NOT NULL DEFAULT '*',
    ADD COLUMN IF NOT EXISTS target_sw TEXT NOT NULL DEFAULT '*',
    ADD COLUMN IF NOT EXISTS target_hw TEXT NOT NULL DEFAULT '*',
    ADD COLUMN IF NOT EXISTS cpe_other TEXT NOT NULL DEFAULT '*';

CREATE INDEX IF NOT EXISTS idx_cpe_node_id ON vulnerability_cpe_matches (node_id);

-- The old (cve_id, criteria) uniqueness is too coarse: two applicability
-- entries may share a criteria string but differ by range/node context.
-- Drop it; identity is now (node_id, match_criteria_id) for tree rows.
ALTER TABLE vulnerability_cpe_matches DROP CONSTRAINT IF EXISTS vulnerability_cpe_matches_cve_id_criteria_key;

CREATE UNIQUE INDEX IF NOT EXISTS uq_cpe_match_identity
    ON vulnerability_cpe_matches (node_id, match_criteria_id)
    WHERE node_id IS NOT NULL AND match_criteria_id <> '';