package db

import (
	"context"
	"sort"

	"github.com/jackc/pgx/v5"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

var cpeMatchColumns = []string{
	"cve_id", "node_id", "match_criteria_id", "criteria", "part", "vendor", "product", "version",
	"version_start_including", "version_start_excluding", "version_end_including", "version_end_excluding",
	"cpe_update", "edition", "language", "sw_edition", "target_sw", "target_hw", "cpe_other", "vulnerable",
}

const cpeMatchSelect = `cve_id, node_id, match_criteria_id, criteria, part, vendor, product, version,
	version_start_including, version_start_excluding, version_end_including, version_end_excluding,
	cpe_update, edition, language, sw_edition, target_sw, target_hw, cpe_other, vulnerable`

// ReplaceConfigurations deletes and re-inserts the full applicability trees
// (configurations -> nodes -> cpe matches) for the given CVEs.
func (d *DB) ReplaceConfigurations(ctx context.Context, cveIDs []string, configs map[string][]model.Configuration) error {
	if len(cveIDs) == 0 {
		return nil
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `DELETE FROM vulnerability_cpe_matches WHERE cve_id = ANY($1)`, cveIDs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM vulnerability_configuration_nodes
		WHERE configuration_id IN (SELECT id FROM vulnerability_configurations WHERE cve_id = ANY($1))`, cveIDs); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM vulnerability_configurations WHERE cve_id = ANY($1)`, cveIDs); err != nil {
		return err
	}

	for _, cveID := range cveIDs {
		for _, cfg := range configs[cveID] {
			if err := insertConfiguration(ctx, tx, cfg); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

func insertConfiguration(ctx context.Context, tx pgx.Tx, cfg model.Configuration) error {
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO vulnerability_configurations (cve_id, operator, negate, position)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		cfg.CVEID, cfg.Operator, cfg.Negate, cfg.Position).Scan(&id)
	if err != nil {
		return err
	}
	for i, n := range cfg.Nodes {
		if err := insertNode(ctx, tx, id, nil, n, i); err != nil {
			return err
		}
	}
	return nil
}

func insertNode(ctx context.Context, tx pgx.Tx, configID int64, parentID *int64, n model.ConfigurationNode, pos int) error {
	var id int64
	err := tx.QueryRow(ctx, `INSERT INTO vulnerability_configuration_nodes
		(configuration_id, parent_node_id, operator, negate, position)
		VALUES ($1, $2, $3, $4, $5) RETURNING id`,
		configID, parentID, n.Operator, n.Negate, pos).Scan(&id)
	if err != nil {
		return err
	}
	for _, m := range n.Matches {
		if err := insertMatch(ctx, tx, id, m); err != nil {
			return err
		}
	}
	for i, child := range n.Children {
		if err := insertNode(ctx, tx, configID, &id, child, i); err != nil {
			return err
		}
	}
	return nil
}

func insertMatch(ctx context.Context, tx pgx.Tx, nodeID int64, m model.CPEMatch) error {
	_, err := tx.Exec(ctx, `INSERT INTO vulnerability_cpe_matches
		(cve_id, node_id, match_criteria_id, criteria, part, vendor, product, version,
		 version_start_including, version_start_excluding, version_end_including, version_end_excluding,
		 cpe_update, edition, language, sw_edition, target_sw, target_hw, cpe_other, vulnerable)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
		m.CVEID, nodeID, m.MatchCriteriaID, m.Criteria, m.Part, m.Vendor, m.Product, m.Version,
		m.VersionStartIncl, m.VersionStartExcl, m.VersionEndIncl, m.VersionEndExcl,
		m.Update, m.Edition, m.Language, m.SWEdition, m.TargetSW, m.TargetHW, m.Other, m.Vulnerable)
	return err
}

func scanCPEMatch(row pgx.Row) (model.CPEMatch, error) {
	var m model.CPEMatch
	var nodeID *int64
	err := row.Scan(&m.CVEID, &nodeID, &m.MatchCriteriaID, &m.Criteria, &m.Part, &m.Vendor, &m.Product, &m.Version,
		&m.VersionStartIncl, &m.VersionStartExcl, &m.VersionEndIncl, &m.VersionEndExcl,
		&m.Update, &m.Edition, &m.Language, &m.SWEdition, &m.TargetSW, &m.TargetHW, &m.Other, &m.Vulnerable)
	if nodeID != nil {
		m.NodeID = *nodeID
	}
	return m, err
}

// CandidateCVEs discovers candidate CVE IDs whose applicability expression
// mentions the given product (including vulnerable=false environment
// conditions). Uses the (part, vendor, product) lookup index.
func (d *DB) CandidateCVEs(ctx context.Context, part, vendor, product string) ([]string, error) {
	rows, err := d.pool.Query(ctx, `SELECT DISTINCT cve_id FROM vulnerability_cpe_matches
		WHERE vendor = $1 AND product = $2
		AND ($3 = '' OR part = $3)
		ORDER BY cve_id`, vendor, product, part)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// GetConfigurations loads the complete applicability trees for the given CVEs
// in a small, fixed number of batched queries.
func (d *DB) GetConfigurations(ctx context.Context, cveIDs []string) (map[string][]model.Configuration, error) {
	out := make(map[string][]model.Configuration)
	if len(cveIDs) == 0 {
		return out, nil
	}

	cfgRows, err := d.pool.Query(ctx, `SELECT id, cve_id, operator, negate, position
		FROM vulnerability_configurations WHERE cve_id = ANY($1)
		ORDER BY cve_id, position`, cveIDs)
	if err != nil {
		return nil, err
	}
	configs := make(map[int64]*model.Configuration)
	configIDs := make([]int64, 0)
	for cfgRows.Next() {
		var c model.Configuration
		if err := cfgRows.Scan(&c.ID, &c.CVEID, &c.Operator, &c.Negate, &c.Position); err != nil {
			cfgRows.Close()
			return nil, err
		}
		configs[c.ID] = &c
		configIDs = append(configIDs, c.ID)
	}
	cfgRows.Close()
	if err := cfgRows.Err(); err != nil {
		return nil, err
	}

	nodeRows, err := d.pool.Query(ctx, `SELECT id, configuration_id, parent_node_id, operator, negate, position
		FROM vulnerability_configuration_nodes WHERE configuration_id = ANY($1)
		ORDER BY configuration_id, position`, configIDs)
	if err != nil {
		return nil, err
	}
	nodes := make(map[int64]*model.ConfigurationNode)
	nodeIDs := make([]int64, 0)
	for nodeRows.Next() {
		var n model.ConfigurationNode
		if err := nodeRows.Scan(&n.ID, &n.ConfigurationID, &n.ParentNodeID, &n.Operator, &n.Negate, &n.Position); err != nil {
			nodeRows.Close()
			return nil, err
		}
		nodes[n.ID] = &n
		nodeIDs = append(nodeIDs, n.ID)
	}
	nodeRows.Close()
	if err := nodeRows.Err(); err != nil {
		return nil, err
	}

	if len(nodeIDs) > 0 {
		matchRows, err := d.pool.Query(ctx, `SELECT `+cpeMatchSelect+` FROM vulnerability_cpe_matches
			WHERE node_id = ANY($1) ORDER BY node_id, id`, nodeIDs)
		if err != nil {
			return nil, err
		}
		for matchRows.Next() {
			m, err := scanCPEMatch(matchRows)
			if err != nil {
				matchRows.Close()
				return nil, err
			}
			if n, ok := nodes[m.NodeID]; ok {
				n.Matches = append(n.Matches, m)
			}
		}
		matchRows.Close()
		if err := matchRows.Err(); err != nil {
			return nil, err
		}
	}

	byCVE := make(map[string][]int64)
	for id, c := range configs {
		byCVE[c.CVEID] = append(byCVE[c.CVEID], id)
	}
	for _, c := range configs {
		attached := false
		for _, n := range nodes {
			if n.ConfigurationID != c.ID {
				continue
			}
			if n.ParentNodeID != nil {
				if parent, ok := nodes[*n.ParentNodeID]; ok {
					parent.Children = append(parent.Children, *n)
					attached = true
				}
				continue
			}
			c.Nodes = append(c.Nodes, *n)
			attached = true
		}
		_ = attached
		sort.Slice(c.Nodes, func(i, j int) bool { return c.Nodes[i].Position < c.Nodes[j].Position })
	}
	for cveID, ids := range byCVE {
		sort.Slice(ids, func(i, j int) bool { return configs[ids[i]].Position < configs[ids[j]].Position })
		for _, id := range ids {
			out[cveID] = append(out[cveID], *configs[id])
		}
	}
	return out, nil
}

// GetLegacyMatches loads flattened rows that are not part of a configuration
// tree (pre-resync data). They are evaluated with legacy semantics as a
// transition path until an NVD re-sync stores trees.
func (d *DB) GetLegacyMatches(ctx context.Context, cveIDs []string) (map[string][]model.CPEMatch, error) {
	out := make(map[string][]model.CPEMatch)
	if len(cveIDs) == 0 {
		return out, nil
	}
	rows, err := d.pool.Query(ctx, `SELECT `+cpeMatchSelect+` FROM vulnerability_cpe_matches
		WHERE cve_id = ANY($1) AND node_id IS NULL
		ORDER BY cve_id, id`, cveIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		m, err := scanCPEMatch(rows)
		if err != nil {
			return nil, err
		}
		out[m.CVEID] = append(out[m.CVEID], m)
	}
	return out, rows.Err()
}

// GetCPEMatches returns the flat match rows for a single CVE (API display).
func (d *DB) GetCPEMatches(ctx context.Context, cveID string) ([]model.CPEMatch, error) {
	rows, err := d.pool.Query(ctx, `SELECT `+cpeMatchSelect+` FROM vulnerability_cpe_matches
		WHERE cve_id = $1 ORDER BY id`, cveID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]model.CPEMatch, 0)
	for rows.Next() {
		m, err := scanCPEMatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}