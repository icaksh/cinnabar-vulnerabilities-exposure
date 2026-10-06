package db

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

var cpeMatchColumns = []string{
	"cve_id", "match_criteria_id", "criteria", "part", "vendor", "product", "version",
	"version_start_including", "version_start_excluding", "version_end_including", "version_end_excluding", "vulnerable",
}

func (d *DB) ReplaceCPEMatches(ctx context.Context, cveIDs []string, matches []model.CPEMatch) error {
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

	if len(matches) > 0 {
		_, err := tx.CopyFrom(ctx, pgx.Identifier{"vulnerability_cpe_matches"}, cpeMatchColumns,
			pgx.CopyFromSlice(len(matches), func(i int) ([]any, error) {
				m := matches[i]
				return []any{
					m.CVEID, m.MatchCriteriaID, m.Criteria, m.Part, m.Vendor, m.Product, m.Version,
					m.VersionStartIncl, m.VersionStartExcl, m.VersionEndIncl, m.VersionEndExcl, m.Vulnerable,
				}, nil
			}))
		if err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

const cpeMatchSelect = `cve_id, match_criteria_id, criteria, part, vendor, product, version,
	version_start_including, version_start_excluding, version_end_including, version_end_excluding, vulnerable`

func scanCPEMatch(row pgx.Row) (model.CPEMatch, error) {
	var m model.CPEMatch
	err := row.Scan(&m.CVEID, &m.MatchCriteriaID, &m.Criteria, &m.Part, &m.Vendor, &m.Product, &m.Version,
		&m.VersionStartIncl, &m.VersionStartExcl, &m.VersionEndIncl, &m.VersionEndExcl, &m.Vulnerable)
	return m, err
}

func (d *DB) CandidateLookup(ctx context.Context, part, vendor, product string) ([]model.CPEMatch, error) {
	rows, err := d.pool.Query(ctx, `SELECT `+cpeMatchSelect+` FROM vulnerability_cpe_matches
		WHERE vulnerable = true
		AND vendor = $1 AND product = $2
		AND ($3 = '' OR part = $3)
		ORDER BY cve_id, id`, vendor, product, part)
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
