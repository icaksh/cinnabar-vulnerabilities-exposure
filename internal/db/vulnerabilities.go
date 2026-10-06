package db

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

const upsertVulnerabilitySQL = `
INSERT INTO vulnerabilities (
	cve_id, description, published_at, modified_at,
	cvss_version, cvss_score, severity, cvss_vector,
	cwe_ids, references_json,
	is_kev, kev_date_added, kev_due_date, kev_required_action, kev_known_ransomware_campaign_use,
	source_updated_at
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::jsonb, $10::jsonb, $11, $12, $13, $14, $15, $16)
ON CONFLICT (cve_id) DO UPDATE SET
	description = EXCLUDED.description,
	published_at = EXCLUDED.published_at,
	modified_at = EXCLUDED.modified_at,
	cvss_version = EXCLUDED.cvss_version,
	cvss_score = EXCLUDED.cvss_score,
	severity = EXCLUDED.severity,
	cvss_vector = EXCLUDED.cvss_vector,
	cwe_ids = EXCLUDED.cwe_ids,
	references_json = EXCLUDED.references_json,
	source_updated_at = EXCLUDED.source_updated_at,
	updated_at = now()
`

func (d *DB) UpsertVulnerabilities(ctx context.Context, vuls []model.Vulnerability) error {
	if len(vuls) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, v := range vuls {
		cwe, err := json.Marshal(v.CWEIDs)
		if err != nil {
			return err
		}
		refs, err := json.Marshal(v.References)
		if err != nil {
			return err
		}
		batch.Queue(upsertVulnerabilitySQL,
			v.CVEID, v.Description, v.PublishedAt, v.ModifiedAt,
			v.CVSSVersion, v.CVSSScore, string(v.Severity), v.CVSSVector,
			string(cwe), string(refs),
			v.IsKEV, v.KEVDateAdded, v.KEVDueDate, v.KEVRequiredAction, v.KEVKnownRansomwareCampaignUse,
			v.SourceUpdatedAt,
		)
	}
	br := d.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range vuls {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

const vulnColumns = `
id, cve_id, description, published_at, modified_at,
cvss_version, cvss_score, severity, cvss_vector,
cwe_ids, references_json,
is_kev, kev_date_added, kev_due_date, kev_required_action, kev_known_ransomware_campaign_use,
source_updated_at, created_at, updated_at`

func scanVulnerability(row pgx.Row) (model.Vulnerability, error) {
	var v model.Vulnerability
	var cwe, refs []byte
	var severity string
	err := row.Scan(
		&v.ID, &v.CVEID, &v.Description, &v.PublishedAt, &v.ModifiedAt,
		&v.CVSSVersion, &v.CVSSScore, &severity, &v.CVSSVector,
		&cwe, &refs,
		&v.IsKEV, &v.KEVDateAdded, &v.KEVDueDate, &v.KEVRequiredAction, &v.KEVKnownRansomwareCampaignUse,
		&v.SourceUpdatedAt, &v.CreatedAt, &v.UpdatedAt,
	)
	if err != nil {
		return v, err
	}
	v.Severity = model.Severity(severity)
	if len(cwe) > 0 {
		_ = json.Unmarshal(cwe, &v.CWEIDs)
	}
	if len(refs) > 0 {
		_ = json.Unmarshal(refs, &v.References)
	}
	if v.CWEIDs == nil {
		v.CWEIDs = []string{}
	}
	if v.References == nil {
		v.References = []model.Reference{}
	}
	return v, nil
}

func (d *DB) GetVulnerability(ctx context.Context, cveID string) (*model.Vulnerability, error) {
	v, err := scanVulnerability(d.pool.QueryRow(ctx, `SELECT `+vulnColumns+` FROM vulnerabilities WHERE cve_id = $1`, cveID))
	if err != nil {
		return nil, err
	}
	return &v, nil
}

func (d *DB) GetVulnerabilitiesByIDs(ctx context.Context, ids []string) (map[string]model.Vulnerability, error) {
	out := make(map[string]model.Vulnerability, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := d.pool.Query(ctx, `SELECT `+vulnColumns+` FROM vulnerabilities WHERE cve_id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		v, err := scanVulnerability(rows)
		if err != nil {
			return nil, err
		}
		out[v.CVEID] = v
	}
	return out, rows.Err()
}

func (d *DB) Stats(ctx context.Context) (cveCount, cpeCount, kevCount int64, err error) {
	err = d.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM vulnerabilities),
		(SELECT count(*) FROM vulnerability_cpe_matches),
		(SELECT count(*) FROM vulnerabilities WHERE is_kev = true)`).Scan(&cveCount, &cpeCount, &kevCount)
	return
}

type SearchParams struct {
	CVE           string
	Vendor        string
	Product       string
	Severity      string
	KEV           *bool
	ModifiedSince *time.Time
	Page          int
	PageSize      int
}

func (d *DB) SearchVulnerabilities(ctx context.Context, p SearchParams) ([]model.Vulnerability, int64, error) {
	where := `WHERE ($1 = '' OR cve_id ILIKE '%' || $1 || '%')
		AND ($2 = '' OR severity = $2)
		AND ($3 IS NULL OR is_kev = $3)
		AND ($4::timestamptz IS NULL OR modified_at >= $4)
		AND ($5 = '' OR EXISTS (SELECT 1 FROM vulnerability_cpe_matches m WHERE m.cve_id = vulnerabilities.cve_id AND m.vendor ILIKE '%' || $5 || '%'))
		AND ($6 = '' OR EXISTS (SELECT 1 FROM vulnerability_cpe_matches m WHERE m.cve_id = vulnerabilities.cve_id AND m.product ILIKE '%' || $6 || '%'))`

	var total int64
	err := d.pool.QueryRow(ctx, `SELECT count(*) FROM vulnerabilities `+where,
		p.CVE, p.Severity, p.KEV, p.ModifiedSince, p.Vendor, p.Product).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	rows, err := d.pool.Query(ctx, `SELECT `+vulnColumns+` FROM vulnerabilities `+where+`
		ORDER BY modified_at DESC NULLS LAST, cve_id ASC
		LIMIT $7 OFFSET $8`,
		p.CVE, p.Severity, p.KEV, p.ModifiedSince, p.Vendor, p.Product, p.PageSize, p.Page*p.PageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	out := make([]model.Vulnerability, 0)
	for rows.Next() {
		v, err := scanVulnerability(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, v)
	}
	return out, total, rows.Err()
}
