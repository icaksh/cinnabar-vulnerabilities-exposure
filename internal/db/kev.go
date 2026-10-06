package db

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

func (d *DB) ApplyKEV(ctx context.Context, cveID string, e model.PendingKEV) (bool, error) {
	tag, err := d.pool.Exec(ctx, `UPDATE vulnerabilities SET
		is_kev = true,
		kev_date_added = $2,
		kev_due_date = $3,
		kev_required_action = $4,
		kev_known_ransomware_campaign_use = $5,
		updated_at = now()
		WHERE cve_id = $1`, cveID, e.DateAdded, e.DueDate, e.RequiredAction, e.KnownRansomwareCampaignUse)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (d *DB) UpsertPendingKEV(ctx context.Context, entries []model.PendingKEV) error {
	if len(entries) == 0 {
		return nil
	}
	batch := &pgx.Batch{}
	for _, e := range entries {
		raw, err := json.Marshal(e.Raw)
		if err != nil {
			return err
		}
		batch.Queue(`INSERT INTO pending_kev (cve_id, date_added, due_date, required_action, known_ransomware_campaign_use, raw_json)
			VALUES ($1, $2, $3, $4, $5, $6::jsonb)
			ON CONFLICT (cve_id) DO UPDATE SET
				date_added = EXCLUDED.date_added,
				due_date = EXCLUDED.due_date,
				required_action = EXCLUDED.required_action,
				known_ransomware_campaign_use = EXCLUDED.known_ransomware_campaign_use,
				raw_json = EXCLUDED.raw_json,
				updated_at = now()`,
			e.CVEID, e.DateAdded, e.DueDate, e.RequiredAction, e.KnownRansomwareCampaignUse, string(raw))
	}
	br := d.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range entries {
		if _, err := br.Exec(); err != nil {
			return err
		}
	}
	return nil
}

func (d *DB) ListPendingKEV(ctx context.Context) ([]model.PendingKEV, error) {
	rows, err := d.pool.Query(ctx, `SELECT cve_id, date_added, due_date, required_action,
		known_ransomware_campaign_use, raw_json, created_at, updated_at FROM pending_kev ORDER BY cve_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]model.PendingKEV, 0)
	for rows.Next() {
		var e model.PendingKEV
		var raw []byte
		if err := rows.Scan(&e.CVEID, &e.DateAdded, &e.DueDate, &e.RequiredAction,
			&e.KnownRansomwareCampaignUse, &raw, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, err
		}
		if len(raw) > 0 {
			e.Raw = json.RawMessage(raw)
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func (d *DB) DeletePendingKEV(ctx context.Context, cveIDs []string) error {
	if len(cveIDs) == 0 {
		return nil
	}
	_, err := d.pool.Exec(ctx, `DELETE FROM pending_kev WHERE cve_id = ANY($1)`, cveIDs)
	return err
}

func (d *DB) ReconcilePendingKEV(ctx context.Context) (int, error) {
	pending, err := d.ListPendingKEV(ctx)
	if err != nil {
		return 0, err
	}
	applied := 0
	var deleteIDs []string
	for _, e := range pending {
		ok, err := d.ApplyKEV(ctx, e.CVEID, e)
		if err != nil {
			return applied, err
		}
		if ok {
			applied++
			deleteIDs = append(deleteIDs, e.CVEID)
		}
	}
	if err := d.DeletePendingKEV(ctx, deleteIDs); err != nil {
		return applied, err
	}
	return applied, nil
}
