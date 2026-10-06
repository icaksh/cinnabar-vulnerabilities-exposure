package db

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

func (d *DB) GetSyncState(ctx context.Context, source string) (*model.SyncState, error) {
	var s model.SyncState
	err := d.pool.QueryRow(ctx, `SELECT source, status, last_attempt_at, last_success_at, last_error,
		records_processed, sync_cursor, created_at, updated_at
		FROM vulnerability_sync_state WHERE source = $1`, source).
		Scan(&s.Source, &s.Status, &s.LastAttemptAt, &s.LastSuccessAt, &s.LastError,
			&s.RecordsProcessed, &s.SyncCursor, &s.CreatedAt, &s.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return &model.SyncState{Source: source, Status: "idle"}, nil
	}
	if err != nil {
		return nil, err
	}
	return &s, nil
}

func (d *DB) MarkSyncAttempt(ctx context.Context, source string) error {
	_, err := d.pool.Exec(ctx, `INSERT INTO vulnerability_sync_state (source, status, last_attempt_at)
		VALUES ($1, 'running', now())
		ON CONFLICT (source) DO UPDATE SET status = 'running', last_attempt_at = now(), updated_at = now()`, source)
	return err
}

func (d *DB) MarkSyncSuccess(ctx context.Context, source string, records int64, cursor *time.Time) error {
	_, err := d.pool.Exec(ctx, `UPDATE vulnerability_sync_state SET
		status = 'success', last_success_at = now(), last_error = NULL,
		records_processed = $2, sync_cursor = $3, updated_at = now()
		WHERE source = $1`, source, records, cursor)
	return err
}

func (d *DB) MarkSyncError(ctx context.Context, source string, errMsg string) error {
	_, err := d.pool.Exec(ctx, `UPDATE vulnerability_sync_state SET
		status = 'error', last_error = $2, updated_at = now()
		WHERE source = $1`, source, errMsg)
	return err
}
