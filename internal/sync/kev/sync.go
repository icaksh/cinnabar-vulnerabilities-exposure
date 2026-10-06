package kev

import (
	"context"
	"time"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

type Store interface {
	ApplyKEV(ctx context.Context, cveID string, e model.PendingKEV) (bool, error)
	UpsertPendingKEV(ctx context.Context, entries []model.PendingKEV) error
	ReconcilePendingKEV(ctx context.Context) (int, error)
	MarkSyncAttempt(ctx context.Context, source string) error
	MarkSyncSuccess(ctx context.Context, source string, records int64, cursor *time.Time) error
	MarkSyncError(ctx context.Context, source string, errMsg string) error
}

type Fetcher interface {
	Fetch(ctx context.Context) ([]model.PendingKEV, error)
}

type Syncer struct {
	store   Store
	fetcher Fetcher
}

type Result struct {
	Records    int64
	Applied    int64
	Pending    int64
	Reconciled int
}

func NewSyncer(store Store, fetcher Fetcher) *Syncer {
	return &Syncer{store: store, fetcher: fetcher}
}

func (s *Syncer) Sync(ctx context.Context) (Result, error) {
	if err := s.store.MarkSyncAttempt(ctx, SourceName); err != nil {
		return Result{}, err
	}

	entries, err := s.fetcher.Fetch(ctx)
	if err != nil {
		s.store.MarkSyncError(ctx, SourceName, err.Error())
		return Result{}, err
	}

	var res Result
	var pending []model.PendingKEV
	for _, e := range entries {
		if e.CVEID == "" {
			continue
		}
		applied, err := s.store.ApplyKEV(ctx, e.CVEID, e)
		if err != nil {
			s.store.MarkSyncError(ctx, SourceName, err.Error())
			return res, err
		}
		if applied {
			res.Applied++
		} else {
			pending = append(pending, e)
		}
	}

	if err := s.store.UpsertPendingKEV(ctx, pending); err != nil {
		s.store.MarkSyncError(ctx, SourceName, err.Error())
		return res, err
	}
	res.Pending = int64(len(pending))

	reconciled, err := s.store.ReconcilePendingKEV(ctx)
	if err != nil {
		s.store.MarkSyncError(ctx, SourceName, err.Error())
		return res, err
	}
	res.Reconciled = reconciled

	res.Records = int64(len(entries))
	now := time.Now().UTC()
	if err := s.store.MarkSyncSuccess(ctx, SourceName, res.Records, &now); err != nil {
		return res, err
	}
	return res, nil
}
