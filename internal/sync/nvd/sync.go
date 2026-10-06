package nvd

import (
	"context"
	"time"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

const SourceName = "nvd"

type Store interface {
	GetSyncState(ctx context.Context, source string) (*model.SyncState, error)
	MarkSyncAttempt(ctx context.Context, source string) error
	MarkSyncSuccess(ctx context.Context, source string, records int64, cursor *time.Time) error
	MarkSyncError(ctx context.Context, source string, errMsg string) error
	UpsertVulnerabilities(ctx context.Context, vuls []model.Vulnerability) error
	ReplaceConfigurations(ctx context.Context, cveIDs []string, configs map[string][]model.Configuration) error
}

type Fetcher interface {
	Fetch(ctx context.Context, startIndex int, params QueryParams) (*Response, error)
}

type Syncer struct {
	store     Store
	fetcher   Fetcher
	batchSize int
	overlap   time.Duration
	maxAge    time.Duration
}

type Result struct {
	Records int64
	Cursor  time.Time
	Full    bool
}

func NewSyncer(store Store, fetcher Fetcher, batchSize int, overlap time.Duration) *Syncer {
	return &Syncer{
		store:     store,
		fetcher:   fetcher,
		batchSize: batchSize,
		overlap:   overlap,
		maxAge:    120 * 24 * time.Hour,
	}
}

func (s *Syncer) Sync(ctx context.Context, full bool) (Result, error) {
	if err := s.store.MarkSyncAttempt(ctx, SourceName); err != nil {
		return Result{}, err
	}

	now := time.Now().UTC()
	params, effectiveFull, err := s.buildParams(ctx, full, now)
	if err != nil {
		s.store.MarkSyncError(ctx, SourceName, err.Error())
		return Result{}, err
	}

	var total int64
	startIndex := 0
	for {
		resp, err := s.fetcher.Fetch(ctx, startIndex, params)
		if err != nil {
			s.store.MarkSyncError(ctx, SourceName, err.Error())
			return Result{}, err
		}
		vuls, matches := Parse(*resp)
		if len(vuls) > 0 {
			if err := s.applyBatch(ctx, vuls, matches); err != nil {
				s.store.MarkSyncError(ctx, SourceName, err.Error())
				return Result{}, err
			}
		}
		total += int64(len(vuls))

		startIndex += resp.ResultsPerPage
		if resp.ResultsPerPage <= 0 || startIndex >= resp.TotalResults {
			break
		}
	}

	if err := s.store.MarkSyncSuccess(ctx, SourceName, total, &now); err != nil {
		return Result{}, err
	}
	return Result{Records: total, Cursor: now, Full: effectiveFull}, nil
}

func (s *Syncer) buildParams(ctx context.Context, full bool, now time.Time) (QueryParams, bool, error) {
	if full {
		return QueryParams{}, true, nil
	}
	state, err := s.store.GetSyncState(ctx, SourceName)
	if err != nil {
		return QueryParams{}, false, err
	}
	if state.SyncCursor == nil {
		return QueryParams{}, true, nil
	}
	start := state.SyncCursor.Add(-s.overlap)
	minStart := now.Add(-s.maxAge)
	if start.Before(minStart) {
		start = minStart
	}
	return QueryParams{LastModStartDate: &start, LastModEndDate: &now}, false, nil
}

func (s *Syncer) applyBatch(ctx context.Context, vuls []model.Vulnerability, configs []model.Configuration) error {
	configsByCVE := make(map[string][]model.Configuration, len(vuls))
	for _, c := range configs {
		configsByCVE[c.CVEID] = append(configsByCVE[c.CVEID], c)
	}
	size := s.batchSize
	if size <= 0 {
		size = 500
	}
	for start := 0; start < len(vuls); start += size {
		end := start + size
		if end > len(vuls) {
			end = len(vuls)
		}
		chunk := vuls[start:end]
		if err := s.store.UpsertVulnerabilities(ctx, chunk); err != nil {
			return err
		}
		cveIDs := make([]string, len(chunk))
		chunkConfigs := make(map[string][]model.Configuration, len(chunk))
		for i, v := range chunk {
			cveIDs[i] = v.CVEID
			if cs := configsByCVE[v.CVEID]; len(cs) > 0 {
				chunkConfigs[v.CVEID] = cs
			}
		}
		if err := s.store.ReplaceConfigurations(ctx, cveIDs, chunkConfigs); err != nil {
			return err
		}
	}
	return nil
}
