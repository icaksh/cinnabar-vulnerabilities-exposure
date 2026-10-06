package sync

import (
	"context"
	"log/slog"
	"time"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/db"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/metrics"
	kevsync "github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/sync/kev"
	nvdsync "github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/sync/nvd"
)

type Worker struct {
	db          *db.DB
	nvd         *nvdsync.Syncer
	kev         *kevsync.Syncer
	nvdInterval time.Duration
	kevInterval time.Duration
	logger      *slog.Logger
	metrics     *metrics.Registry
}

func NewWorker(database *db.DB, nvd *nvdsync.Syncer, kev *kevsync.Syncer, nvdInterval, kevInterval time.Duration, logger *slog.Logger, m *metrics.Registry) *Worker {
	return &Worker{
		db:          database,
		nvd:         nvd,
		kev:         kev,
		nvdInterval: nvdInterval,
		kevInterval: kevInterval,
		logger:      logger,
		metrics:     m,
	}
}

func (w *Worker) Run(ctx context.Context) error {
	w.syncNVD(ctx)
	w.syncKEV(ctx)

	nvdTicker := time.NewTicker(w.nvdInterval)
	kevTicker := time.NewTicker(w.kevInterval)
	defer nvdTicker.Stop()
	defer kevTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-nvdTicker.C:
			w.syncNVD(ctx)
		case <-kevTicker.C:
			w.syncKEV(ctx)
		}
	}
}

func (w *Worker) syncNVD(ctx context.Context) {
	release, ok, err := w.db.TryAdvisoryLock(ctx, db.SourceLockKey(nvdsync.SourceName))
	if err != nil {
		w.logger.Error("nvd lock error", "err", err)
		return
	}
	if !ok {
		w.logger.Info("nvd sync already running, skipping")
		return
	}
	defer release()

	start := time.Now()
	res, err := w.nvd.Sync(ctx, false)
	w.metrics.ObserveSyncDuration("nvd", time.Since(start).Seconds())
	if err != nil {
		w.metrics.IncSyncFailures("nvd")
		w.logger.Error("nvd sync failed", "err", err)
		return
	}
	w.metrics.AddSyncRecords("nvd", res.Records)
	w.logger.Info("nvd sync complete", "records", res.Records, "full", res.Full, "duration", time.Since(start).String())

	if reconciled, err := w.db.ReconcilePendingKEV(ctx); err != nil {
		w.logger.Error("kev reconciliation failed", "err", err)
	} else if reconciled > 0 {
		w.logger.Info("kev reconciliation", "applied", reconciled)
	}
}

func (w *Worker) syncKEV(ctx context.Context) {
	release, ok, err := w.db.TryAdvisoryLock(ctx, db.SourceLockKey(kevsync.SourceName))
	if err != nil {
		w.logger.Error("kev lock error", "err", err)
		return
	}
	if !ok {
		w.logger.Info("kev sync already running, skipping")
		return
	}
	defer release()

	start := time.Now()
	res, err := w.kev.Sync(ctx)
	w.metrics.ObserveSyncDuration("kev", time.Since(start).Seconds())
	if err != nil {
		w.metrics.IncSyncFailures("kev")
		w.logger.Error("kev sync failed", "err", err)
		return
	}
	w.metrics.AddSyncRecords("kev", res.Records)
	w.logger.Info("kev sync complete", "records", res.Records, "applied", res.Applied, "pending", res.Pending, "duration", time.Since(start).String())
}
