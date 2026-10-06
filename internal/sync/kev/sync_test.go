package kev

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

type kevFakeStore struct {
	vulns      map[string]bool
	pending    []model.PendingKEV
	applied    int
	attempts   int
	successes  int
	errorCalls int
}

func (f *kevFakeStore) ApplyKEV(_ context.Context, cveID string, e model.PendingKEV) (bool, error) {
	if f.vulns[cveID] {
		f.applied++
		return true, nil
	}
	return false, nil
}
func (f *kevFakeStore) UpsertPendingKEV(_ context.Context, entries []model.PendingKEV) error {
	f.pending = append(f.pending, entries...)
	return nil
}
func (f *kevFakeStore) ReconcilePendingKEV(_ context.Context) (int, error) {
	n := 0
	var keep []model.PendingKEV
	for _, e := range f.pending {
		if f.vulns[e.CVEID] {
			f.applied++
			n++
		} else {
			keep = append(keep, e)
		}
	}
	f.pending = keep
	return n, nil
}
func (f *kevFakeStore) MarkSyncAttempt(_ context.Context, _ string) error { f.attempts++; return nil }
func (f *kevFakeStore) MarkSyncSuccess(_ context.Context, _ string, _ int64, _ *time.Time) error {
	f.successes++
	return nil
}
func (f *kevFakeStore) MarkSyncError(_ context.Context, _ string, _ string) error {
	f.errorCalls++
	return nil
}

type kevFakeFetcher struct {
	entries []model.PendingKEV
	err     error
}

func (f *kevFakeFetcher) Fetch(_ context.Context) ([]model.PendingKEV, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.entries, nil
}

func TestKEVSyncAppliesExisting(t *testing.T) {
	store := &kevFakeStore{vulns: map[string]bool{"CVE-1": true}}
	fetcher := &kevFakeFetcher{entries: []model.PendingKEV{{CVEID: "CVE-1"}}}
	s := NewSyncer(store, fetcher)
	res, err := s.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Applied != 1 || res.Pending != 0 {
		t.Fatalf("res = %+v", res)
	}
	if store.successes != 1 {
		t.Fatalf("successes = %d", store.successes)
	}
}

func TestKEVBeforeCVEGoesPending(t *testing.T) {
	store := &kevFakeStore{vulns: map[string]bool{}}
	fetcher := &kevFakeFetcher{entries: []model.PendingKEV{{CVEID: "CVE-404"}}}
	s := NewSyncer(store, fetcher)
	res, err := s.Sync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Pending != 1 || len(store.pending) != 1 {
		t.Fatalf("res = %+v pending = %+v", res, store.pending)
	}
}

func TestKEVReconciledAfterCVEArrives(t *testing.T) {
	store := &kevFakeStore{vulns: map[string]bool{}}
	fetcher := &kevFakeFetcher{entries: []model.PendingKEV{{CVEID: "CVE-404"}}}
	s := NewSyncer(store, fetcher)
	if _, err := s.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(store.pending) != 1 {
		t.Fatalf("expected 1 pending, got %d", len(store.pending))
	}

	store.vulns["CVE-404"] = true
	reconciled, err := store.ReconcilePendingKEV(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if reconciled != 1 {
		t.Fatalf("reconciled = %d, want 1", reconciled)
	}
	if len(store.pending) != 0 {
		t.Fatalf("pending after reconcile = %d, want 0", len(store.pending))
	}
}

func TestKEVSyncFetchError(t *testing.T) {
	store := &kevFakeStore{vulns: map[string]bool{}}
	fetcher := &kevFakeFetcher{err: errors.New("cisa down")}
	s := NewSyncer(store, fetcher)
	if _, err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error")
	}
	if store.errorCalls != 1 {
		t.Fatalf("error calls = %d", store.errorCalls)
	}
}
