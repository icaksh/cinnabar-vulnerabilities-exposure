package nvd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

type fakeStore struct {
	state           *model.SyncState
	vuls            map[string]model.Vulnerability
	cfgs            map[string][]model.Configuration
	replaceCalls    int
	attempts        int
	successes       int
	errorCalls      int
	lastCursor      *time.Time
	failUpsertAfter int
}

func (f *fakeStore) GetSyncState(_ context.Context, _ string) (*model.SyncState, error) {
	if f.state == nil {
		return &model.SyncState{Source: SourceName, Status: "idle"}, nil
	}
	return f.state, nil
}
func (f *fakeStore) MarkSyncAttempt(_ context.Context, _ string) error { f.attempts++; return nil }
func (f *fakeStore) MarkSyncSuccess(_ context.Context, _ string, records int64, cursor *time.Time) error {
	f.successes++
	f.lastCursor = cursor
	return nil
}
func (f *fakeStore) MarkSyncError(_ context.Context, _ string, _ string) error {
	f.errorCalls++
	return nil
}
func (f *fakeStore) UpsertVulnerabilities(_ context.Context, vuls []model.Vulnerability) error {
	if f.vuls == nil {
		f.vuls = map[string]model.Vulnerability{}
	}
	for _, v := range vuls {
		f.vuls[v.CVEID] = v
	}
	return nil
}
func (f *fakeStore) ReplaceConfigurations(_ context.Context, cveIDs []string, cfgs map[string][]model.Configuration) error {
	f.replaceCalls++
	if f.failUpsertAfter > 0 && f.replaceCalls >= f.failUpsertAfter {
		return errors.New("replace failed")
	}
	if f.cfgs == nil {
		f.cfgs = map[string][]model.Configuration{}
	}
	for _, id := range cveIDs {
		f.cfgs[id] = nil
	}
	for cveID, cs := range cfgs {
		f.cfgs[cveID] = cs
	}
	return nil
}

type fakeFetcher struct {
	pages            map[int]*Response
	calls            []QueryParams
	err              error
	failOnStartIndex int
}

func (f *fakeFetcher) Fetch(_ context.Context, startIndex int, params QueryParams) (*Response, error) {
	f.calls = append(f.calls, params)
	if f.err != nil && (f.failOnStartIndex < 0 || startIndex == f.failOnStartIndex) {
		return nil, f.err
	}
	return f.pages[startIndex], nil
}

func mkVuln(id, desc string) model.Vulnerability {
	return model.Vulnerability{CVEID: id, Description: desc, Severity: model.SeverityHigh}
}

func TestFullSyncPagination(t *testing.T) {
	store := &fakeStore{}
	fetcher := &fakeFetcher{pages: map[int]*Response{
		0: {ResultsPerPage: 2, StartIndex: 0, TotalResults: 4, Vulnerabilities: []VulnerabilityEntry{
			{CVE: cveRecord{ID: "CVE-1"}}, {CVE: cveRecord{ID: "CVE-2"}},
		}},
		2: {ResultsPerPage: 2, StartIndex: 2, TotalResults: 4, Vulnerabilities: []VulnerabilityEntry{
			{CVE: cveRecord{ID: "CVE-3"}}, {CVE: cveRecord{ID: "CVE-4"}},
		}},
	}}
	s := NewSyncer(store, fetcher, 10, time.Hour)
	res, err := s.Sync(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Records != 4 {
		t.Fatalf("records = %d, want 4", res.Records)
	}
	if len(store.vuls) != 4 {
		t.Fatalf("stored vulns = %d, want 4", len(store.vuls))
	}
	if store.successes != 1 || store.attempts != 1 {
		t.Fatalf("attempts=%d successes=%d", store.attempts, store.successes)
	}
	if len(fetcher.calls) != 2 {
		t.Fatalf("fetch calls = %d, want 2", len(fetcher.calls))
	}
}

func TestIncrementalSyncUsesCursor(t *testing.T) {
	cursor := time.Now().UTC().Add(-time.Hour)
	store := &fakeStore{state: &model.SyncState{Source: SourceName, Status: "success", SyncCursor: &cursor}}
	fetcher := &fakeFetcher{pages: map[int]*Response{
		0: {ResultsPerPage: 1, TotalResults: 1, Vulnerabilities: []VulnerabilityEntry{{CVE: cveRecord{ID: "CVE-9"}}}},
	}}
	s := NewSyncer(store, fetcher, 10, time.Hour)
	res, err := s.Sync(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if res.Full {
		t.Fatal("expected incremental, got full")
	}
	if len(fetcher.calls) != 1 {
		t.Fatalf("expected 1 fetch, got %d", len(fetcher.calls))
	}
	if fetcher.calls[0].LastModStartDate == nil {
		t.Fatal("expected LastModStartDate set for incremental")
	}
	if fetcher.calls[0].LastModEndDate == nil {
		t.Fatal("expected LastModEndDate set")
	}
}

func TestNoCursorBootstraps(t *testing.T) {
	store := &fakeStore{state: &model.SyncState{Source: SourceName, Status: "idle"}}
	fetcher := &fakeFetcher{pages: map[int]*Response{
		0: {ResultsPerPage: 1, TotalResults: 1, Vulnerabilities: []VulnerabilityEntry{{CVE: cveRecord{ID: "CVE-9"}}}},
	}}
	s := NewSyncer(store, fetcher, 10, time.Hour)
	res, err := s.Sync(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Full {
		t.Fatal("expected full bootstrap when no cursor")
	}
	if fetcher.calls[0].LastModStartDate != nil {
		t.Fatal("expected no LastModStartDate for bootstrap")
	}
	if fetcher.calls[0].LastModEndDate != nil {
		t.Fatal("expected no LastModEndDate for bootstrap")
	}
}

func TestFailedRequestMarksError(t *testing.T) {
	store := &fakeStore{}
	fetcher := &fakeFetcher{err: errors.New("nvd down"), failOnStartIndex: -1}
	s := NewSyncer(store, fetcher, 10, time.Hour)
	_, err := s.Sync(context.Background(), true)
	if err == nil {
		t.Fatal("expected error")
	}
	if store.errorCalls != 1 {
		t.Fatalf("error calls = %d, want 1", store.errorCalls)
	}
	if store.successes != 0 {
		t.Fatal("expected no success")
	}
}

func TestPartialSyncPreservesGoodData(t *testing.T) {
	store := &fakeStore{failUpsertAfter: 2}
	fetcher := &fakeFetcher{pages: map[int]*Response{
		0: {ResultsPerPage: 3, TotalResults: 6, Vulnerabilities: []VulnerabilityEntry{
			{CVE: cveRecord{ID: "CVE-1"}}, {CVE: cveRecord{ID: "CVE-2"}}, {CVE: cveRecord{ID: "CVE-3"}},
		}},
		3: {ResultsPerPage: 3, TotalResults: 6, Vulnerabilities: []VulnerabilityEntry{
			{CVE: cveRecord{ID: "CVE-4"}}, {CVE: cveRecord{ID: "CVE-5"}}, {CVE: cveRecord{ID: "CVE-6"}},
		}},
	}}
	s := NewSyncer(store, fetcher, 2, time.Hour)
	_, err := s.Sync(context.Background(), true)
	if err == nil {
		t.Fatal("expected error")
	}
	if store.errorCalls != 1 {
		t.Fatalf("error calls = %d", store.errorCalls)
	}
	if _, ok := store.vuls["CVE-1"]; !ok {
		t.Fatal("expected CVE-1 to have been persisted before failure")
	}
}

func TestModifiedCVEUpdated(t *testing.T) {
	store := &fakeStore{vuls: map[string]model.Vulnerability{"CVE-1": mkVuln("CVE-1", "old")}}
	fetcher := &fakeFetcher{pages: map[int]*Response{
		0: {ResultsPerPage: 1, TotalResults: 1, Vulnerabilities: []VulnerabilityEntry{{CVE: cveRecord{ID: "CVE-1", Descriptions: []description{{Lang: "en", Value: "new"}}}}}},
	}}
	s := NewSyncer(store, fetcher, 10, time.Hour)
	if _, err := s.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if store.vuls["CVE-1"].Description != "new" {
		t.Fatalf("description = %q, want new", store.vuls["CVE-1"].Description)
	}
}

func TestIdempotentRepeat(t *testing.T) {
	store := &fakeStore{}
	fetcher := &fakeFetcher{pages: map[int]*Response{
		0: {ResultsPerPage: 1, TotalResults: 1, Vulnerabilities: []VulnerabilityEntry{{CVE: cveRecord{ID: "CVE-1"}}}},
	}}
	s := NewSyncer(store, fetcher, 10, time.Hour)
	if _, err := s.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Sync(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(store.vuls) != 1 {
		t.Fatalf("vulns after repeat = %d, want 1", len(store.vuls))
	}
	if store.replaceCalls != 2 {
		t.Fatalf("replace calls = %d, want 2", store.replaceCalls)
	}
}
