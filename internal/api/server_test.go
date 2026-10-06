package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/config"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/db"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/metrics"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/resolver"
)

type fakeStore struct {
	pingErr     error
	vulns       map[string]*model.Vulnerability
	cpeMatches  map[string][]model.CPEMatch
	candidates  map[string][]model.CPEMatch
	searchItems []model.Vulnerability
	searchTotal int64
	statsCVE    int64
	statsCPE    int64
	statsKEV    int64
	syncStates  map[string]*model.SyncState
}

func (f *fakeStore) Ping(context.Context) error { return f.pingErr }
func (f *fakeStore) GetVulnerability(_ context.Context, id string) (*model.Vulnerability, error) {
	if v, ok := f.vulns[id]; ok {
		return v, nil
	}
	return nil, pgx.ErrNoRows
}
func (f *fakeStore) GetCPEMatches(_ context.Context, id string) ([]model.CPEMatch, error) {
	return f.cpeMatches[id], nil
}
func (f *fakeStore) SearchVulnerabilities(_ context.Context, _ db.SearchParams) ([]model.Vulnerability, int64, error) {
	return f.searchItems, f.searchTotal, nil
}
func (f *fakeStore) Stats(_ context.Context) (int64, int64, int64, error) {
	return f.statsCVE, f.statsCPE, f.statsKEV, nil
}
func (f *fakeStore) GetSyncState(_ context.Context, source string) (*model.SyncState, error) {
	if s, ok := f.syncStates[source]; ok {
		return s, nil
	}
	return &model.SyncState{Source: source, Status: "idle"}, nil
}
func (f *fakeStore) CandidateLookup(_ context.Context, part, vendor, product string) ([]model.CPEMatch, error) {
	return f.candidates[vendor+"|"+product], nil
}
func (f *fakeStore) GetVulnerabilitiesByIDs(_ context.Context, ids []string) (map[string]model.Vulnerability, error) {
	out := map[string]model.Vulnerability{}
	for _, id := range ids {
		if v, ok := f.vulns[id]; ok {
			out[id] = *v
		}
	}
	return out, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestHandler(cfg config.Config, store *fakeStore) http.Handler {
	r := resolver.New(store)
	m := metrics.NewRegistry()
	return New(cfg, store, r, testLogger(), m)
}

func doRequest(t *testing.T, h http.Handler, method, path, body string, auth string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func defaultTestConfig() config.Config {
	return config.Config{
		MaxBatchItems: 5,
		MaxBodyBytes:  1 << 20,
		MaxPageSize:   100,
	}
}

func TestHealthEndpoints(t *testing.T) {
	store := &fakeStore{}
	h := newTestHandler(defaultTestConfig(), store)

	if rec := doRequest(t, h, http.MethodGet, "/health", "", ""); rec.Code != 200 {
		t.Fatalf("health = %d", rec.Code)
	}
	if rec := doRequest(t, h, http.MethodGet, "/health/live", "", ""); rec.Code != 200 {
		t.Fatalf("live = %d", rec.Code)
	}
}

func TestReadinessDatabaseUnavailable(t *testing.T) {
	store := &fakeStore{pingErr: context.DeadlineExceeded}
	h := newTestHandler(defaultTestConfig(), store)
	if rec := doRequest(t, h, http.MethodGet, "/health/ready", "", ""); rec.Code != 503 {
		t.Fatalf("ready = %d, want 503", rec.Code)
	}
}

func TestReadinessOK(t *testing.T) {
	store := &fakeStore{}
	h := newTestHandler(defaultTestConfig(), store)
	if rec := doRequest(t, h, http.MethodGet, "/health/ready", "", ""); rec.Code != 200 {
		t.Fatalf("ready = %d, want 200", rec.Code)
	}
}

func TestAuthRequired(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.APIKeys = []string{"secret"}
	store := &fakeStore{}
	h := newTestHandler(cfg, store)

	if rec := doRequest(t, h, http.MethodGet, "/v1/status", "", ""); rec.Code != 401 {
		t.Fatalf("status without auth = %d, want 401", rec.Code)
	}
	if rec := doRequest(t, h, http.MethodGet, "/v1/status", "", "secret"); rec.Code != 200 {
		t.Fatalf("status with auth = %d, want 200", rec.Code)
	}
	if rec := doRequest(t, h, http.MethodGet, "/v1/status", "", "wrong"); rec.Code != 401 {
		t.Fatalf("status with wrong auth = %d, want 401", rec.Code)
	}
	// health stays unauthenticated
	if rec := doRequest(t, h, http.MethodGet, "/health", "", ""); rec.Code != 200 {
		t.Fatalf("health = %d, want 200", rec.Code)
	}
}

func TestStatusEndpoint(t *testing.T) {
	store := &fakeStore{
		statsCVE: 10, statsCPE: 20, statsKEV: 3,
		syncStates: map[string]*model.SyncState{"nvd": {Source: "nvd", Status: "success"}},
	}
	h := newTestHandler(defaultTestConfig(), store)
	rec := doRequest(t, h, http.MethodGet, "/v1/status", "", "")
	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["status"] != "ok" {
		t.Fatalf("status field = %v", out["status"])
	}
}

func TestCVELookup(t *testing.T) {
	store := &fakeStore{
		vulns: map[string]*model.Vulnerability{
			"CVE-2020-0001": {CVEID: "CVE-2020-0001", Description: "desc", Severity: model.SeverityHigh},
		},
	}
	h := newTestHandler(defaultTestConfig(), store)

	if rec := doRequest(t, h, http.MethodGet, "/v1/cves/CVE-2020-0001", "", ""); rec.Code != 200 {
		t.Fatalf("lookup = %d", rec.Code)
	}
	if rec := doRequest(t, h, http.MethodGet, "/v1/cves/CVE-NOPE", "", ""); rec.Code != 404 {
		t.Fatalf("missing lookup = %d, want 404", rec.Code)
	}
}

func TestCVESearch(t *testing.T) {
	store := &fakeStore{
		searchItems: []model.Vulnerability{{CVEID: "CVE-1"}},
		searchTotal: 1,
	}
	h := newTestHandler(defaultTestConfig(), store)
	rec := doRequest(t, h, http.MethodGet, "/v1/cves?severity=HIGH&page=0&page_size=10", "", "")
	if rec.Code != 200 {
		t.Fatalf("search = %d", rec.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out["total"].(float64) != 1 {
		t.Fatalf("total = %v", out["total"])
	}
}

func TestSearchInvalidSeverity(t *testing.T) {
	store := &fakeStore{}
	h := newTestHandler(defaultTestConfig(), store)
	if rec := doRequest(t, h, http.MethodGet, "/v1/cves?severity=BOGUS", "", ""); rec.Code != 400 {
		t.Fatalf("search invalid severity = %d, want 400", rec.Code)
	}
}

func TestResolveEndpoint(t *testing.T) {
	store := &fakeStore{
		candidates: map[string][]model.CPEMatch{
			"v|p": {
				{CVEID: "CVE-1", Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", Part: "a", Vendor: "v", Product: "p", Version: "*", Vulnerable: true},
			},
		},
		vulns: map[string]*model.Vulnerability{
			"CVE-1": {CVEID: "CVE-1", Severity: model.SeverityHigh},
		},
	}
	h := newTestHandler(defaultTestConfig(), store)

	body := `{"cpes":["cpe:/a:v:p:1.0"],"product":"p","version":"1.0","method":"probed","confidence":10}`
	rec := doRequest(t, h, http.MethodPost, "/v1/resolve", body, "")
	if rec.Code != 200 {
		t.Fatalf("resolve = %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Status  string        `json:"status"`
		Matches []model.Match `json:"matches"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "ok" || len(out.Matches) != 1 {
		t.Fatalf("out = %+v", out)
	}
	if out.Matches[0].CVEID != "CVE-1" {
		t.Fatalf("match = %+v", out.Matches[0])
	}
}

func TestResolveInvalidPayload(t *testing.T) {
	store := &fakeStore{}
	h := newTestHandler(defaultTestConfig(), store)
	if rec := doRequest(t, h, http.MethodPost, "/v1/resolve", `{not json`, ""); rec.Code != 400 {
		t.Fatalf("invalid payload = %d, want 400", rec.Code)
	}
}

func TestBatchLimit(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.MaxBatchItems = 2
	store := &fakeStore{}
	h := newTestHandler(cfg, store)

	items := make([]map[string]any, 3)
	for i := range items {
		items[i] = map[string]any{"client_ref": "r", "cpes": []string{"cpe:/a:v:p:1.0"}}
	}
	body, _ := json.Marshal(map[string]any{"items": items})
	rec := doRequest(t, h, http.MethodPost, "/v1/resolve/batch", string(body), "")
	if rec.Code != 400 {
		t.Fatalf("batch over limit = %d, want 400", rec.Code)
	}
}

func TestBatchResolveEchoesClientRef(t *testing.T) {
	store := &fakeStore{
		candidates: map[string][]model.CPEMatch{
			"v|p": {{CVEID: "CVE-1", Criteria: "cpe:2.3:a:v:p:*:*:*:*:*:*:*:*", Part: "a", Vendor: "v", Product: "p", Version: "*", Vulnerable: true}},
		},
		vulns: map[string]*model.Vulnerability{"CVE-1": {CVEID: "CVE-1"}},
	}
	h := newTestHandler(defaultTestConfig(), store)

	body := `{"items":[{"client_ref":"opaque-42","cpes":["cpe:/a:v:p:1.0"]}]}`
	rec := doRequest(t, h, http.MethodPost, "/v1/resolve/batch", body, "")
	if rec.Code != 200 {
		t.Fatalf("batch = %d: %s", rec.Code, rec.Body.String())
	}
	var out model.BatchResolution
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 || out.Results[0].ClientRef != "opaque-42" {
		t.Fatalf("results = %+v", out.Results)
	}
}

func TestBodyTooLarge(t *testing.T) {
	cfg := defaultTestConfig()
	cfg.MaxBodyBytes = 10
	store := &fakeStore{}
	h := newTestHandler(cfg, store)

	var buf bytes.Buffer
	buf.WriteString(`{"cpes":["cpe:/a:v:p:1.0"],"version":"1.0.0.0.0"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/resolve", &buf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 400 {
		t.Fatalf("oversized body = %d, want 400", rec.Code)
	}
}
