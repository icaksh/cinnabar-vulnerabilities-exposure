package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/db"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, errorResponse{Error: msg})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "alive"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		s.metrics.IncDBErrors("ping")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	cveCount, cpeCount, kevCount, err := s.store.Stats(ctx)
	if err != nil {
		s.metrics.IncDBErrors("stats")
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	nvd, _ := s.store.GetSyncState(ctx, "nvd")
	kev, _ := s.store.GetSyncState(ctx, "kev")

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"database": map[string]any{
			"cve_count":      cveCount,
			"cpe_rule_count": cpeCount,
			"kev_count":      kevCount,
		},
		"nvd": nvd,
		"kev": kev,
	})
}

func (s *Server) handleCVE(w http.ResponseWriter, r *http.Request) {
	cveID := r.PathValue("cve_id")
	if cveID == "" {
		writeError(w, http.StatusBadRequest, "missing cve_id")
		return
	}
	v, err := s.store.GetVulnerability(r.Context(), cveID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "cve not found")
			return
		}
		s.metrics.IncDBErrors("lookup")
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	matches, err := s.store.GetCPEMatches(r.Context(), cveID)
	if err != nil {
		s.metrics.IncDBErrors("lookup_cpe")
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"vulnerability": v,
		"cpe_matches":   matches,
	})
}

func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()

	p := db.SearchParams{
		CVE:     q.Get("cve"),
		Vendor:  q.Get("vendor"),
		Product: q.Get("product"),
	}

	severity := q.Get("severity")
	if severity != "" && !validSeverity(severity) {
		writeError(w, http.StatusBadRequest, "invalid severity")
		return
	}
	p.Severity = severity

	if v := q.Get("kev"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid kev filter")
			return
		}
		p.KEV = &b
	}
	if v := q.Get("modified_since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid modified_since")
			return
		}
		t = t.UTC()
		p.ModifiedSince = &t
	}

	p.Page = parseIntDefault(q.Get("page"), 0)
	p.PageSize = parseIntDefault(q.Get("page_size"), 20)
	if p.PageSize < 1 {
		p.PageSize = 1
	}
	if p.PageSize > s.cfg.MaxPageSize {
		p.PageSize = s.cfg.MaxPageSize
	}

	items, total, err := s.store.SearchVulnerabilities(r.Context(), p)
	if err != nil {
		s.metrics.IncDBErrors("search")
		writeError(w, http.StatusInternalServerError, "database error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":     total,
		"page":      p.Page,
		"page_size": p.PageSize,
		"items":     items,
	})
}

func (s *Server) handleResolve(w http.ResponseWriter, r *http.Request) {
	var req model.ResolveRequest
	if err := decodeBody(w, r, s.cfg.MaxBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	s.metrics.IncResolveRequests("single")
	res, err := s.resolver.Resolve(r.Context(), req)
	if err != nil {
		s.metrics.IncDBErrors("resolve")
		writeError(w, http.StatusInternalServerError, "resolution error")
		return
	}
	s.metrics.AddResolveMatches("single", int64(len(res.Matches)))
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"matches":   res.Matches,
		"uncertain": res.Uncertain,
	})
}

func (s *Server) handleBatchResolve(w http.ResponseWriter, r *http.Request) {
	var req model.BatchResolveRequest
	if err := decodeBody(w, r, s.cfg.MaxBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if len(req.Items) == 0 {
		writeError(w, http.StatusBadRequest, "no items provided")
		return
	}
	if len(req.Items) > s.cfg.MaxBatchItems {
		writeError(w, http.StatusBadRequest, "batch size exceeds limit")
		return
	}

	results := make([]model.BatchResolutionItem, 0, len(req.Items))
	for _, item := range req.Items {
		rr := model.ResolveRequest{
			CPEs:       item.CPEs,
			Product:    item.Product,
			Version:    item.Version,
			Method:     item.Method,
			Confidence: item.Confidence,
		}
		out := model.BatchResolutionItem{
			ClientRef: item.ClientRef,
			Status:    "ok",
			Matches:   []model.Match{},
			Uncertain: []model.Match{},
		}
		res, err := s.resolver.Resolve(r.Context(), rr)
		if err != nil {
			out.Status = "error"
		} else {
			out.Matches = res.Matches
			out.Uncertain = res.Uncertain
			if out.Matches == nil {
				out.Matches = []model.Match{}
			}
			if out.Uncertain == nil {
				out.Uncertain = []model.Match{}
			}
		}
		results = append(results, out)
	}

	s.metrics.IncResolveRequests("batch")
	var totalMatches int64
	for _, res := range results {
		totalMatches += int64(len(res.Matches))
	}
	s.metrics.AddResolveMatches("batch", totalMatches)

	writeJSON(w, http.StatusOK, model.BatchResolution{Results: results})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	_, _ = w.Write([]byte(s.metrics.Render()))
}

func decodeBody(w http.ResponseWriter, r *http.Request, maxBytes int64, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		return errors.New("invalid JSON body")
	}
	return nil
}

func parseIntDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 {
		return def
	}
	return n
}

func validSeverity(s string) bool {
	switch s {
	case "NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN":
		return true
	default:
		return false
	}
}
