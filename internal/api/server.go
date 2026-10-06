package api

import (
	"context"
	"crypto/subtle"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/config"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/db"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/metrics"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/resolver"
)

type Store interface {
	Ping(ctx context.Context) error
	GetVulnerability(ctx context.Context, cveID string) (*model.Vulnerability, error)
	GetCPEMatches(ctx context.Context, cveID string) ([]model.CPEMatch, error)
	SearchVulnerabilities(ctx context.Context, p db.SearchParams) ([]model.Vulnerability, int64, error)
	Stats(ctx context.Context) (cveCount, cpeCount, kevCount int64, err error)
	GetSyncState(ctx context.Context, source string) (*model.SyncState, error)
}

type Server struct {
	cfg      config.Config
	store    Store
	resolver *resolver.Resolver
	logger   *slog.Logger
	metrics  *metrics.Registry
}

func New(cfg config.Config, store Store, r *resolver.Resolver, logger *slog.Logger, m *metrics.Registry) http.Handler {
	s := &Server{cfg: cfg, store: store, resolver: r, logger: logger, metrics: m}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /health/live", s.handleLive)
	mux.HandleFunc("GET /health/ready", s.handleReady)
	mux.HandleFunc("GET /v1/status", s.handleStatus)
	mux.HandleFunc("GET /v1/cves", s.handleSearch)
	mux.HandleFunc("GET /v1/cves/{cve_id}", s.handleCVE)
	mux.HandleFunc("POST /v1/resolve", s.handleResolve)
	mux.HandleFunc("POST /v1/resolve/batch", s.handleBatchResolve)
	mux.HandleFunc("GET /metrics", s.handleMetrics)

	var h http.Handler = mux
	h = s.recoverMiddleware(h)
	h = s.authMiddleware(h)
	h = s.loggingMiddleware(h)
	return h
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	if len(s.cfg.APIKeys) == 0 {
		return next
	}
	keys := map[string]bool{}
	for _, k := range s.cfg.APIKeys {
		keys[k] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/v1/") && r.URL.Path != "/metrics" {
			next.ServeHTTP(w, r)
			return
		}
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		token := ""
		if strings.HasPrefix(auth, prefix) {
			token = strings.TrimPrefix(auth, prefix)
		}
		ok := false
		for k := range keys {
			if subtle.ConstantTimeCompare([]byte(token), []byte(k)) == 1 {
				ok = true
				break
			}
		}
		if !ok {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		dur := time.Since(start)
		s.metrics.ObserveHTTP(r.Method, r.URL.Path, statusLabel(rec.status), dur.Seconds())
		s.logger.Info("http",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", dur.String(),
		)
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("panic", "err", rec)
				writeError(w, http.StatusInternalServerError, "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func statusLabel(code int) string {
	switch {
	case code >= 500:
		return "5xx"
	case code >= 400:
		return "4xx"
	default:
		return "2xx"
	}
}
