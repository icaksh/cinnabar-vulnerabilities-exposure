package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr string

	DatabaseURL string

	NVDBaseURL string
	NVDAPIKey  string
	KEVURL     string

	NVDSyncInterval time.Duration
	KEVSyncInterval time.Duration
	NVDRateLimit    time.Duration
	KEVRateLimit    time.Duration

	APIKeys []string

	MaxBatchItems int
	MaxBodyBytes  int64
	MaxPageSize   int

	LogLevel string

	NVDIncrementalOverlap time.Duration
	SyncBatchSize         int
}

func Load() Config {
	return Config{
		HTTPAddr:    env("CVE_HTTP_ADDR", ":8080"),
		DatabaseURL: env("DATABASE_URL", "postgres://cve:cve@localhost:5432/cve?sslmode=disable"),
		NVDBaseURL:  env("NVD_BASE_URL", "https://services.nvd.nist.gov"),
		NVDAPIKey:   os.Getenv("NVD_API_KEY"),
		KEVURL:      env("CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"),

		NVDSyncInterval: envDuration("NVD_SYNC_INTERVAL", 30*time.Minute),
		KEVSyncInterval: envDuration("KEV_SYNC_INTERVAL", 2*time.Hour),
		NVDRateLimit:    envDuration("NVD_RATE_LIMIT", 0),
		KEVRateLimit:    envDuration("KEV_RATE_LIMIT", 0),

		APIKeys: splitCSV(os.Getenv("CVE_API_KEYS")),

		MaxBatchItems: envInt("CVE_MAX_BATCH_ITEMS", 1000),
		MaxBodyBytes:  int64(envInt("CVE_MAX_BODY_BYTES", 1<<20)),
		MaxPageSize:   envInt("CVE_MAX_PAGE_SIZE", 100),

		LogLevel: env("CVE_LOG_LEVEL", "info"),

		NVDIncrementalOverlap: envDuration("NVD_INCREMENTAL_OVERLAP", 24*time.Hour),
		SyncBatchSize:         envInt("SYNC_BATCH_SIZE", 500),
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}

func splitCSV(v string) []string {
	if v == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
