package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
)

type counterMap struct {
	mu sync.Mutex
	m  map[string]*atomic.Int64
}

func newCounterMap() counterMap {
	return counterMap{m: map[string]*atomic.Int64{}}
}

func (c *counterMap) add(key string, n int64) {
	c.mu.Lock()
	v, ok := c.m[key]
	if !ok {
		v = &atomic.Int64{}
		c.m[key] = v
	}
	c.mu.Unlock()
	v.Add(n)
}

func (c *counterMap) snapshot() map[string]int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int64, len(c.m))
	for k, v := range c.m {
		out[k] = v.Load()
	}
	return out
}

type histogram struct {
	mu      sync.Mutex
	buckets []float64
	m       map[string][]int64
	sum     map[string]float64
	count   map[string]int64
}

func newHistogram(buckets []float64) histogram {
	return histogram{
		buckets: buckets,
		m:       map[string][]int64{},
		sum:     map[string]float64{},
		count:   map[string]int64{},
	}
}

func (h *histogram) observe(key string, v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.m[key]; !ok {
		h.m[key] = make([]int64, len(h.buckets))
	}
	for i, b := range h.buckets {
		if v <= b {
			h.m[key][i]++
		}
	}
	h.sum[key] += v
	h.count[key]++
}

func (h *histogram) snapshot() map[string]struct {
	Buckets []int64
	Sum     float64
	Count   int64
} {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]struct {
		Buckets []int64
		Sum     float64
		Count   int64
	}{}
	for k := range h.m {
		out[k] = struct {
			Buckets []int64
			Sum     float64
			Count   int64
		}{Buckets: h.m[k], Sum: h.sum[k], Count: h.count[k]}
	}
	return out
}

type Registry struct {
	httpRequests    counterMap
	httpDuration    histogram
	resolveRequests counterMap
	resolveMatches  counterMap
	syncRecords     counterMap
	syncFailures    counterMap
	syncDuration    histogram
	dbErrors        counterMap
}

func NewRegistry() *Registry {
	return &Registry{
		httpRequests:    newCounterMap(),
		httpDuration:    newHistogram([]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}),
		resolveRequests: newCounterMap(),
		resolveMatches:  newCounterMap(),
		syncRecords:     newCounterMap(),
		syncFailures:    newCounterMap(),
		syncDuration:    newHistogram([]float64{1, 5, 10, 30, 60, 120, 300, 600, 1800, 3600}),
		dbErrors:        newCounterMap(),
	}
}

func (r *Registry) ObserveHTTP(method, path, code string, durSec float64) {
	r.httpRequests.add(strings.Join([]string{method, path, code}, "\x00"), 1)
	r.httpDuration.observe(strings.Join([]string{method, path}, "\x00"), durSec)
}

func (r *Registry) IncResolveRequests(kind string) {
	r.resolveRequests.add(kind, 1)
}

func (r *Registry) AddResolveMatches(kind string, n int64) {
	r.resolveMatches.add(kind, n)
}

func (r *Registry) AddSyncRecords(source string, n int64) {
	r.syncRecords.add(source, n)
}

func (r *Registry) IncSyncFailures(source string) {
	r.syncFailures.add(source, 1)
}

func (r *Registry) ObserveSyncDuration(source string, durSec float64) {
	r.syncDuration.observe(source, durSec)
}

func (r *Registry) IncDBErrors(op string) {
	r.dbErrors.add(op, 1)
}

func (r *Registry) Render() string {
	var b strings.Builder

	writeCounter := func(name, help string, m map[string]int64) {
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s counter\n", name)
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "" {
				fmt.Fprintf(&b, "%s %d\n", name, m[k])
			} else {
				fmt.Fprintf(&b, "%s{key=%q} %d\n", name, k, m[k])
			}
		}
	}

	writeHistogram := func(name, help string, h *histogram) {
		snap := h.snapshot()
		fmt.Fprintf(&b, "# HELP %s %s\n", name, help)
		fmt.Fprintf(&b, "# TYPE %s histogram\n", name)
		keys := make([]string, 0, len(snap))
		for k := range snap {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := snap[k]
			cum := int64(0)
			for i, bnd := range h.buckets {
				cum += v.Buckets[i]
				label := fmt.Sprintf("%s_bucket{key=%q,le=%q}", name, k, formatFloat(bnd))
				fmt.Fprintf(&b, "%s %d\n", label, cum)
			}
			fmt.Fprintf(&b, "%s_bucket{key=%q,le=\"+Inf\"} %d\n", name, k, v.Count)
			fmt.Fprintf(&b, "%s_sum{key=%q} %s\n", name, k, formatFloat(v.Sum))
			fmt.Fprintf(&b, "%s_count{key=%q} %d\n", name, k, v.Count)
		}
	}

	writeCounter("cve_http_requests_total", "Total HTTP requests", r.httpRequests.snapshot())
	writeHistogram("cve_http_request_duration_seconds", "HTTP request duration in seconds", &r.httpDuration)
	writeCounter("cve_resolve_requests_total", "Resolver requests", r.resolveRequests.snapshot())
	writeCounter("cve_resolve_matches_total", "Resolver matches produced", r.resolveMatches.snapshot())
	writeCounter("cve_sync_records_total", "Records processed per source", r.syncRecords.snapshot())
	writeCounter("cve_sync_failures_total", "Sync failures per source", r.syncFailures.snapshot())
	writeHistogram("cve_sync_duration_seconds", "Sync duration in seconds", &r.syncDuration)
	writeCounter("cve_db_errors_total", "Database errors", r.dbErrors.snapshot())

	return b.String()
}

func formatFloat(f float64) string {
	return fmt.Sprintf("%g", f)
}
