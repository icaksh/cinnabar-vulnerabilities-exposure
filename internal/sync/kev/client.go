package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"time"

	"github.com/icaksh/cinnabar-vulnerabilities-exposure/internal/model"
)

const SourceName = "kev"

type feed struct {
	Vulnerabilities []entry `json:"vulnerabilities"`
}

type entry struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse"`
	Notes                      string   `json:"notes"`
	CWEs                       []string `json:"cwes"`
}

type Client struct {
	url        string
	httpClient *http.Client
	maxRetries int
}

func NewClient(url string, maxRetries int) *Client {
	return &Client{
		url:        url,
		httpClient: &http.Client{Timeout: 60 * time.Second},
		maxRetries: maxRetries,
	}
}

func (c *Client) Fetch(ctx context.Context) ([]model.PendingKEV, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		entries, err := c.fetchOnce(ctx)
		if err == nil {
			return entries, nil
		}
		lastErr = err
		if !retryable(err) {
			return nil, err
		}
		if attempt == c.maxRetries {
			break
		}
		select {
		case <-time.After(backoff(attempt)):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return nil, lastErr
}

func (c *Client) fetchOnce(ctx context.Context) ([]model.PendingKEV, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("kev http %d: %s", resp.StatusCode, string(body))
	}
	var f feed
	if err := json.NewDecoder(resp.Body).Decode(&f); err != nil {
		return nil, err
	}
	return Parse(f), nil
}

func Parse(f feed) []model.PendingKEV {
	out := make([]model.PendingKEV, 0, len(f.Vulnerabilities))
	for _, e := range f.Vulnerabilities {
		raw, _ := json.Marshal(e)
		out = append(out, model.PendingKEV{
			CVEID:                      e.CVEID,
			DateAdded:                  parseDate(e.DateAdded),
			DueDate:                    parseDate(e.DueDate),
			RequiredAction:             strPtr(e.RequiredAction),
			KnownRansomwareCampaignUse: e.KnownRansomwareCampaignUse == "Known",
			Raw:                        raw,
		})
	}
	return out
}

func parseDate(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return nil
	}
	t = t.UTC()
	return &t
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func retryable(err error) bool {
	return err != nil
}

func backoff(attempt int) time.Duration {
	base := time.Second << attempt
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(base) / 4))
	return base + jitter
}
