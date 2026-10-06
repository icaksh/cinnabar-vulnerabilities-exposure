package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

const defaultResultsPerPage = 2000

type Client struct {
	baseURL     string
	apiKey      string
	httpClient  *http.Client
	minInterval time.Duration
	maxRetries  int

	mu          sync.Mutex
	nextAllowed time.Time
}

func NewClient(baseURL, apiKey string, minInterval time.Duration, maxRetries int) *Client {
	return &Client{
		baseURL:     baseURL,
		apiKey:      apiKey,
		httpClient:  &http.Client{Timeout: 60 * time.Second},
		minInterval: minInterval,
		maxRetries:  maxRetries,
	}
}

type FetchError struct {
	StatusCode int
	Message    string
}

func (e *FetchError) Error() string {
	return fmt.Sprintf("nvd http %d: %s", e.StatusCode, e.Message)
}

func (c *Client) Fetch(ctx context.Context, startIndex int, params QueryParams) (*Response, error) {
	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if err := c.waitRate(ctx); err != nil {
			return nil, err
		}
		resp, err := c.fetchOnce(ctx, startIndex, params)
		if err == nil {
			return resp, nil
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

func (c *Client) fetchOnce(ctx context.Context, startIndex int, params QueryParams) (*Response, error) {
	u, err := url.Parse(c.baseURL + "/rest/json/cves/2.0")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(defaultResultsPerPage))
	if params.LastModStartDate != nil {
		q.Set("lastModStartDate", formatNVDTime(*params.LastModStartDate))
	}
	if params.LastModEndDate != nil {
		q.Set("lastModEndDate", formatNVDTime(*params.LastModEndDate))
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("apiKey", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, &FetchError{StatusCode: resp.StatusCode, Message: string(body)}
	}

	dec := json.NewDecoder(resp.Body)
	var out Response
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) waitRate(ctx context.Context) error {
	if c.minInterval <= 0 {
		return nil
	}
	c.mu.Lock()
	now := time.Now()
	var wait time.Duration
	if now.Before(c.nextAllowed) {
		wait = c.nextAllowed.Sub(now)
		c.nextAllowed = c.nextAllowed.Add(c.minInterval)
	} else {
		c.nextAllowed = now.Add(c.minInterval)
	}
	c.mu.Unlock()
	if wait <= 0 {
		return nil
	}
	select {
	case <-time.After(wait):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func retryable(err error) bool {
	fe, ok := err.(*FetchError)
	if !ok {
		return true
	}
	switch fe.StatusCode {
	case http.StatusTooManyRequests,
		http.StatusInternalServerError,
		http.StatusBadGateway,
		http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func backoff(attempt int) time.Duration {
	base := time.Second << attempt
	if base > 30*time.Second {
		base = 30 * time.Second
	}
	jitter := time.Duration(rand.Int63n(int64(base) / 4))
	return base + jitter
}

func formatNVDTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000")
}
