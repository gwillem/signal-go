package signalservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

// Transport handles low-level HTTP communication with the Signal API.
// It manages rate limiting, auth headers, and request/response logging.
type Transport struct {
	baseURL string
	client  *http.Client
	logger  *log.Logger
}

// NewTransport creates a new HTTP transport for the Signal API.
func NewTransport(baseURL string, tlsConf *tls.Config, logger *log.Logger) *Transport {
	client := &http.Client{}
	if tlsConf != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConf}
	}
	return &Transport{
		baseURL: baseURL,
		client:  client,
		logger:  logger,
	}
}

// Do executes an HTTP request with automatic retry on 429 (Too Many Requests).
// It respects the Retry-After header, capping the wait at 10 minutes.
func (t *Transport) Do(req *http.Request) (*http.Response, error) {
	const maxRetries = 3
	const maxWait = 10 * time.Minute

	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("transport: read request body: %w", err)
		}
	}

	for attempt := range maxRetries + 1 {
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		resp, err := t.client.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			logf(t.logger, "http %s %s → %d", req.Method, req.URL.Path, resp.StatusCode)
			return resp, nil
		}

		// 429 — read body for logging, then close it before sleeping.
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		wait := time.Duration(5<<attempt) * time.Second // 5s, 10s, 20s, 40s
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if secs, err := strconv.Atoi(ra); err == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
		}
		wait = min(wait, maxWait)

		if attempt == maxRetries {
			logf(t.logger, "http %s %s → 429 (no retries left, Retry-After: %s)",
				req.Method, req.URL.Path, resp.Header.Get("Retry-After"))
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     resp.Header,
				Body:       io.NopCloser(bytes.NewReader(respBody)),
				Request:    req,
			}, nil
		}

		logf(t.logger, "http %s %s → 429, retrying in %v (attempt %d/%d, Retry-After: %s)",
			req.Method, req.URL.Path, wait, attempt+1, maxRetries,
			resp.Header.Get("Retry-After"))

		select {
		case <-time.After(wait):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	return nil, fmt.Errorf("transport: retry loop exhausted")
}

// Get performs a GET request with optional basic auth.
func (t *Transport) Get(ctx context.Context, path string, auth *BasicAuth) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.baseURL+path, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("transport: new request: %w", err)
	}
	if auth != nil {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
	return t.doAndRead(req)
}

// Put performs a PUT request with JSON body and optional basic auth.
func (t *Transport) Put(ctx context.Context, path string, body []byte, auth *BasicAuth) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, t.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("transport: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != nil {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
	return t.doAndRead(req)
}

// Post performs a POST request with JSON body and optional basic auth.
func (t *Transport) Post(ctx context.Context, path string, body []byte, auth *BasicAuth) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("transport: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != nil {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
	return t.doAndRead(req)
}

// Patch performs a PATCH request with JSON body and optional basic auth.
func (t *Transport) Patch(ctx context.Context, path string, body []byte, auth *BasicAuth) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, t.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("transport: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if auth != nil {
		req.SetBasicAuth(auth.Username, auth.Password)
	}
	return t.doAndRead(req)
}

// PutWithHeader performs a PUT request with a custom header (e.g., for sealed sender).
func (t *Transport) PutWithHeader(ctx context.Context, path string, body []byte, headerKey, headerValue string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, t.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("transport: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerKey, headerValue)
	return t.doAndRead(req)
}

// doAndRead executes the request and reads the response body.
func (t *Transport) doAndRead(req *http.Request) ([]byte, int, error) {
	resp, err := t.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("transport: read response: %w", err)
	}
	return body, resp.StatusCode, nil
}

// GetJSON performs a GET request and unmarshals the response into result.
func (t *Transport) GetJSON(ctx context.Context, path string, auth *BasicAuth, result any) (int, error) {
	body, status, err := t.Get(ctx, path, auth)
	if err != nil {
		return status, err
	}
	if result != nil && len(body) > 0 {
		if err := json.Unmarshal(body, result); err != nil {
			return status, fmt.Errorf("transport: unmarshal response: %w", err)
		}
	}
	return status, nil
}

// PutJSON performs a PUT request with JSON body and optional basic auth.
func (t *Transport) PutJSON(ctx context.Context, path string, body any, auth *BasicAuth) ([]byte, int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("transport: marshal request: %w", err)
	}
	return t.Put(ctx, path, data, auth)
}

// PostJSON performs a POST request with JSON body and optional basic auth.
func (t *Transport) PostJSON(ctx context.Context, path string, body any, auth *BasicAuth) ([]byte, int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("transport: marshal request: %w", err)
	}
	return t.Post(ctx, path, data, auth)
}

// PatchJSON performs a PATCH request with JSON body and optional basic auth.
func (t *Transport) PatchJSON(ctx context.Context, path string, body any, auth *BasicAuth) ([]byte, int, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, 0, fmt.Errorf("transport: marshal request: %w", err)
	}
	return t.Patch(ctx, path, data, auth)
}
