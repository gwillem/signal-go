package signalservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

// HTTPClient communicates with the Signal server REST API.
type HTTPClient struct {
	baseURL    string
	httpClient *http.Client
	logger     *log.Logger
}

// NewHTTPClient creates a new HTTP client for the Signal API.
// If tlsConf is non-nil, it is used for TLS connections.
// If logger is nil, logging is disabled.
func NewHTTPClient(baseURL string, tlsConf *tls.Config, logger *log.Logger) *HTTPClient {
	client := &http.Client{}
	if tlsConf != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConf}
	}
	return &HTTPClient{
		baseURL:    baseURL,
		httpClient: client,
		logger:     logger,
	}
}

// authType specifies the authentication method for API requests.
type authType int

const (
	authNone  authType = iota // No authentication
	authBasic                 // HTTP Basic auth
)

// apiRequest holds parameters for a JSON API call.
type apiRequest struct {
	method   string
	path     string
	body     any      // marshaled to JSON if non-nil
	authType authType // authentication type
	auth     BasicAuth
}

// doJSON executes a JSON API request and returns the response body and status code.
// The caller should check the status code and handle errors appropriately.
func (c *HTTPClient) doJSON(ctx context.Context, req apiRequest) ([]byte, int, error) {
	var bodyReader io.Reader
	if req.body != nil {
		data, err := json.Marshal(req.body)
		if err != nil {
			return nil, 0, fmt.Errorf("httpclient: marshal request: %w", err)
		}
		bodyReader = bytes.NewReader(data)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.method, c.baseURL+req.path, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("httpclient: new request: %w", err)
	}

	if req.body != nil {
		httpReq.Header.Set("Content-Type", "application/json")
	}

	if req.authType == authBasic {
		httpReq.SetBasicAuth(req.auth.Username, req.auth.Password)
	}

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("httpclient: read response: %w", err)
	}

	return respBody, resp.StatusCode, nil
}

// do executes an HTTP request with automatic retry on 429 (Too Many Requests).
// It respects the Retry-After header, capping the wait at 10 minutes.
// Falls back to exponential backoff (5s, 10s, 20s) if no Retry-After is present.
func (c *HTTPClient) do(req *http.Request) (*http.Response, error) {
	const maxRetries = 3
	const maxWait = 10 * time.Minute

	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("httpclient: read request body: %w", err)
		}
	}

	for attempt := range maxRetries + 1 {
		if body != nil {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusTooManyRequests {
			logf(c.logger, "http %s %s → %d", req.Method, req.URL.Path, resp.StatusCode)
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
			logf(c.logger, "http %s %s → 429 (no retries left, Retry-After: %s)",
				req.Method, req.URL.Path, resp.Header.Get("Retry-After"))
			// Return a synthetic response so callers see the 429.
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     resp.Header,
				Body:       io.NopCloser(bytes.NewReader(respBody)),
				Request:    req,
			}, nil
		}

		logf(c.logger, "http %s %s → 429, retrying in %v (attempt %d/%d, Retry-After: %s)",
			req.Method, req.URL.Path, wait, attempt+1, maxRetries,
			resp.Header.Get("Retry-After"))

		select {
		case <-time.After(wait):
		case <-req.Context().Done():
			return nil, req.Context().Err()
		}
	}

	// unreachable
	return nil, fmt.Errorf("httpclient: retry loop exhausted")
}

// RegisterSecondaryDevice calls PUT /v1/devices/link to finalize device registration.
// Signal requires Basic auth with the phone number (e164) as username and a
// pre-generated password.
func (c *HTTPClient) RegisterSecondaryDevice(ctx context.Context, req *RegisterRequest, auth BasicAuth) (*RegisterResponse, error) {
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPut,
		path:     "/v1/devices/link",
		body:     req,
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: register: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: register: status %d: %s", status, respBody)
	}

	var result RegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal response: %w", err)
	}
	return &result, nil
}

// StaleDevicesError is returned when the server responds with 410,
// indicating that sessions for certain devices are outdated.
// The caller should delete those sessions, re-fetch pre-keys, and retry.
type StaleDevicesError struct {
	StaleDevices []int
}

func (e *StaleDevicesError) Error() string {
	return fmt.Sprintf("httpclient: stale devices: %v", e.StaleDevices)
}

// MismatchedDevicesError is returned when the server responds with 409,
// indicating device list mismatch (missing or extra devices).
type MismatchedDevicesError struct {
	MissingDevices []int `json:"missingDevices"`
	ExtraDevices   []int `json:"extraDevices"`
}

func (e *MismatchedDevicesError) Error() string {
	return fmt.Sprintf("httpclient: mismatched devices: missing=%v extra=%v", e.MissingDevices, e.ExtraDevices)
}

// SetAccountAttributes calls PUT /v1/accounts/attributes/ to update account attributes.
func (c *HTTPClient) SetAccountAttributes(ctx context.Context, attrs *AccountAttributes, auth BasicAuth) error {
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPut,
		path:     "/v1/accounts/attributes/",
		body:     attrs,
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return fmt.Errorf("httpclient: set attributes: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("httpclient: set attributes: status %d: %s", status, respBody)
	}
	return nil
}

// UploadPreKeys calls PUT /v2/keys?identity={aci|pni} to upload pre-keys.
func (c *HTTPClient) UploadPreKeys(ctx context.Context, identity string, keys *PreKeyUpload, auth BasicAuth) error {
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPut,
		path:     "/v2/keys?identity=" + identity,
		body:     keys,
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return fmt.Errorf("httpclient: upload keys: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("httpclient: upload keys: status %d: %s", status, respBody)
	}
	return nil
}

// CreateVerificationSession starts a new verification session for primary registration.
// POST /v1/verification/session
func (c *HTTPClient) CreateVerificationSession(ctx context.Context, number string) (*VerificationSessionResponse, error) {
	req := &VerificationSessionRequest{Number: number}
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPost,
		path:     "/v1/verification/session",
		body:     req,
		authType: authNone,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: create session: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: create session: status %d: %s", status, respBody)
	}

	var result VerificationSessionResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal session: %w", err)
	}
	return &result, nil
}

// GetSessionStatus retrieves the current state of a verification session.
// GET /v1/verification/session/{sessionId}
func (c *HTTPClient) GetSessionStatus(ctx context.Context, sessionID string) (*VerificationSessionResponse, error) {
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodGet,
		path:     "/v1/verification/session/" + sessionID,
		authType: authNone,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: get session: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get session: status %d: %s", status, respBody)
	}

	var result VerificationSessionResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal session: %w", err)
	}
	return &result, nil
}

// RequestVerificationCode requests an SMS or voice verification code.
// POST /v1/verification/session/{sessionId}/code
func (c *HTTPClient) RequestVerificationCode(ctx context.Context, sessionID, transport string) (*VerificationSessionResponse, error) {
	req := &RequestVerificationCodeRequest{
		Transport: transport,
		Client:    "android-2024-01",
	}
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPost,
		path:     "/v1/verification/session/" + sessionID + "/code",
		body:     req,
		authType: authNone,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: request code: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: request code: status %d: %s", status, respBody)
	}

	var result VerificationSessionResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal session: %w", err)
	}
	return &result, nil
}

// SubmitVerificationCode submits the 6-digit verification code.
// PUT /v1/verification/session/{sessionId}/code
func (c *HTTPClient) SubmitVerificationCode(ctx context.Context, sessionID, code string) (*VerificationSessionResponse, error) {
	req := &SubmitVerificationCodeRequest{Code: code}
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPut,
		path:     "/v1/verification/session/" + sessionID + "/code",
		body:     req,
		authType: authNone,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: submit code: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: submit code: status %d: %s", status, respBody)
	}

	var result VerificationSessionResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal session: %w", err)
	}
	return &result, nil
}

// UpdateSession submits a CAPTCHA or push challenge response.
// PATCH /v1/verification/session/{sessionId}
func (c *HTTPClient) UpdateSession(ctx context.Context, sessionID string, req *UpdateSessionRequest) (*VerificationSessionResponse, error) {
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPatch,
		path:     "/v1/verification/session/" + sessionID,
		body:     req,
		authType: authNone,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: update session: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: update session: status %d: %s", status, respBody)
	}

	var result VerificationSessionResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal session: %w", err)
	}
	return &result, nil
}

// RegisterPrimaryDevice registers a new primary device account.
// POST /v1/registration
// Auth uses phone number as username and generated password.
func (c *HTTPClient) RegisterPrimaryDevice(ctx context.Context, req *PrimaryRegistrationRequest, auth BasicAuth) (*PrimaryRegistrationResponse, error) {
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPost,
		path:     "/v1/registration",
		body:     req,
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: register primary: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: register primary: status %d: %s", status, respBody)
	}

	var result PrimaryRegistrationResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal registration: %w", err)
	}
	return &result, nil
}

// decodeBase64 decodes a base64 string (with or without padding).
func decodeBase64(s string) ([]byte, error) {
	// Try standard base64 first, then raw (no padding)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
