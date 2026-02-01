package signalservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// HTTPClient communicates with the Signal server REST API.
type HTTPClient struct {
	baseURL    string
	httpClient *http.Client
}

// NewHTTPClient creates a new HTTP client for the Signal API.
func NewHTTPClient(baseURL string) *HTTPClient {
	return &HTTPClient{
		baseURL:    baseURL,
		httpClient: &http.Client{},
	}
}

// RegisterSecondaryDevice calls PUT /v1/devices/link to finalize device registration.
func (c *HTTPClient) RegisterSecondaryDevice(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: marshal register request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/devices/link", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: register: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: register: status %d: %s", resp.StatusCode, respBody)
	}

	var result RegisterResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal response: %w", err)
	}

	return &result, nil
}

// UploadPreKeys calls PUT /v2/keys?identity={aci|pni} to upload pre-keys.
func (c *HTTPClient) UploadPreKeys(ctx context.Context, identity string, keys *PreKeyUpload, auth BasicAuth) error {
	body, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("httpclient: marshal pre-keys: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v2/keys?identity="+identity, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(auth.Username, auth.Password)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("httpclient: upload keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("httpclient: upload keys: status %d: %s", resp.StatusCode, respBody)
	}

	return nil
}
