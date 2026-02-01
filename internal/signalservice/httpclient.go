package signalservice

import (
	"bytes"
	"context"
	"crypto/tls"
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
// If tlsConf is non-nil, it is used for TLS connections.
func NewHTTPClient(baseURL string, tlsConf *tls.Config) *HTTPClient {
	client := &http.Client{}
	if tlsConf != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConf}
	}
	return &HTTPClient{
		baseURL:    baseURL,
		httpClient: client,
	}
}

// RegisterSecondaryDevice calls PUT /v1/devices/link to finalize device registration.
// Signal requires Basic auth with the phone number (e164) as username and a
// pre-generated password.
func (c *HTTPClient) RegisterSecondaryDevice(ctx context.Context, req *RegisterRequest, auth BasicAuth) (*RegisterResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: marshal register request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/devices/link", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(auth.Username, auth.Password)

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

// GetPreKeys fetches a recipient's pre-key bundle.
// GET /v2/keys/{destination}/{deviceId}
func (c *HTTPClient) GetPreKeys(ctx context.Context, destination string, deviceID int, auth BasicAuth) (*PreKeyResponse, error) {
	url := fmt.Sprintf("%s/v2/keys/%s/%d", c.baseURL, destination, deviceID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.SetBasicAuth(auth.Username, auth.Password)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: get pre-keys: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get pre-keys: status %d: %s", resp.StatusCode, respBody)
	}

	var result PreKeyResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal pre-keys: %w", err)
	}

	return &result, nil
}

// SendMessage sends an encrypted message to a destination.
// PUT /v1/messages/{destination}
func (c *HTTPClient) SendMessage(ctx context.Context, destination string, msg *OutgoingMessageList, auth BasicAuth) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("httpclient: marshal message: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/messages/"+destination, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(auth.Username, auth.Password)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("httpclient: send message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("httpclient: send message: status %d: %s", resp.StatusCode, respBody)
	}

	return nil
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
