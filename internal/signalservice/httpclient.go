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

	"github.com/gwillem/signal-go/internal/libsignal"
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

	resp, err := c.do(httpReq)
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

	resp, err := c.do(httpReq)
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

// SendMessage sends an encrypted message to a destination.
// PUT /v1/messages/{destination}
//
// Returns *StaleDevicesError for 410 and *MismatchedDevicesError for 409,
// allowing callers to handle session refresh and retry.
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

	resp, err := c.do(httpReq)
	if err != nil {
		return fmt.Errorf("httpclient: send message: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusGone: // 410
		var parsed struct {
			StaleDevices []int `json:"staleDevices"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return fmt.Errorf("httpclient: send message: status 410: %s", respBody)
		}
		return &StaleDevicesError{StaleDevices: parsed.StaleDevices}
	case http.StatusConflict: // 409
		var parsed MismatchedDevicesError
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return fmt.Errorf("httpclient: send message: status 409: %s", respBody)
		}
		return &parsed
	default:
		return fmt.Errorf("httpclient: send message: status %d: %s", resp.StatusCode, respBody)
	}
}

// SetAccountAttributes calls PUT /v1/accounts/attributes/ to update account attributes.
func (c *HTTPClient) SetAccountAttributes(ctx context.Context, attrs *AccountAttributes, auth BasicAuth) error {
	body, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("httpclient: marshal attributes: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/accounts/attributes/", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(auth.Username, auth.Password)

	resp, err := c.do(httpReq)
	if err != nil {
		return fmt.Errorf("httpclient: set attributes: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("httpclient: set attributes: status %d: %s", resp.StatusCode, respBody)
	}

	return nil
}

// GetDevices calls GET /v1/devices/ to list registered devices for this account.
func (c *HTTPClient) GetDevices(ctx context.Context, auth BasicAuth) ([]DeviceInfo, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/devices/", nil)
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.SetBasicAuth(auth.Username, auth.Password)

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: get devices: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get devices: status %d: %s", resp.StatusCode, respBody)
	}

	var result DeviceListResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal devices: %w", err)
	}

	return result.Devices, nil
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

	resp, err := c.do(httpReq)
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

// CreateVerificationSession starts a new verification session for primary registration.
// POST /v1/verification/session
func (c *HTTPClient) CreateVerificationSession(ctx context.Context, number string) (*VerificationSessionResponse, error) {
	req := &VerificationSessionRequest{Number: number}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: marshal session request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/verification/session", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: create session: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: create session: status %d: %s", resp.StatusCode, respBody)
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
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/verification/session/"+sessionID, nil)
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: get session: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get session: status %d: %s", resp.StatusCode, respBody)
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
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: marshal code request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/verification/session/"+sessionID+"/code", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: request code: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: request code: status %d: %s", resp.StatusCode, respBody)
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
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: marshal submit request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/verification/session/"+sessionID+"/code", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: submit code: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: submit code: status %d: %s", resp.StatusCode, respBody)
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
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: marshal update request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPatch, c.baseURL+"/v1/verification/session/"+sessionID, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: update session: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: update session: status %d: %s", resp.StatusCode, respBody)
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
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: marshal registration: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/registration", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.SetBasicAuth(auth.Username, auth.Password)

	resp, err := c.do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("httpclient: register primary: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: register primary: status %d: %s", resp.StatusCode, respBody)
	}

	var result PrimaryRegistrationResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal registration: %w", err)
	}

	return &result, nil
}

// ProfileOptions configures which profile fields to update.
type ProfileOptions struct {
	Name              *string // nil = don't change, non-nil = set to this value
	PhoneNumberSharing *bool   // nil = don't change, non-nil = set to this value
}

// SetProfile updates the user's profile on the Signal server.
// PUT /v1/profile
func (c *HTTPClient) SetProfile(ctx context.Context, aci string, profileKey []byte, name string, auth BasicAuth) error {
	return c.SetProfileWithOptions(ctx, aci, profileKey, &ProfileOptions{Name: &name}, auth)
}

// SetProfileWithOptions updates the user's profile on the Signal server with configurable options.
// PUT /v1/profile
func (c *HTTPClient) SetProfileWithOptions(ctx context.Context, aci string, profileKey []byte, opts *ProfileOptions, auth BasicAuth) error {
	cipher, err := NewProfileCipher(profileKey)
	if err != nil {
		return fmt.Errorf("httpclient: create profile cipher: %w", err)
	}

	// Encrypt profile fields - use provided values or defaults
	name := ""
	if opts != nil && opts.Name != nil {
		name = *opts.Name
	}
	encryptedName, err := cipher.EncryptString(name, GetTargetNameLength(name))
	if err != nil {
		return fmt.Errorf("httpclient: encrypt name: %w", err)
	}

	encryptedAbout, err := cipher.EncryptString("", GetTargetAboutLength(""))
	if err != nil {
		return fmt.Errorf("httpclient: encrypt about: %w", err)
	}

	encryptedEmoji, err := cipher.EncryptString("", 32) // EMOJI_PADDED_LENGTH
	if err != nil {
		return fmt.Errorf("httpclient: encrypt emoji: %w", err)
	}

	phoneSharing := false
	if opts != nil && opts.PhoneNumberSharing != nil {
		phoneSharing = *opts.PhoneNumberSharing
	}
	encryptedPhoneSharing, err := cipher.EncryptBoolean(phoneSharing)
	if err != nil {
		return fmt.Errorf("httpclient: encrypt phone sharing: %w", err)
	}

	// Get profile key version and commitment from libsignal
	version, err := getProfileKeyVersion(profileKey, aci)
	if err != nil {
		return fmt.Errorf("httpclient: get profile key version: %w", err)
	}

	commitment, err := getProfileKeyCommitment(profileKey, aci)
	if err != nil {
		return fmt.Errorf("httpclient: get profile key commitment: %w", err)
	}

	profileWrite := &ProfileWrite{
		Version:            version,
		Name:               encryptedName,
		About:              encryptedAbout,
		AboutEmoji:         encryptedEmoji,
		PhoneNumberSharing: encryptedPhoneSharing,
		Avatar:             false,
		SameAvatar:         true,
		Commitment:         commitment,
		BadgeIDs:           []string{},
	}

	body, err := json.Marshal(profileWrite)
	if err != nil {
		return fmt.Errorf("httpclient: marshal profile: %w", err)
	}

	logf(c.logger, "setting profile: version=%s name=%q", version, name)

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.baseURL+"/v1/profile", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("httpclient: new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(auth.Username, auth.Password)

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("httpclient: set profile: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("httpclient: set profile: status %d: %s", resp.StatusCode, respBody)
	}

	logf(c.logger, "profile set successfully")
	return nil
}

// getProfileKeyVersion wraps libsignal's profile key version derivation.
func getProfileKeyVersion(profileKey []byte, aci string) (string, error) {
	return libsignal.ProfileKeyGetVersion(profileKey, aci)
}

// getProfileKeyCommitment wraps libsignal's profile key commitment derivation.
func getProfileKeyCommitment(profileKey []byte, aci string) ([]byte, error) {
	return libsignal.ProfileKeyGetCommitment(profileKey, aci)
}

// GetProfile fetches a user's profile from the server.
// GET /v1/profile/{aci}/{version}
func (c *HTTPClient) GetProfile(ctx context.Context, aci string, profileKey []byte, auth BasicAuth) (*ProfileResponse, error) {
	version, err := getProfileKeyVersion(profileKey, aci)
	if err != nil {
		return nil, fmt.Errorf("httpclient: get profile key version: %w", err)
	}

	url := fmt.Sprintf("%s/v1/profile/%s/%s", c.baseURL, aci, version)
	logf(c.logger, "fetching profile: aci=%s version=%s", aci, version)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("httpclient: new request: %w", err)
	}
	req.SetBasicAuth(auth.Username, auth.Password)

	resp, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("httpclient: get profile: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("httpclient: read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get profile: status %d: %s", resp.StatusCode, respBody)
	}

	var profile ProfileResponse
	if err := json.Unmarshal(respBody, &profile); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal profile: %w", err)
	}

	return &profile, nil
}
