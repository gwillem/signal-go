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

// authType specifies the authentication method for API requests.
type authType int

const (
	authNone  authType = iota // No authentication
	authBasic                 // HTTP Basic auth
	authUAK                   // Unidentified-Access-Key header (sealed sender)
)

// apiRequest holds parameters for a JSON API call.
type apiRequest struct {
	method   string
	path     string
	body     any      // marshaled to JSON if non-nil
	authType authType // authentication type
	auth     BasicAuth
	uak      []byte // Unidentified-Access-Key for sealed sender
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

	switch req.authType {
	case authBasic:
		httpReq.SetBasicAuth(req.auth.Username, req.auth.Password)
	case authUAK:
		httpReq.Header.Set("Unidentified-Access-Key", encodeBase64(req.uak))
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

// GetPreKeys fetches a recipient's pre-key bundle.
// GET /v2/keys/{destination}/{deviceId}
func (c *HTTPClient) GetPreKeys(ctx context.Context, destination string, deviceID int, auth BasicAuth) (*PreKeyResponse, error) {
	path := fmt.Sprintf("/v2/keys/%s/%d", destination, deviceID)
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodGet,
		path:     path,
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: get pre-keys: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get pre-keys: status %d: %s", status, respBody)
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
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPut,
		path:     "/v1/messages/" + destination,
		body:     msg,
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return fmt.Errorf("httpclient: send message: %w", err)
	}

	return c.handleMessageResponse(status, respBody)
}

// handleMessageResponse handles 409/410 errors for message sending.
func (c *HTTPClient) handleMessageResponse(status int, respBody []byte) error {
	switch status {
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
		return fmt.Errorf("httpclient: send message: status %d: %s", status, respBody)
	}
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

// GetDevices calls GET /v1/devices/ to list registered devices for this account.
func (c *HTTPClient) GetDevices(ctx context.Context, auth BasicAuth) ([]DeviceInfo, error) {
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodGet,
		path:     "/v1/devices/",
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: get devices: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get devices: status %d: %s", status, respBody)
	}

	var result DeviceListResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal devices: %w", err)
	}
	return result.Devices, nil
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

	logf(c.logger, "setting profile: version=%s name=%q", version, name)

	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPut,
		path:     "/v1/profile",
		body:     profileWrite,
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return fmt.Errorf("httpclient: set profile: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("httpclient: set profile: status %d: %s", status, respBody)
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

	path := fmt.Sprintf("/v1/profile/%s/%s", aci, version)
	logf(c.logger, "fetching profile: aci=%s version=%s", aci, version)

	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodGet,
		path:     path,
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: get profile: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get profile: status %d: %s", status, respBody)
	}

	var profile ProfileResponse
	if err := json.Unmarshal(respBody, &profile); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal profile: %w", err)
	}
	return &profile, nil
}

// GetSenderCertificate fetches a sender certificate for sealed sender messages.
// GET /v1/certificate/delivery
// The certificate is valid for about 24 hours and should be cached.
func (c *HTTPClient) GetSenderCertificate(ctx context.Context, auth BasicAuth) ([]byte, error) {
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodGet,
		path:     "/v1/certificate/delivery",
		authType: authBasic,
		auth:     auth,
	})
	if err != nil {
		return nil, fmt.Errorf("httpclient: get sender certificate: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("httpclient: get sender certificate: status %d: %s", status, respBody)
	}

	var certResp SenderCertificateResponse
	if err := json.Unmarshal(respBody, &certResp); err != nil {
		return nil, fmt.Errorf("httpclient: unmarshal sender certificate: %w", err)
	}

	logf(c.logger, "sender cert base64 len=%d value=%s", len(certResp.Certificate), certResp.Certificate)

	certBytes, err := decodeBase64(certResp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("httpclient: decode sender certificate: %w", err)
	}

	logf(c.logger, "sender cert bytes len=%d first20=%x", len(certBytes), truncateBytes(certBytes, 20))
	return certBytes, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func truncateBytes(b []byte, n int) []byte {
	if len(b) <= n {
		return b
	}
	return b[:n]
}

// SendSealedMessage sends a sealed sender message.
// PUT /v1/messages/{destination}
// Uses the Unidentified-Access-Key header for sealed sender authentication.
func (c *HTTPClient) SendSealedMessage(ctx context.Context, destination string, msg *OutgoingMessageList, unidentifiedAccessKey []byte) error {
	path := "/v1/messages/" + destination
	respBody, status, err := c.doJSON(ctx, apiRequest{
		method:   http.MethodPut,
		path:     path,
		body:     msg,
		authType: authUAK,
		uak:      unidentifiedAccessKey,
	})
	if err != nil {
		return fmt.Errorf("httpclient: send sealed message: %w", err)
	}

	switch status {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
		return nil
	case http.StatusConflict: // 409: mismatched devices
		var mismatch MismatchedDevicesError
		if err := json.Unmarshal(respBody, &mismatch); err != nil {
			return fmt.Errorf("httpclient: unmarshal 409: %w", err)
		}
		return &mismatch
	case http.StatusGone: // 410: stale devices
		var stale StaleDevicesError
		if err := json.Unmarshal(respBody, &stale); err != nil {
			return fmt.Errorf("httpclient: unmarshal 410: %w", err)
		}
		return &stale
	case http.StatusUnauthorized: // 401: access key rejected
		return fmt.Errorf("httpclient: sealed sender: access key rejected (401): recipient may have sealed sender disabled")
	default:
		return fmt.Errorf("httpclient: send sealed message: status %d: %s", status, respBody)
	}
}

// decodeBase64 decodes a base64 string (with or without padding).
func decodeBase64(s string) ([]byte, error) {
	// Try standard base64 first, then raw (no padding)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// encodeBase64 encodes bytes to base64 with padding.
func encodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}
