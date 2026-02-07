package signalservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"iter"
	"log"
	"net/http"
	"sync/atomic"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/store"
)

// Service provides high-level access to the Signal API.
// It owns the transport, store, and authentication credentials.
type Service struct {
	transport     *Transport
	store         *store.Store
	auth          BasicAuth
	localACI      string
	localDeviceID int
	wsURL         string
	tlsConfig     *tls.Config
	logger        *log.Logger
	debugDir      string
	receiving     atomic.Bool // guards against concurrent receiveMessages calls
}

// ServiceConfig holds configuration for creating a Service.
type ServiceConfig struct {
	APIURL        string
	WSURL         string
	TLSConfig     *tls.Config
	Store         *store.Store
	Auth          BasicAuth
	LocalACI      string
	LocalDeviceID int
	Logger        *log.Logger
	DebugDir      string
}

// NewService creates a new Signal API service.
func NewService(cfg ServiceConfig) *Service {
	return &Service{
		transport:     NewTransport(cfg.APIURL, cfg.TLSConfig, cfg.Logger),
		store:         cfg.Store,
		auth:          cfg.Auth,
		localACI:      cfg.LocalACI,
		localDeviceID: cfg.LocalDeviceID,
		wsURL:         cfg.WSURL,
		tlsConfig:     cfg.TLSConfig,
		logger:        cfg.Logger,
		debugDir:      cfg.DebugDir,
	}
}


// --- Keys API ---

// GetPreKeys fetches a recipient's pre-key bundle.
func (s *Service) GetPreKeys(ctx context.Context, destination string, deviceID int) (*PreKeyResponse, error) {
	path := fmt.Sprintf("/v2/keys/%s/%d", destination, deviceID)
	body, status, err := s.transport.Get(ctx, path, &s.auth)
	if err != nil {
		return nil, fmt.Errorf("get pre-keys: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get pre-keys: status %d: %s", status, body)
	}

	var result PreKeyResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal pre-keys: %w", err)
	}
	return &result, nil
}

// RefreshPreKeys loads stored pre-keys and re-uploads them to the server.
func (s *Service) RefreshPreKeys(ctx context.Context) error {
	// Upload ACI pre-keys (ID 1).
	if err := s.uploadStoredPreKeys(ctx, "aci", 1); err != nil {
		return fmt.Errorf("refresh ACI pre-keys: %w", err)
	}
	// Upload PNI pre-keys (ID 0x01000001).
	if err := s.uploadStoredPreKeys(ctx, "pni", 0x01000001); err != nil {
		return fmt.Errorf("refresh PNI pre-keys: %w", err)
	}
	return nil
}

// uploadStoredPreKeys loads a signed pre-key and Kyber pre-key from the store,
// converts them to upload entities, and uploads them to the server.
func (s *Service) uploadStoredPreKeys(ctx context.Context, identity string, keyID uint32) error {
	spk, err := s.store.LoadSignedPreKey(keyID)
	if err != nil {
		return fmt.Errorf("load signed pre-key %d: %w", keyID, err)
	}
	if spk == nil {
		return fmt.Errorf("signed pre-key %d not found", keyID)
	}
	defer spk.Destroy()

	kpk, err := s.store.LoadKyberPreKey(keyID)
	if err != nil {
		return fmt.Errorf("load Kyber pre-key %d: %w", keyID, err)
	}
	if kpk == nil {
		return fmt.Errorf("Kyber pre-key %d not found", keyID)
	}
	defer kpk.Destroy()

	spkEntity, err := signedPreKeyToEntity(spk)
	if err != nil {
		return fmt.Errorf("convert signed pre-key: %w", err)
	}
	kpkEntity, err := kyberPreKeyToEntity(kpk)
	if err != nil {
		return fmt.Errorf("convert Kyber pre-key: %w", err)
	}

	return s.UploadPreKeys(ctx, identity, &PreKeyUpload{
		SignedPreKey:    spkEntity,
		PqLastResortKey: kpkEntity,
	})
}

// UploadPreKeys uploads pre-keys to the server.
func (s *Service) UploadPreKeys(ctx context.Context, identity string, keys *PreKeyUpload) error {
	body, err := json.Marshal(keys)
	if err != nil {
		return fmt.Errorf("marshal pre-keys: %w", err)
	}

	respBody, status, err := s.transport.Put(ctx, "/v2/keys?identity="+identity, body, &s.auth)
	if err != nil {
		return fmt.Errorf("upload keys: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("upload keys: status %d: %s", status, respBody)
	}
	return nil
}

// --- Messages API ---

// SendMessage sends an encrypted message to a destination.
// Returns *StaleDevicesError for 410 and *MismatchedDevicesError for 409.
func (s *Service) SendMessage(ctx context.Context, destination string, msg *outgoingMessageList) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	logf(s.logger, "http PUT /v1/messages/%s body=%s", destination, string(body))

	respBody, status, err := s.transport.Put(ctx, "/v1/messages/"+destination, body, &s.auth)
	if err != nil {
		return fmt.Errorf("send message: %w", err)
	}

	switch status {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusGone: // 410
		var parsed struct {
			StaleDevices []int `json:"staleDevices"`
		}
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return fmt.Errorf("send message: status 410: %s", respBody)
		}
		return &staleDevicesError{StaleDevices: parsed.StaleDevices}
	case http.StatusConflict: // 409
		var parsed mismatchedDevicesError
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return fmt.Errorf("send message: status 409: %s", respBody)
		}
		return &parsed
	default:
		return fmt.Errorf("send message: status %d: %s", status, respBody)
	}
}

// SendSealedMessage sends a sealed sender message using unidentified access key.
func (s *Service) SendSealedMessage(ctx context.Context, destination string, msg *outgoingMessageList, accessKey []byte) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal sealed message: %w", err)
	}

	accessKeyB64 := base64.StdEncoding.EncodeToString(accessKey)
	respBody, status, err := s.transport.PutWithHeader(ctx, "/v1/messages/"+destination, body, "Unidentified-Access-Key", accessKeyB64)
	if err != nil {
		return fmt.Errorf("send sealed message: %w", err)
	}

	switch status {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
		return nil
	case http.StatusConflict: // 409
		var mismatch mismatchedDevicesError
		if err := json.Unmarshal(respBody, &mismatch); err != nil {
			return fmt.Errorf("unmarshal 409: %w", err)
		}
		return &mismatch
	case http.StatusGone: // 410
		var stale staleDevicesError
		if err := json.Unmarshal(respBody, &stale); err != nil {
			return fmt.Errorf("unmarshal 410: %w", err)
		}
		return &stale
	case http.StatusUnauthorized: // 401
		return fmt.Errorf("sealed sender: access key rejected (401): recipient may have sealed sender disabled")
	default:
		return fmt.Errorf("send sealed message: status %d: %s", status, respBody)
	}
}

// SendMultiRecipientMessage sends a multi-recipient sealed sender message (SSv2).
// body is the MRM binary blob from SealedSenderMultiRecipientEncrypt.
// groupSendToken is the full token for the Group-Send-Token header.
func (s *Service) SendMultiRecipientMessage(ctx context.Context, body []byte, groupSendToken []byte, timestamp uint64) error {
	path := fmt.Sprintf("/v1/messages/multi_recipient?ts=%d&online=false&urgent=true&story=false", timestamp)

	headers := map[string]string{
		"Content-Type":     "application/vnd.signal-messenger.mrm",
		"Group-Send-Token": base64.StdEncoding.EncodeToString(groupSendToken),
	}

	respBody, status, err := s.transport.PutBinary(ctx, path, body, headers)
	if err != nil {
		return fmt.Errorf("send multi-recipient message: %w", err)
	}

	switch status {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
		// Check for uuids404 in the response (recipients the server couldn't deliver to).
		if len(respBody) > 0 {
			var result sendGroupMessageResponse
			if err := json.Unmarshal(respBody, &result); err == nil && len(result.UUIDs404) > 0 {
				logf(s.logger, "multi_recipient: uuids404=%v", result.UUIDs404)
			}
		}
		return nil
	case http.StatusConflict: // 409
		var entries []groupMismatchedDevices
		if err := json.Unmarshal(respBody, &entries); err != nil {
			return fmt.Errorf("send multi-recipient 409: %s", respBody)
		}
		return &groupMismatchedDevicesError{Entries: entries}
	case http.StatusGone: // 410
		var entries []groupStaleDevices
		if err := json.Unmarshal(respBody, &entries); err != nil {
			return fmt.Errorf("send multi-recipient 410: %s", respBody)
		}
		return &groupStaleDevicesError{Entries: entries}
	default:
		return fmt.Errorf("send multi-recipient message: status %d: %s", status, respBody)
	}
}

// --- Account API ---

// GetDevices returns the list of registered devices for this account.
func (s *Service) GetDevices(ctx context.Context) ([]DeviceInfo, error) {
	body, status, err := s.transport.Get(ctx, "/v1/devices/", &s.auth)
	if err != nil {
		return nil, fmt.Errorf("get devices: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get devices: status %d: %s", status, body)
	}

	var result deviceListResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("unmarshal devices: %w", err)
	}
	return result.Devices, nil
}

// SetAccountAttributes updates account attributes on the server.
func (s *Service) SetAccountAttributes(ctx context.Context, attrs *AccountAttributes) error {
	body, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("marshal attributes: %w", err)
	}

	respBody, status, err := s.transport.Put(ctx, "/v1/accounts/attributes/", body, &s.auth)
	if err != nil {
		return fmt.Errorf("set attributes: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("set attributes: status %d: %s", status, respBody)
	}
	return nil
}

// GetSenderCertificate fetches a sender certificate for sealed sender messages.
func (s *Service) GetSenderCertificate(ctx context.Context) ([]byte, error) {
	body, status, err := s.transport.Get(ctx, "/v1/certificate/delivery", &s.auth)
	if err != nil {
		return nil, fmt.Errorf("get sender certificate: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get sender certificate: status %d: %s", status, body)
	}

	var certResp senderCertificateResponse
	if err := json.Unmarshal(body, &certResp); err != nil {
		return nil, fmt.Errorf("unmarshal sender certificate: %w", err)
	}

	logf(s.logger, "sender cert base64 len=%d", len(certResp.Certificate))

	certBytes, err := decodeBase64(certResp.Certificate)
	if err != nil {
		return nil, fmt.Errorf("decode sender certificate: %w", err)
	}
	return certBytes, nil
}

// decodeBase64 decodes a base64 string (with or without padding).
func decodeBase64(s string) ([]byte, error) {
	// Try standard base64 first, then raw (no padding)
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// --- Profile API ---

// ProfileOptions configures which profile fields to update.
type ProfileOptions struct {
	Name               *string // nil = don't change, non-nil = set to this value
	PhoneNumberSharing *bool   // nil = don't change, non-nil = set to this value
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
func (s *Service) GetProfile(ctx context.Context, aci string, profileKey []byte) (*profileResponse, error) {
	version, err := getProfileKeyVersion(profileKey, aci)
	if err != nil {
		return nil, fmt.Errorf("get profile key version: %w", err)
	}

	path := fmt.Sprintf("/v1/profile/%s/%s", aci, version)
	logf(s.logger, "fetching profile: aci=%s version=%s", aci, version)

	body, status, err := s.transport.Get(ctx, path, &s.auth)
	if err != nil {
		return nil, fmt.Errorf("get profile: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("get profile: status %d: %s", status, body)
	}

	var profile profileResponse
	if err := json.Unmarshal(body, &profile); err != nil {
		return nil, fmt.Errorf("unmarshal profile: %w", err)
	}
	return &profile, nil
}

// SetProfile updates the user's profile on the server.
func (s *Service) SetProfile(ctx context.Context, aci string, profileKey []byte, opts *ProfileOptions) error {
	cipher, err := NewProfileCipher(profileKey)
	if err != nil {
		return fmt.Errorf("create profile cipher: %w", err)
	}

	name := ""
	if opts != nil && opts.Name != nil {
		name = *opts.Name
	}
	encryptedName, err := cipher.EncryptString(name, getTargetNameLength(name))
	if err != nil {
		return fmt.Errorf("encrypt name: %w", err)
	}

	encryptedAbout, err := cipher.EncryptString("", getTargetAboutLength(""))
	if err != nil {
		return fmt.Errorf("encrypt about: %w", err)
	}

	encryptedEmoji, err := cipher.EncryptString("", 32)
	if err != nil {
		return fmt.Errorf("encrypt emoji: %w", err)
	}

	phoneSharing := false
	if opts != nil && opts.PhoneNumberSharing != nil {
		phoneSharing = *opts.PhoneNumberSharing
	}
	encryptedPhoneSharing, err := cipher.EncryptBoolean(phoneSharing)
	if err != nil {
		return fmt.Errorf("encrypt phone sharing: %w", err)
	}

	version, err := getProfileKeyVersion(profileKey, aci)
	if err != nil {
		return fmt.Errorf("get profile key version: %w", err)
	}

	commitment, err := getProfileKeyCommitment(profileKey, aci)
	if err != nil {
		return fmt.Errorf("get profile key commitment: %w", err)
	}

	profileWrite := &profileWrite{
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
		return fmt.Errorf("marshal profile: %w", err)
	}

	logf(s.logger, "setting profile: version=%s name=%q", version, name)

	respBody, status, err := s.transport.Put(ctx, "/v1/profile", body, &s.auth)
	if err != nil {
		return fmt.Errorf("set profile: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("set profile: status %d: %s", status, respBody)
	}

	logf(s.logger, "profile set successfully")
	return nil
}

// --- Messaging ---

// SendTextMessage sends a text message to a recipient (ACI UUID or group ID).
// Automatically detects group IDs (64 hex characters) and routes to group send.
func (s *Service) SendTextMessage(ctx context.Context, recipient, text string) error {
	if isGroupID(recipient) {
		return s.SendGroupMessage(ctx, recipient, text)
	}
	return s.sendTextMessage(ctx, recipient, text)
}

// isGroupID returns true if s looks like a group ID (64 hex characters = 32 bytes).
func isGroupID(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// SendSealedSenderMessage sends a sealed sender message to a recipient.
func (s *Service) SendSealedSenderMessage(ctx context.Context, recipient, text string) error {
	return s.sendSealedSenderMessage(ctx, recipient, text)
}

// RequestContactSync sends a contact sync request to the primary device.
func (s *Service) RequestContactSync(ctx context.Context) error {
	return s.requestContactSync(ctx)
}

// ReceiveMessages returns an iterator that yields incoming messages.
func (s *Service) ReceiveMessages(ctx context.Context) iter.Seq2[Message, error] {
	return s.receiveMessages(ctx)
}
