// Package signal provides a high-level client for the Signal messenger protocol.
package signal

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"iter"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
	"github.com/gwillem/signal-go/internal/signalservice"
	"github.com/gwillem/signal-go/internal/store"
)

// Message represents a received Signal message.
type Message = signalservice.Message

// Group represents a Signal group stored locally.
type Group = store.Group

const (
	defaultProvisioningURL = "wss://chat.signal.org/v1/websocket/provisioning/"
	defaultAPIURL          = "https://chat.signal.org"
	defaultWSURL           = "wss://chat.signal.org"
)

// Client is the main entry point for interacting with Signal.
type Client struct {
	provisioningURL   string
	apiURL            string
	wsURL             string
	tlsConfig         *tls.Config
	dbPath            string
	debugDir          string
	logger            *log.Logger
	data              *provisioncrypto.ProvisionData
	store             *store.Store
	deviceID          int
	aci               string
	pni               string
	password          string
	number            string
	registrationID    int
	pniRegistrationID int
	service           *signalservice.Service
}

// initService creates the Service after credentials are known (called from Link/Load).
func (c *Client) initService() {
	libsignal.SetCallbackLogger(c.logger)
	c.service = signalservice.NewService(signalservice.ServiceConfig{
		APIURL:        c.apiURL,
		WSURL:         c.wsURL,
		TLSConfig:     c.tlsConfig,
		Store:         c.store,
		Auth:          c.auth(),
		LocalACI:      c.aci,
		LocalDeviceID: c.deviceID,
		Logger:        c.logger,
		DebugDir:      c.debugDir,
	})
}

// auth returns the BasicAuth credentials for API requests.
// Used by functions not yet migrated to Service.
func (c *Client) auth() signalservice.BasicAuth {
	return signalservice.BasicAuth{
		Username: fmt.Sprintf("%s.%d", c.aci, c.deviceID),
		Password: c.password,
	}
}

// storeSignedPreKeyFromBytes deserializes and stores a signed pre-key.
func (c *Client) storeSignedPreKeyFromBytes(data []byte, label string) error {
	if len(data) == 0 {
		return nil
	}
	rec, err := libsignal.DeserializeSignedPreKeyRecord(data)
	if err != nil {
		return fmt.Errorf("deserialize %s signed pre-key: %w", label, err)
	}
	id, err := rec.ID()
	if err != nil {
		rec.Destroy()
		return fmt.Errorf("%s signed pre-key ID: %w", label, err)
	}
	if err := c.store.StoreSignedPreKey(id, rec); err != nil {
		rec.Destroy()
		return fmt.Errorf("store %s signed pre-key: %w", label, err)
	}
	return nil
}

// storeKyberPreKeyFromBytes deserializes and stores a Kyber pre-key.
func (c *Client) storeKyberPreKeyFromBytes(data []byte, label string) error {
	if len(data) == 0 {
		return nil
	}
	rec, err := libsignal.DeserializeKyberPreKeyRecord(data)
	if err != nil {
		return fmt.Errorf("deserialize %s Kyber pre-key: %w", label, err)
	}
	id, err := rec.ID()
	if err != nil {
		rec.Destroy()
		return fmt.Errorf("%s Kyber pre-key ID: %w", label, err)
	}
	if err := c.store.StoreKyberPreKey(id, rec); err != nil {
		rec.Destroy()
		return fmt.Errorf("store %s Kyber pre-key: %w", label, err)
	}
	return nil
}

// Option configures a Client.
type Option func(*Client)

// WithProvisioningURL overrides the default provisioning WebSocket URL.
func WithProvisioningURL(url string) Option {
	return func(c *Client) { c.provisioningURL = url }
}

// WithAPIURL overrides the default REST API URL.
func WithAPIURL(url string) Option {
	return func(c *Client) { c.apiURL = url }
}

// WithTLSConfig overrides the TLS configuration used for connections.
// If nil (the default), Signal's pinned CA certificate is used.
func WithTLSConfig(tc *tls.Config) Option {
	return func(c *Client) { c.tlsConfig = tc }
}

// WithDBPath overrides the database path for persistent storage.
// If not set, defaults to $XDG_DATA_HOME/signal-go/<aci>.db after linking.
func WithDBPath(path string) Option {
	return func(c *Client) { c.dbPath = path }
}

// WithLogger sets the logger for verbose output.
// If not set, logging is disabled.
func WithLogger(l *log.Logger) Option {
	return func(c *Client) { c.logger = l }
}

// WithDebugDir sets a directory for dumping raw envelope bytes before decryption.
// When set, every received envelope is written as a .bin file for offline inspection.
func WithDebugDir(path string) Option {
	return func(c *Client) { c.debugDir = path }
}

// NewClient creates a new Signal client.
func NewClient(opts ...Option) *Client {
	c := &Client{
		provisioningURL: defaultProvisioningURL,
		apiURL:          defaultAPIURL,
		wsURL:           defaultWSURL,
		tlsConfig:       signalservice.TLSConfig(),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Open opens an existing account by phone number (e.g. "+31647272794").
// It finds the database in the default data directory, opens it, and loads credentials.
func Open(number string, opts ...Option) (*Client, error) {
	dbPath, err := discoverDBByNumber(number)
	if err != nil {
		return nil, err
	}
	c := NewClient(append(opts, WithDBPath(dbPath))...)
	if err := c.Load(); err != nil {
		return nil, err
	}
	return c, nil
}

// Link connects as a secondary device. It blocks until the primary device
// scans the QR code and completes provisioning, then registers the device
// with the Signal server. The onQR callback is called with the device link
// URI for display as a QR code.
func (c *Client) Link(ctx context.Context, onQR func(uri string)) error {
	cb := &linkCallbacks{onQR: onQR}
	result, err := signalservice.RunProvisioning(ctx, c.provisioningURL, cb, c.tlsConfig)
	if err != nil {
		return fmt.Errorf("client: provisioning: %w", err)
	}
	c.data = result.Data

	reg, err := signalservice.RegisterLinkedDevice(ctx, c.apiURL, result.Data, "signal-go", c.tlsConfig)
	if err != nil {
		return fmt.Errorf("client: register device: %w", err)
	}

	c.deviceID = reg.DeviceID
	c.aci = reg.ACI
	c.pni = reg.PNI
	c.password = reg.Password
	c.number = result.Data.Number
	c.registrationID = reg.RegistrationID
	c.pniRegistrationID = reg.PNIRegistrationID

	// Open store and persist credentials.
	if err := c.openStore(); err != nil {
		return fmt.Errorf("client: open store: %w", err)
	}

	// Store pre-keys locally so we can decrypt incoming messages.
	if err := c.storePreKeys(reg); err != nil {
		return fmt.Errorf("client: store pre-keys: %w", err)
	}

	// Set up identity key for the store.
	aciPriv, err := libsignal.DeserializePrivateKey(result.Data.ACIIdentityKeyPrivate)
	if err != nil {
		return fmt.Errorf("client: deserialize identity key: %w", err)
	}
	c.store.SetIdentity(aciPriv, uint32(reg.RegistrationID))

	return c.saveAccount()
}

// Register registers a new Signal account as a primary device.
// The getCode callback is called to prompt the user for the SMS/voice verification code.
// The getCaptcha callback is called if a CAPTCHA challenge is required.
func (c *Client) Register(
	ctx context.Context,
	number string,
	transport string, // "sms" or "voice"
	getCode func() (string, error),
	getCaptcha func() (string, error),
) error {
	reg, err := signalservice.RegisterPrimary(ctx, c.apiURL, number, transport, getCode, getCaptcha, c.tlsConfig, c.logger)
	if err != nil {
		return fmt.Errorf("client: register: %w", err)
	}

	c.deviceID = reg.DeviceID
	c.aci = reg.ACI
	c.pni = reg.PNI
	c.password = reg.Password
	c.number = reg.Number
	c.registrationID = reg.RegistrationID
	c.pniRegistrationID = reg.PNIRegistrationID

	// Open store and persist credentials.
	if err := c.openStore(); err != nil {
		return fmt.Errorf("client: open store: %w", err)
	}

	// Store pre-keys locally.
	if err := c.storePrimaryPreKeys(reg); err != nil {
		return fmt.Errorf("client: store pre-keys: %w", err)
	}

	// Set up identity key for the store.
	aciPriv, err := libsignal.DeserializePrivateKey(reg.ACIIdentityKeyPrivate)
	if err != nil {
		return fmt.Errorf("client: deserialize identity key: %w", err)
	}
	c.store.SetIdentity(aciPriv, uint32(reg.RegistrationID))

	// Save account with locally generated identity keys and profile key.
	acct := &store.Account{
		Number:                number,
		ACI:                   reg.ACI,
		PNI:                   reg.PNI,
		Password:              reg.Password,
		DeviceID:              reg.DeviceID,
		RegistrationID:        reg.RegistrationID,
		PNIRegistrationID:     reg.PNIRegistrationID,
		ACIIdentityKeyPrivate: reg.ACIIdentityKeyPrivate,
		ACIIdentityKeyPublic:  reg.ACIIdentityKeyPublic,
		PNIIdentityKeyPrivate: reg.PNIIdentityKeyPrivate,
		PNIIdentityKeyPublic:  reg.PNIIdentityKeyPublic,
		ProfileKey:            signalservice.GenerateProfileKey(),
	}
	if err := c.store.SaveAccount(acct); err != nil {
		return fmt.Errorf("client: save account: %w", err)
	}
	c.initService()
	return nil
}

func (c *Client) storePrimaryPreKeys(reg *signalservice.PrimaryRegistrationResult) error {
	return c.storePreKeysForIdentities(reg.ACISignedPreKey, reg.ACIKyberPreKey, reg.PNISignedPreKey, reg.PNIKyberPreKey)
}

// Load opens an existing database and loads credentials without re-linking.
// If no explicit DB path is set, it discovers the most recent account database
// in the default data directory.
func (c *Client) Load() error {
	if c.dbPath == "" {
		discovered, err := discoverDB()
		if err != nil {
			return fmt.Errorf("client: %w", err)
		}
		c.dbPath = discovered
	}
	if c.logger != nil {
		c.logger.Printf("opening database path=%s", c.dbPath)
	}
	if err := c.openStore(); err != nil {
		return fmt.Errorf("client: open store: %w", err)
	}

	acct, err := c.store.LoadAccount()
	if err != nil {
		return fmt.Errorf("client: load account: %w", err)
	}
	if acct == nil {
		return fmt.Errorf("client: no account found in database")
	}

	c.number = acct.Number
	c.aci = acct.ACI
	c.pni = acct.PNI
	c.password = acct.Password
	c.deviceID = acct.DeviceID

	// Set up ACI identity key for the store.
	identityPriv, err := libsignal.DeserializePrivateKey(acct.ACIIdentityKeyPrivate)
	if err != nil {
		return fmt.Errorf("client: deserialize identity key: %w", err)
	}
	c.store.SetIdentity(identityPriv, uint32(acct.RegistrationID))

	// Set up PNI identity key for the store (if available).
	if len(acct.PNIIdentityKeyPrivate) > 0 {
		pniPriv, err := libsignal.DeserializePrivateKey(acct.PNIIdentityKeyPrivate)
		if err != nil {
			return fmt.Errorf("client: deserialize PNI identity key: %w", err)
		}
		c.store.SetPNIIdentity(pniPriv, uint32(acct.PNIRegistrationID))
	}

	// Log identity key fingerprint for debugging.
	if c.logger != nil {
		if pub, err := identityPriv.PublicKey(); err == nil {
			if data, err := pub.Serialize(); err == nil && len(data) >= 8 {
				c.logger.Printf("loaded identity key fingerprint=%x", data[:8])
			}
			pub.Destroy()
		}
	}

	c.initService()
	return nil
}

// Close closes the client's database connection.
func (c *Client) Close() error {
	if c.store != nil {
		return c.store.Close()
	}
	return nil
}

// Number returns the phone number associated with the linked account.
func (c *Client) Number() string {
	if c.number != "" {
		return c.number
	}
	if c.data != nil {
		return c.data.Number
	}
	return ""
}

// DeviceID returns the device ID assigned during registration.
func (c *Client) DeviceID() int {
	return c.deviceID
}

// ACI returns the Account Identity UUID.
func (c *Client) ACI() string {
	return c.aci
}

// IdentityKey returns our public identity key bytes.
func (c *Client) IdentityKey() ([]byte, error) {
	if c.store == nil {
		return nil, fmt.Errorf("client: not loaded")
	}
	priv, err := c.store.GetIdentityKeyPair()
	if err != nil {
		return nil, err
	}
	pub, err := priv.PublicKey()
	priv.Destroy()
	if err != nil {
		return nil, err
	}
	defer pub.Destroy()
	return pub.Serialize()
}

// GetIdentityKey returns the stored identity key for a remote party.
func (c *Client) GetIdentityKey(theirUUID string) ([]byte, error) {
	if c.store == nil {
		return nil, fmt.Errorf("client: not loaded")
	}
	// Create address with device 1 (identity keys are per-account, not per-device)
	addr, err := libsignal.NewAddress(theirUUID, 1)
	if err != nil {
		return nil, err
	}
	defer addr.Destroy()

	pub, err := c.store.GetIdentityKey(addr)
	if err != nil {
		return nil, err
	}
	if pub == nil {
		return nil, fmt.Errorf("no identity key stored for %s", theirUUID)
	}
	defer pub.Destroy()
	return pub.Serialize()
}

// Send sends a text message to the given recipient (ACI UUID).
// Use SendWithPNI for recipients who discovered you via phone number lookup.
func (c *Client) Send(ctx context.Context, recipient string, text string) error {
	return c.sendInternal(ctx, recipient, text, false)
}

// SendWithPNI sends a text message using PNI identity for encryption.
// Use this when the recipient discovered you via phone number (CDSI) and
// initiated the conversation by sending to your PNI.
func (c *Client) SendWithPNI(ctx context.Context, recipient string, text string) error {
	return c.sendInternal(ctx, recipient, text, true)
}

// SendSealed sends a text message using sealed sender (UNIDENTIFIED_SENDER).
// This hides the sender's identity from the Signal server.
// Requires the recipient's profile key to be stored (for deriving unidentified access key).
func (c *Client) SendSealed(ctx context.Context, recipient string, text string) error {
	if c.service == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	return c.service.SendSealedSenderMessage(ctx, recipient, text)
}

// SendGroup sends a text message to a group.
// The groupID should be the hex-encoded GroupIdentifier (obtained from Groups()).
// Uses sender key encryption for efficient group messaging.
func (c *Client) SendGroup(ctx context.Context, groupID string, text string) error {
	if c.service == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	return c.service.SendGroupMessage(ctx, groupID, text)
}

func (c *Client) sendInternal(ctx context.Context, recipient string, text string, usePNI bool) error {
	if c.service == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	// Note: Server only accepts ACI for authentication, not PNI.
	// When usePNI=true, we use PNI identity for encryption but ACI for auth.
	// This creates a mismatch that recipients may not handle correctly.
	// The proper solution is sealed sender (not yet implemented).
	if usePNI {
		c.store.UsePNI(true)
		defer c.store.UsePNI(false)
	}
	return c.service.SendTextMessage(ctx, recipient, text)
}

// Receive returns an iterator that yields incoming text messages.
// It connects to the authenticated WebSocket and decrypts messages.
// The iterator stops when the context is cancelled or the caller breaks.
func (c *Client) Receive(ctx context.Context) iter.Seq2[Message, error] {
	if c.service == nil {
		return func(yield func(Message, error) bool) {
			yield(Message{}, fmt.Errorf("client: not linked (call Link or Load first)"))
		}
	}
	return c.service.ReceiveMessages(ctx)
}

// SyncContacts requests a contact sync from the primary device.
// The primary device will respond with a SyncMessage.Contacts that is
// automatically handled by the receive loop, populating the local contact store.
func (c *Client) SyncContacts(ctx context.Context) error {
	if c.service == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	return c.service.RequestContactSync(ctx)
}

// LookupNumber returns the phone number for the given ACI UUID from the local
// contact store. Returns empty string if not found.
func (c *Client) LookupNumber(aci string) string {
	if c.store == nil {
		return ""
	}
	contact, err := c.store.GetContactByACI(aci)
	if err != nil || contact == nil {
		return ""
	}
	return contact.Number
}

// Groups returns all groups this device knows about.
// Groups are discovered incrementally from received group messages.
func (c *Client) Groups() ([]*Group, error) {
	if c.store == nil {
		return nil, fmt.Errorf("client: not loaded")
	}
	return c.store.GetAllGroups()
}

// GetGroup returns group details by group ID (hex-encoded GroupIdentifier).
// Returns nil if the group is not found.
func (c *Client) GetGroup(groupID string) (*Group, error) {
	if c.store == nil {
		return nil, fmt.Errorf("client: not loaded")
	}
	return c.store.GetGroup(groupID)
}

// SyncGroups fetches group master keys from the Storage Service and stores them locally.
// This requires the account's master key to be available (set during device linking).
// Returns the number of groups synced.
func (c *Client) SyncGroups(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, fmt.Errorf("client: not linked (call Link or Load first)")
	}
	return c.service.SyncGroupsFromStorage(ctx)
}

// FetchGroupDetails fetches details (name, members) for all groups that don't have names yet.
// This uses the Groups V2 API which requires zkgroup auth credentials.
// Returns the number of groups updated.
func (c *Client) FetchGroupDetails(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, fmt.Errorf("client: not linked (call Link or Load first)")
	}
	return c.service.FetchAllGroupDetails(ctx)
}

// VerifyIdentityKey checks if the server has the same identity key as locally stored.
// Returns (serverKey, localKey, match, error).
func (c *Client) VerifyIdentityKey(ctx context.Context) (serverKey, localKey []byte, match bool, err error) {
	if c.store == nil {
		return nil, nil, false, fmt.Errorf("client: not linked (call Link or Load first)")
	}

	// Get local identity key
	acct, err := c.store.LoadAccount()
	if err != nil {
		return nil, nil, false, fmt.Errorf("client: load account: %w", err)
	}
	if acct == nil {
		return nil, nil, false, fmt.Errorf("client: no account found")
	}
	localKey = acct.ACIIdentityKeyPublic

	// Query server for our pre-keys (includes identity key)
	preKeys, err := c.service.GetPreKeys(ctx, c.aci, c.deviceID)
	if err != nil {
		return nil, localKey, false, fmt.Errorf("client: get pre-keys from server: %w", err)
	}

	serverKey, err = base64.StdEncoding.DecodeString(preKeys.IdentityKey)
	if err != nil {
		return nil, localKey, false, fmt.Errorf("client: decode server identity key: %w", err)
	}

	match = bytes.Equal(serverKey, localKey)
	return serverKey, localKey, match, nil
}

// GetDeviceIdentityKey fetches the identity key for a specific device from the server.
func (c *Client) GetDeviceIdentityKey(ctx context.Context, deviceID int) (string, error) {
	preKeys, err := c.service.GetPreKeys(ctx, c.aci, deviceID)
	if err != nil {
		return "", err
	}
	return preKeys.IdentityKey, nil
}

// DeviceInfo is the public type for device information.
type DeviceInfo = signalservice.DeviceInfo

// Devices returns the list of registered devices for this account.
func (c *Client) Devices(ctx context.Context) ([]DeviceInfo, error) {
	return c.service.GetDevices(ctx)
}

// UpdateAttributes updates account attributes on the Signal server.
// This can fix message delivery issues by ensuring the unidentifiedAccessKey is set.
func (c *Client) UpdateAttributes(ctx context.Context) error {
	if c.store == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	acct, err := c.store.LoadAccount()
	if err != nil {
		return fmt.Errorf("client: load account: %w", err)
	}
	if acct == nil {
		return fmt.Errorf("client: no account found")
	}

	attrs := &signalservice.AccountAttributes{
		RegistrationID:    acct.RegistrationID,
		PNIRegistrationID: acct.PNIRegistrationID,
		Voice:             true,
		Video:             true,
		FetchesMessages:   true,
		Capabilities: signalservice.Capabilities{
			Storage:                  true,
			VersionedExpirationTimer: true,
			AttachmentBackfill:       true,
		},
	}

	// Derive unidentified access key from profile key.
	if len(acct.ProfileKey) > 0 {
		uak, err := signalservice.DeriveAccessKey(acct.ProfileKey)
		if err != nil {
			return fmt.Errorf("client: derive access key: %w", err)
		}
		attrs.UnidentifiedAccessKey = base64.StdEncoding.EncodeToString(uak)
	}

	return c.service.SetAccountAttributes(ctx, attrs)
}

// AccountSettings contains configurable account settings.
type AccountSettings struct {
	// DiscoverableByPhoneNumber controls whether your number can be found via Contact Discovery.
	DiscoverableByPhoneNumber *bool
	// UnrestrictedUnidentifiedAccess allows anyone to send you sealed sender messages.
	UnrestrictedUnidentifiedAccess *bool
}

// UpdateAccountSettings updates account attributes and/or profile settings on the server.
// Only non-nil fields in settings are updated.
func (c *Client) UpdateAccountSettings(ctx context.Context, settings *AccountSettings) error {
	if c.store == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	acct, err := c.store.LoadAccount()
	if err != nil {
		return fmt.Errorf("client: load account: %w", err)
	}
	if acct == nil {
		return fmt.Errorf("client: no account found")
	}

	// Generate profile key if missing (needed for UnidentifiedAccessKey).
	if len(acct.ProfileKey) == 0 {
		if c.logger != nil {
			c.logger.Printf("generating new profile key for account")
		}
		acct.ProfileKey = signalservice.GenerateProfileKey()
		if err := c.store.SaveAccount(acct); err != nil {
			return fmt.Errorf("client: save account with profile key: %w", err)
		}
	}

	// Update account attributes if any attribute settings are provided.
	if settings.DiscoverableByPhoneNumber != nil || settings.UnrestrictedUnidentifiedAccess != nil {
		attrs := &signalservice.AccountAttributes{
			RegistrationID:    acct.RegistrationID,
			PNIRegistrationID: acct.PNIRegistrationID,
			Voice:             true,
			Video:             true,
			FetchesMessages:   true,
			Capabilities: signalservice.Capabilities{
				Storage:                  true,
				VersionedExpirationTimer: true,
				AttachmentBackfill:       true,
			},
		}

		// Derive unidentified access key from profile key.
		if len(acct.ProfileKey) > 0 {
			uak, err := signalservice.DeriveAccessKey(acct.ProfileKey)
			if err != nil {
				return fmt.Errorf("client: derive access key: %w", err)
			}
			attrs.UnidentifiedAccessKey = base64.StdEncoding.EncodeToString(uak)
		}

		if settings.DiscoverableByPhoneNumber != nil {
			attrs.DiscoverableByPhoneNumber = settings.DiscoverableByPhoneNumber
		}
		if settings.UnrestrictedUnidentifiedAccess != nil {
			attrs.UnrestrictedUnidentifiedAccess = *settings.UnrestrictedUnidentifiedAccess
		}

		if err := c.service.SetAccountAttributes(ctx, attrs); err != nil {
			return fmt.Errorf("client: set account attributes: %w", err)
		}
	}

	return nil
}

// RefreshPreKeys re-uploads local pre-keys to the server.
// Use this if pre-keys on the server are out of sync with local storage.
func (c *Client) RefreshPreKeys(ctx context.Context) error {
	if c.store == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	return c.service.RefreshPreKeys(ctx)
}

func (c *Client) storePreKeys(reg *signalservice.RegistrationResult) error {
	return c.storePreKeysForIdentities(reg.ACISignedPreKey, reg.ACIKyberPreKey, reg.PNISignedPreKey, reg.PNIKyberPreKey)
}

func (c *Client) storePreKeysForIdentities(aciSPK, aciKPK, pniSPK, pniKPK []byte) error {
	if err := c.storeSignedPreKeyFromBytes(aciSPK, "ACI"); err != nil {
		return err
	}
	if err := c.storeKyberPreKeyFromBytes(aciKPK, "ACI"); err != nil {
		return err
	}
	if err := c.storeSignedPreKeyFromBytes(pniSPK, "PNI"); err != nil {
		return err
	}
	return c.storeKyberPreKeyFromBytes(pniKPK, "PNI")
}

func (c *Client) openStore() error {
	dbPath := c.dbPath
	if dbPath == "" {
		// Use per-account DB: $XDG_DATA_HOME/signal-go/<aci>.db
		// If no ACI yet, use default.db (store.Open handles XDG default).
		name := "default"
		if c.aci != "" {
			name = c.aci
		}
		dir := store.DefaultDataDir()
		dbPath = filepath.Join(dir, name+".db")
	}

	s, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open store %s: %w", dbPath, err)
	}
	c.store = s
	return nil
}

func (c *Client) saveAccount() error {
	if c.store == nil {
		return fmt.Errorf("store not opened")
	}

	acct := &store.Account{
		Number:            c.number,
		ACI:               c.aci,
		PNI:               c.pni,
		Password:          c.password,
		DeviceID:          c.deviceID,
		RegistrationID:    c.registrationID,
		PNIRegistrationID: c.pniRegistrationID,
	}

	if c.data != nil {
		acct.ACIIdentityKeyPrivate = c.data.ACIIdentityKeyPrivate
		acct.ACIIdentityKeyPublic = c.data.ACIIdentityKeyPublic
		acct.PNIIdentityKeyPrivate = c.data.PNIIdentityKeyPrivate
		acct.PNIIdentityKeyPublic = c.data.PNIIdentityKeyPublic
		acct.ProfileKey = c.data.ProfileKey
		acct.MasterKey = c.data.MasterKey
	}

	if err := c.store.SaveAccount(acct); err != nil {
		return fmt.Errorf("save account: %w", err)
	}
	c.initService()
	return nil
}

// ProfileInfo contains basic profile information for display.
type ProfileInfo struct {
	Number     string
	ACI        string
	PNI        string
	DeviceID   int
	ProfileKey []byte
}

// ServerProfile contains decrypted profile data from the server.
type ServerProfile struct {
	Name       string
	About      string
	AboutEmoji string
	Avatar     string // CDN path, empty if no avatar
}

// ProfileInfo returns the current account's profile information.
func (c *Client) ProfileInfo() (*ProfileInfo, error) {
	if c.store == nil {
		return nil, fmt.Errorf("client not loaded")
	}

	acct, err := c.store.LoadAccount()
	if err != nil {
		return nil, fmt.Errorf("load account: %w", err)
	}
	if acct == nil {
		return nil, fmt.Errorf("no account found")
	}

	return &ProfileInfo{
		Number:     acct.Number,
		ACI:        acct.ACI,
		PNI:        acct.PNI,
		DeviceID:   acct.DeviceID,
		ProfileKey: acct.ProfileKey,
	}, nil
}

// GetServerProfile fetches and decrypts the user's profile from the server.
func (c *Client) GetServerProfile(ctx context.Context) (*ServerProfile, error) {
	if c.store == nil {
		return nil, fmt.Errorf("client not loaded")
	}

	acct, err := c.store.LoadAccount()
	if err != nil {
		return nil, fmt.Errorf("load account: %w", err)
	}
	if acct == nil {
		return nil, fmt.Errorf("no account found")
	}
	if len(acct.ProfileKey) == 0 {
		return nil, fmt.Errorf("no profile key available")
	}

	resp, err := c.service.GetProfile(ctx, acct.ACI, acct.ProfileKey)
	if err != nil {
		return nil, err
	}

	// Decrypt profile fields
	cipher, err := signalservice.NewProfileCipher(acct.ProfileKey)
	if err != nil {
		return nil, fmt.Errorf("create profile cipher: %w", err)
	}

	profile := &ServerProfile{
		Avatar:     resp.Avatar,
		Name:       decryptProfileField(resp.Name, cipher),
		About:      decryptProfileField(resp.About, cipher),
		AboutEmoji: decryptProfileField(resp.AboutEmoji, cipher),
	}

	return profile, nil
}

// decryptProfileField decodes base64 and decrypts a profile field.
// Returns empty string on any error (decode or decrypt).
func decryptProfileField(encoded string, cipher *signalservice.ProfileCipher) string {
	if encoded == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	decrypted, _ := cipher.DecryptString(data)
	return decrypted
}

// SetProfileName sets the profile name on the Signal server.
// If the account doesn't have a profile key, one is generated and saved.
func (c *Client) SetProfileName(ctx context.Context, name string) error {
	return c.SetProfile(ctx, name, nil)
}

// SetProfile updates profile settings on the Signal server.
// If name is empty and numberSharing is nil, this is a no-op.
// If the account doesn't have a profile key, one is generated and saved.
func (c *Client) SetProfile(ctx context.Context, name string, numberSharing *bool) error {
	if c.store == nil {
		return fmt.Errorf("client not loaded")
	}

	acct, err := c.store.LoadAccount()
	if err != nil {
		return fmt.Errorf("load account: %w", err)
	}
	if acct == nil {
		return fmt.Errorf("no account found")
	}

	// Generate profile key if missing (for accounts registered before profile key support).
	if len(acct.ProfileKey) == 0 {
		if c.logger != nil {
			c.logger.Printf("generating new profile key for account")
		}
		acct.ProfileKey = signalservice.GenerateProfileKey()
		if err := c.store.SaveAccount(acct); err != nil {
			return fmt.Errorf("save account with profile key: %w", err)
		}
	}

	// Build profile options, fetching current name if not provided
	var profileName *string
	if name != "" {
		profileName = &name
	} else {
		// Fetch current name to preserve it
		resp, err := c.service.GetProfile(ctx, acct.ACI, acct.ProfileKey)
		if err == nil && resp.Name != "" {
			cipher, _ := signalservice.NewProfileCipher(acct.ProfileKey)
			if cipher != nil {
				currentName := decryptProfileField(resp.Name, cipher)
				if currentName != "" {
					profileName = &currentName
				}
			}
		}
	}

	opts := &signalservice.ProfileOptions{
		Name:               profileName,
		PhoneNumberSharing: numberSharing,
	}
	return c.service.SetProfile(ctx, acct.ACI, acct.ProfileKey, opts)
}

// discoverDB finds the .db file in the default data directory.
// Returns an error if no database files exist or if multiple exist (ambiguous).
func discoverDB() (string, error) {
	dbFiles, err := listDBFiles()
	if err != nil {
		return "", err
	}

	if len(dbFiles) == 0 {
		return "", fmt.Errorf("no account database found in %s (run 'sgnl link' first)", store.DefaultDataDir())
	}
	if len(dbFiles) > 1 {
		// List accounts with phone numbers for better UX
		var lines []string
		for _, path := range dbFiles {
			number := getAccountNumber(path)
			if number != "" {
				lines = append(lines, fmt.Sprintf("%s (%s)", number, filepath.Base(path)))
			} else {
				lines = append(lines, filepath.Base(path))
			}
		}
		return "", fmt.Errorf("multiple accounts found, specify which one with --account <number> or --db <path>:\n  %s",
			strings.Join(lines, "\n  "))
	}
	return dbFiles[0], nil
}

// discoverDBByNumber finds a database file by phone number.
// Returns empty string if not found.
func discoverDBByNumber(number string) (string, error) {
	// Normalize number (ensure + prefix)
	if !strings.HasPrefix(number, "+") {
		number = "+" + number
	}

	dbFiles, err := listDBFiles()
	if err != nil {
		return "", err
	}

	for _, path := range dbFiles {
		if getAccountNumber(path) == number {
			return path, nil
		}
	}
	return "", fmt.Errorf("no account found for number %s", number)
}

// listDBFiles returns all .db files in the default data directory.
func listDBFiles() ([]string, error) {
	dir := store.DefaultDataDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read data dir %s: %w", dir, err)
	}

	var dbFiles []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".db" {
			continue
		}
		// Skip WAL and SHM files
		name := e.Name()
		if strings.HasSuffix(name, "-wal") || strings.HasSuffix(name, "-shm") {
			continue
		}
		dbFiles = append(dbFiles, filepath.Join(dir, name))
	}
	return dbFiles, nil
}

// getAccountNumber opens a database and returns the phone number, or empty string on error.
func getAccountNumber(dbPath string) string {
	s, err := store.Open(dbPath)
	if err != nil {
		return ""
	}
	defer s.Close()

	acct, err := s.LoadAccount()
	if err != nil || acct == nil {
		return ""
	}
	return acct.Number
}

type linkCallbacks struct {
	onQR func(uri string)
}

func (lc *linkCallbacks) OnLinkURI(uri string) {
	if lc.onQR != nil {
		lc.onQR(uri)
	}
}
