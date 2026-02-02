// Package signal provides a high-level client for the Signal messenger protocol.
package signal

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"iter"
	"log"
	"os"
	"path/filepath"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
	"github.com/gwillem/signal-go/internal/signalservice"
	"github.com/gwillem/signal-go/internal/store"
)

// Message represents a received Signal message.
type Message = signalservice.Message

const (
	defaultProvisioningURL = "wss://chat.signal.org/v1/websocket/provisioning/"
	defaultAPIURL          = "https://chat.signal.org"
	defaultWSURL           = "wss://chat.signal.org"
)

// Client is the main entry point for interacting with Signal.
type Client struct {
	provisioningURL   string
	apiURL            string
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
		tlsConfig:       signalservice.TLSConfig(),
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Link connects as a secondary device. It blocks until the primary device
// scans the QR code and completes provisioning, then registers the device
// with the Signal server. The onQR callback is called with the device link
// URI for display as a QR code.
func (c *Client) Link(ctx context.Context, onQR func(uri string)) error {
	cb := &linkCallbacks{onQR: onQR}
	result, err := signalservice.RunProvisioning(ctx, c.provisioningURL, cb, c.tlsConfig)
	if err != nil {
		return err
	}
	c.data = result.Data

	reg, err := signalservice.RegisterLinkedDevice(ctx, c.apiURL, result.Data, "signal-go", c.tlsConfig)
	if err != nil {
		return err
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

	// Set up identity key for the store.
	identityPriv, err := libsignal.DeserializePrivateKey(acct.ACIIdentityKeyPrivate)
	if err != nil {
		return fmt.Errorf("client: deserialize identity key: %w", err)
	}
	c.store.SetIdentity(identityPriv, uint32(acct.RegistrationID))

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

// Send sends a text message to the given recipient (ACI UUID).
func (c *Client) Send(ctx context.Context, recipient string, text string) error {
	if c.store == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	auth := signalservice.BasicAuth{
		Username: fmt.Sprintf("%s.%d", c.aci, c.deviceID),
		Password: c.password,
	}
	return signalservice.SendTextMessage(ctx, c.apiURL, recipient, text, c.store, auth, c.tlsConfig)
}

// Receive returns an iterator that yields incoming text messages.
// It connects to the authenticated WebSocket and decrypts messages.
// The iterator stops when the context is cancelled or the caller breaks.
func (c *Client) Receive(ctx context.Context) iter.Seq2[Message, error] {
	if c.store == nil {
		return func(yield func(Message, error) bool) {
			yield(Message{}, fmt.Errorf("client: not linked (call Link or Load first)"))
		}
	}
	auth := signalservice.BasicAuth{
		Username: fmt.Sprintf("%s.%d", c.aci, c.deviceID),
		Password: c.password,
	}
	wsURL := defaultWSURL
	return signalservice.ReceiveMessages(ctx, wsURL, c.apiURL, c.store, auth, c.aci, uint32(c.deviceID), c.tlsConfig, c.logger, c.debugDir)
}

// SyncContacts requests a contact sync from the primary device.
// The primary device will respond with a SyncMessage.Contacts that is
// automatically handled by the receive loop, populating the local contact store.
func (c *Client) SyncContacts(ctx context.Context) error {
	if c.store == nil {
		return fmt.Errorf("client: not linked (call Link or Load first)")
	}
	auth := signalservice.BasicAuth{
		Username: fmt.Sprintf("%s.%d", c.aci, c.deviceID),
		Password: c.password,
	}
	return signalservice.RequestContactSync(ctx, c.apiURL, c.store, auth, c.aci, c.tlsConfig, c.logger)
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

// DeviceInfo is the public type for device information.
type DeviceInfo = signalservice.DeviceInfo

// Devices returns the list of registered devices for this account.
func (c *Client) Devices(ctx context.Context) ([]DeviceInfo, error) {
	auth := signalservice.BasicAuth{
		Username: fmt.Sprintf("%s.%d", c.aci, c.deviceID),
		Password: c.password,
	}
	httpClient := signalservice.NewHTTPClient(c.apiURL, c.tlsConfig)
	return httpClient.GetDevices(ctx, auth)
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

	auth := signalservice.BasicAuth{
		Username: fmt.Sprintf("%s.%d", c.aci, c.deviceID),
		Password: c.password,
	}

	attrs := &signalservice.AccountAttributes{
		RegistrationID:    acct.RegistrationID,
		PNIRegistrationID: acct.PNIRegistrationID,
		FetchesMessages:   true,
		Capabilities: signalservice.Capabilities{
			Storage:                  true,
			VersionedExpirationTimer: true,
			AttachmentBackfill:       true,
		},
	}

	// Derive unidentified access key from profile key.
	if len(acct.ProfileKey) > 0 {
		uak, err := signalservice.DeriveUnidentifiedAccessKey(acct.ProfileKey)
		if err != nil {
			return fmt.Errorf("client: derive access key: %w", err)
		}
		attrs.UnidentifiedAccessKey = base64.StdEncoding.EncodeToString(uak)
	}

	httpClient := signalservice.NewHTTPClient(c.apiURL, c.tlsConfig)
	return httpClient.SetAccountAttributes(ctx, attrs, auth)
}

func (c *Client) storePreKeys(reg *signalservice.RegistrationResult) error {
	// Store ACI signed pre-key.
	if len(reg.ACISignedPreKey) > 0 {
		rec, err := libsignal.DeserializeSignedPreKeyRecord(reg.ACISignedPreKey)
		if err != nil {
			return fmt.Errorf("deserialize ACI signed pre-key: %w", err)
		}
		id, err := rec.ID()
		if err != nil {
			rec.Destroy()
			return fmt.Errorf("ACI signed pre-key ID: %w", err)
		}
		if err := c.store.StoreSignedPreKey(id, rec); err != nil {
			rec.Destroy()
			return fmt.Errorf("store ACI signed pre-key: %w", err)
		}
	}

	// Store ACI Kyber pre-key.
	if len(reg.ACIKyberPreKey) > 0 {
		rec, err := libsignal.DeserializeKyberPreKeyRecord(reg.ACIKyberPreKey)
		if err != nil {
			return fmt.Errorf("deserialize ACI Kyber pre-key: %w", err)
		}
		id, err := rec.ID()
		if err != nil {
			rec.Destroy()
			return fmt.Errorf("ACI Kyber pre-key ID: %w", err)
		}
		if err := c.store.StoreKyberPreKey(id, rec); err != nil {
			rec.Destroy()
			return fmt.Errorf("store ACI Kyber pre-key: %w", err)
		}
	}

	// Store PNI signed pre-key (uses offset ID to avoid colliding with ACI).
	if len(reg.PNISignedPreKey) > 0 {
		rec, err := libsignal.DeserializeSignedPreKeyRecord(reg.PNISignedPreKey)
		if err != nil {
			return fmt.Errorf("deserialize PNI signed pre-key: %w", err)
		}
		id, err := rec.ID()
		if err != nil {
			rec.Destroy()
			return fmt.Errorf("PNI signed pre-key ID: %w", err)
		}
		if err := c.store.StoreSignedPreKey(id, rec); err != nil {
			rec.Destroy()
			return fmt.Errorf("store PNI signed pre-key: %w", err)
		}
	}

	// Store PNI Kyber pre-key (uses offset ID to avoid colliding with ACI).
	if len(reg.PNIKyberPreKey) > 0 {
		rec, err := libsignal.DeserializeKyberPreKeyRecord(reg.PNIKyberPreKey)
		if err != nil {
			return fmt.Errorf("deserialize PNI Kyber pre-key: %w", err)
		}
		id, err := rec.ID()
		if err != nil {
			rec.Destroy()
			return fmt.Errorf("PNI Kyber pre-key ID: %w", err)
		}
		if err := c.store.StoreKyberPreKey(id, rec); err != nil {
			rec.Destroy()
			return fmt.Errorf("store PNI Kyber pre-key: %w", err)
		}
	}

	return nil
}

// Store returns the underlying store, or nil if not yet opened.
func (c *Client) Store() *store.Store {
	return c.store
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
		return err
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

	return c.store.SaveAccount(acct)
}

// discoverDB finds the most recently modified .db file in the default data directory.
// Returns an error if no database files exist.
func discoverDB() (string, error) {
	dir := store.DefaultDataDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("read data dir %s: %w", dir, err)
	}

	var bestPath string
	var bestTime int64
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".db" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if t := info.ModTime().UnixNano(); t > bestTime {
			bestTime = t
			bestPath = filepath.Join(dir, e.Name())
		}
	}
	if bestPath == "" {
		return "", fmt.Errorf("no account database found in %s (run 'sig link' first)", dir)
	}
	return bestPath, nil
}

type linkCallbacks struct {
	onQR func(uri string)
}

func (lc *linkCallbacks) OnLinkURI(uri string) {
	if lc.onQR != nil {
		lc.onQR(uri)
	}
}
