// Package signal provides a high-level client for the Signal messenger protocol.
package signal

import (
	"context"
	"crypto/tls"
	"fmt"
	"path/filepath"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
	"github.com/gwillem/signal-go/internal/signalservice"
	"github.com/gwillem/signal-go/internal/store"
)

const (
	defaultProvisioningURL = "wss://chat.signal.org/v1/websocket/provisioning/"
	defaultAPIURL          = "https://chat.signal.org"
)

// Client is the main entry point for interacting with Signal.
type Client struct {
	provisioningURL string
	apiURL          string
	tlsConfig       *tls.Config
	dbPath          string
	data            *provisioncrypto.ProvisionData
	store           *store.Store
	deviceID        int
	aci             string
	pni             string
	password        string
	number          string
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

	// Open store and persist credentials.
	if err := c.openStore(); err != nil {
		return fmt.Errorf("client: open store: %w", err)
	}

	return c.saveAccount()
}

// Load opens an existing database and loads credentials without re-linking.
func (c *Client) Load() error {
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
		Number:   c.number,
		ACI:      c.aci,
		PNI:      c.pni,
		Password: c.password,
		DeviceID: c.deviceID,
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

type linkCallbacks struct {
	onQR func(uri string)
}

func (lc *linkCallbacks) OnLinkURI(uri string) {
	if lc.onQR != nil {
		lc.onQR(uri)
	}
}
