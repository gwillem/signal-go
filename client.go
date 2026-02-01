// Package signal provides a high-level client for the Signal messenger protocol.
package signal

import (
	"context"
	"crypto/tls"

	"github.com/gwillem/signal-go/internal/provisioncrypto"
	"github.com/gwillem/signal-go/internal/signalservice"
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
	data            *provisioncrypto.ProvisionData
	deviceID        int
	aci             string
	pni             string
	password        string
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
	return nil
}

// Number returns the phone number associated with the linked account.
func (c *Client) Number() string {
	if c.data == nil {
		return ""
	}
	return c.data.Number
}

// DeviceID returns the device ID assigned during registration.
func (c *Client) DeviceID() int {
	return c.deviceID
}

type linkCallbacks struct {
	onQR func(uri string)
}

func (lc *linkCallbacks) OnLinkURI(uri string) {
	if lc.onQR != nil {
		lc.onQR(uri)
	}
}
