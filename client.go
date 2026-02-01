// Package signal provides a high-level client for the Signal messenger protocol.
package signal

import (
	"context"

	"github.com/gwillem/signal-go/internal/provisioncrypto"
	"github.com/gwillem/signal-go/internal/signalservice"
)

const defaultProvisioningURL = "wss://chat.signal.org/v1/websocket/provisioning/"

// Client is the main entry point for interacting with Signal.
type Client struct {
	provisioningURL string
	data            *provisioncrypto.ProvisionData
}

// Option configures a Client.
type Option func(*Client)

// WithProvisioningURL overrides the default provisioning WebSocket URL.
func WithProvisioningURL(url string) Option {
	return func(c *Client) { c.provisioningURL = url }
}

// NewClient creates a new Signal client.
func NewClient(opts ...Option) *Client {
	c := &Client{provisioningURL: defaultProvisioningURL}
	for _, o := range opts {
		o(c)
	}
	return c
}

// Link connects as a secondary device. It blocks until the primary device
// scans the QR code and completes provisioning. The onQR callback is called
// with the device link URI for display as a QR code.
func (c *Client) Link(ctx context.Context, onQR func(uri string)) error {
	cb := &linkCallbacks{onQR: onQR}
	result, err := signalservice.RunProvisioning(ctx, c.provisioningURL, cb)
	if err != nil {
		return err
	}
	c.data = result.Data
	return nil
}

// Number returns the phone number associated with the linked account.
func (c *Client) Number() string {
	if c.data == nil {
		return ""
	}
	return c.data.Number
}

type linkCallbacks struct {
	onQR func(uri string)
}

func (lc *linkCallbacks) OnLinkURI(uri string) {
	if lc.onQR != nil {
		lc.onQR(uri)
	}
}
