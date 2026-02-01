// Package signalservice orchestrates Signal protocol operations:
// device provisioning, message sending, and message receiving.
package signalservice

import (
	"encoding/base64"
	"net/url"
)

// DeviceLinkURI formats a device-linking URI for display as a QR code.
// The public key is encoded as standard Base64 (no padding), then URL-encoded,
// matching Signal-Android's ProvisioningSocket.kt.
func DeviceLinkURI(uuid string, pubKey []byte) string {
	encoded := base64.RawStdEncoding.EncodeToString(pubKey)
	return "sgnl://linkdevice?uuid=" + uuid + "&pub_key=" + url.QueryEscape(encoded)
}
