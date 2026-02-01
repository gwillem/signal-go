package signalservice

import "encoding/base64"

// DeviceLinkURI formats a device-linking URI for display as a QR code.
func DeviceLinkURI(uuid string, pubKey []byte) string {
	return "sgnl://linkdevice?uuid=" + uuid + "&pub_key=" + base64.URLEncoding.EncodeToString(pubKey)
}
