package signalservice

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestDeviceLinkURI(t *testing.T) {
	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	pubKey := []byte{0x05, 0x01, 0x02, 0x03, 0x04}

	uri := DeviceLinkURI(uuid, pubKey)
	want := "sgnl://linkdevice?uuid=a1b2c3d4-e5f6-7890-abcd-ef1234567890&pub_key=" + base64.URLEncoding.EncodeToString(pubKey)

	if uri != want {
		t.Fatalf("got:\n  %s\nwant:\n  %s", uri, want)
	}
}

func TestDeviceLinkURIBase64Encoding(t *testing.T) {
	uuid := "test-uuid"
	// Bytes that would produce + and / in standard base64 → should use URL-safe encoding.
	pubKey := []byte{0xfb, 0xef, 0xbe}
	uri := DeviceLinkURI(uuid, pubKey)

	// Extract the base64 part (after "pub_key=").
	parts := strings.SplitN(uri, "pub_key=", 2)
	if len(parts) != 2 {
		t.Fatalf("expected pub_key= in URI: %s", uri)
	}
	b64Part := parts[1]

	// Base64 part should not contain + or / (URL-unsafe characters).
	for _, c := range b64Part {
		if c == '+' || c == '/' {
			t.Fatalf("base64 contains non-URL-safe character: %s", b64Part)
		}
	}
}
