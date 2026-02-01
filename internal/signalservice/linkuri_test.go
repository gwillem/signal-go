package signalservice

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"
)

func TestDeviceLinkURI(t *testing.T) {
	uuid := "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	pubKey := []byte{0x05, 0x01, 0x02, 0x03, 0x04}

	uri := DeviceLinkURI(uuid, pubKey)

	// Should use standard base64 without padding, URL-encoded.
	wantB64 := url.QueryEscape(base64.RawStdEncoding.EncodeToString(pubKey))
	want := "sgnl://linkdevice?uuid=" + uuid + "&pub_key=" + wantB64

	if uri != want {
		t.Fatalf("got:\n  %s\nwant:\n  %s", uri, want)
	}
}

func TestDeviceLinkURIRoundTrip(t *testing.T) {
	uuid := "test-uuid"
	// Bytes that produce + and / in standard base64.
	pubKey := []byte{0xfb, 0xef, 0xbe}
	uri := DeviceLinkURI(uuid, pubKey)

	// Parse URI and extract pub_key (URL-decoding happens automatically).
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	if parsed.Scheme != "sgnl" {
		t.Fatalf("scheme: got %q, want sgnl", parsed.Scheme)
	}
	if parsed.Host != "linkdevice" {
		t.Fatalf("host: got %q, want linkdevice", parsed.Host)
	}

	gotB64 := parsed.Query().Get("pub_key")
	decoded, err := base64.RawStdEncoding.DecodeString(gotB64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(decoded) != string(pubKey) {
		t.Fatalf("pub key mismatch after round-trip")
	}
}

func TestDeviceLinkURINoRawUnsafeChars(t *testing.T) {
	// Bytes that produce + and / in standard base64.
	pubKey := []byte{0xfb, 0xef, 0xbe}
	uri := DeviceLinkURI("test", pubKey)

	// The raw URI should not contain unescaped + or / in the query value.
	parts := strings.SplitN(uri, "pub_key=", 2)
	if len(parts) != 2 {
		t.Fatalf("expected pub_key= in URI: %s", uri)
	}
	b64Part := parts[1]

	// After URL-encoding, + becomes %2B and / becomes %2F.
	for _, c := range b64Part {
		if c == '+' || c == '/' {
			t.Fatalf("URI contains unescaped unsafe character in: %s", b64Part)
		}
	}
}
