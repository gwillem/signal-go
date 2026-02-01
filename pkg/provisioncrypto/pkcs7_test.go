package provisioncrypto

import (
	"bytes"
	"testing"
)

func TestPKCS7PadUnpadRoundTrip(t *testing.T) {
	for dataLen := range 33 {
		data := bytes.Repeat([]byte{0x42}, dataLen)
		padded := PKCS7Pad(data, 16)
		if len(padded)%16 != 0 {
			t.Fatalf("len=%d: padded length %d not multiple of 16", dataLen, len(padded))
		}
		unpadded, err := PKCS7Unpad(padded, 16)
		if err != nil {
			t.Fatalf("len=%d: unpad error: %v", dataLen, err)
		}
		if !bytes.Equal(unpadded, data) {
			t.Fatalf("len=%d: round-trip mismatch", dataLen)
		}
	}
}

func TestPKCS7PadBlockAligned(t *testing.T) {
	// Block-aligned input gets a full block of padding.
	data := bytes.Repeat([]byte{0x01}, 16)
	padded := PKCS7Pad(data, 16)
	if len(padded) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(padded))
	}
	// Last 16 bytes should all be 0x10.
	for _, b := range padded[16:] {
		if b != 16 {
			t.Fatalf("expected padding byte 0x10, got 0x%02x", b)
		}
	}
}

func TestPKCS7UnpadRejectsInvalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"not block-aligned", []byte{0x01, 0x02, 0x03}},
		{"zero padding byte", bytes.Repeat([]byte{0x00}, 16)},
		{"padding too large", append(bytes.Repeat([]byte{0x00}, 15), 17)},
		{"inconsistent padding", append(bytes.Repeat([]byte{0x00}, 14), 0x01, 0x02)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := PKCS7Unpad(tc.data, 16)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}
