package signalcrypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestNewProfileCipher(t *testing.T) {
	tests := []struct {
		name    string
		keyLen  int
		wantErr bool
	}{
		{"valid 32-byte key", 32, false},
		{"too short", 16, true},
		{"too long", 64, true},
		{"empty", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keyLen)
			rand.Read(key)

			cipher, err := NewProfileCipher(key)
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cipher == nil {
				t.Error("expected cipher, got nil")
			}
		})
	}
}

func TestProfileCipherRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	cipher, err := NewProfileCipher(key)
	if err != nil {
		t.Fatalf("NewProfileCipher: %v", err)
	}

	tests := []struct {
		name         string
		input        []byte
		paddedLength int
	}{
		{"empty", []byte{}, 16},
		{"short text", []byte("hello"), 32},
		{"exact length", []byte("12345678"), 8},
		{"binary data", []byte{0x00, 0xFF, 0x7F, 0x80}, 16},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := cipher.Encrypt(tt.input, tt.paddedLength)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			// Verify ciphertext has expected structure
			expectedLen := 12 + tt.paddedLength + 16 // nonce + padded data + tag
			if len(encrypted) != expectedLen {
				t.Errorf("encrypted length = %d, want %d", len(encrypted), expectedLen)
			}

			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			// Decrypted should be padded length, with original at start
			if len(decrypted) != tt.paddedLength {
				t.Errorf("decrypted length = %d, want %d", len(decrypted), tt.paddedLength)
			}

			if !bytes.HasPrefix(decrypted, tt.input) {
				t.Errorf("decrypted prefix mismatch: got %v, want prefix %v", decrypted, tt.input)
			}

			// Verify padding is null bytes
			for i := len(tt.input); i < len(decrypted); i++ {
				if decrypted[i] != 0 {
					t.Errorf("padding byte at %d = %d, want 0", i, decrypted[i])
				}
			}
		})
	}
}

func TestProfileCipherStringRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	cipher, err := NewProfileCipher(key)
	if err != nil {
		t.Fatalf("NewProfileCipher: %v", err)
	}

	tests := []struct {
		name         string
		input        string
		paddedLength int
	}{
		{"empty string", "", 16},
		{"ASCII", "Hello World", 32},
		{"Unicode", "日本語テスト", 64},
		{"emoji", "👋🌍", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := cipher.EncryptString(tt.input, tt.paddedLength)
			if err != nil {
				t.Fatalf("EncryptString: %v", err)
			}

			decrypted, err := cipher.DecryptString(encrypted)
			if err != nil {
				t.Fatalf("DecryptString: %v", err)
			}

			if decrypted != tt.input {
				t.Errorf("DecryptString = %q, want %q", decrypted, tt.input)
			}
		})
	}
}

func TestProfileCipherEncryptBoolean(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	cipher, err := NewProfileCipher(key)
	if err != nil {
		t.Fatalf("NewProfileCipher: %v", err)
	}

	for _, value := range []bool{true, false} {
		t.Run("", func(t *testing.T) {
			encrypted, err := cipher.EncryptBoolean(value)
			if err != nil {
				t.Fatalf("EncryptBoolean(%v): %v", value, err)
			}

			// Should be nonce(12) + 1 byte + tag(16) = 29 bytes
			if len(encrypted) != 29 {
				t.Errorf("encrypted length = %d, want 29", len(encrypted))
			}

			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if len(decrypted) != 1 {
				t.Fatalf("decrypted length = %d, want 1", len(decrypted))
			}

			got := decrypted[0] == 1
			if got != value {
				t.Errorf("decrypted boolean = %v, want %v", got, value)
			}
		})
	}
}

func TestProfileCipherInputTooLong(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	cipher, err := NewProfileCipher(key)
	if err != nil {
		t.Fatalf("NewProfileCipher: %v", err)
	}

	input := []byte("this is longer than eight bytes")
	_, err = cipher.Encrypt(input, 8)
	if err == nil {
		t.Error("expected error for input longer than padded length")
	}
}

func TestProfileCipherDecryptTooShort(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	cipher, err := NewProfileCipher(key)
	if err != nil {
		t.Fatalf("NewProfileCipher: %v", err)
	}

	// Minimum valid ciphertext: 12 (nonce) + 1 (data) + 16 (tag) = 29 bytes
	shortInputs := [][]byte{
		nil,
		{},
		make([]byte, 28), // one byte too short
	}

	for _, input := range shortInputs {
		_, err := cipher.Decrypt(input)
		if err == nil {
			t.Errorf("expected error for short input of length %d", len(input))
		}
	}
}

func TestProfileCipherTamperedCiphertext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	cipher, err := NewProfileCipher(key)
	if err != nil {
		t.Fatalf("NewProfileCipher: %v", err)
	}

	encrypted, err := cipher.EncryptString("test", 32)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	// Tamper with ciphertext (flip a bit in the middle)
	tampered := make([]byte, len(encrypted))
	copy(tampered, encrypted)
	tampered[20] ^= 0xFF

	_, err = cipher.Decrypt(tampered)
	if err == nil {
		t.Error("expected error for tampered ciphertext")
	}
}

func TestProfileCipherWrongKey(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)

	cipher1, _ := NewProfileCipher(key1)
	cipher2, _ := NewProfileCipher(key2)

	encrypted, err := cipher1.EncryptString("secret", 32)
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	_, err = cipher2.Decrypt(encrypted)
	if err == nil {
		t.Error("expected error when decrypting with wrong key")
	}
}

func TestGetTargetNameLength(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"", NamePaddedLength1},
		{"short", NamePaddedLength1},
		{string(make([]byte, NamePaddedLength1)), NamePaddedLength1},     // exactly 53 bytes
		{string(make([]byte, NamePaddedLength1+1)), NamePaddedLength2},   // 54 bytes -> 257
		{string(make([]byte, NamePaddedLength2)), NamePaddedLength2},     // 257 bytes
	}

	for _, tt := range tests {
		got := GetTargetNameLength(tt.name)
		if got != tt.want {
			t.Errorf("GetTargetNameLength(%d bytes) = %d, want %d", len(tt.name), got, tt.want)
		}
	}
}

func TestGetTargetAboutLength(t *testing.T) {
	tests := []struct {
		aboutLen int
		want     int
	}{
		{0, aboutPaddedLength1},
		{50, aboutPaddedLength1},
		{128, aboutPaddedLength1},        // exactly 128 -> 128
		{129, aboutPaddedLength2},        // 129 -> 254
		{253, aboutPaddedLength2},        // 253 < 254 -> 254
		{254, aboutPaddedLength3},        // 254 >= 254 -> 512
		{400, aboutPaddedLength3},
	}

	for _, tt := range tests {
		about := string(make([]byte, tt.aboutLen))
		got := GetTargetAboutLength(about)
		if got != tt.want {
			t.Errorf("GetTargetAboutLength(%d bytes) = %d, want %d", tt.aboutLen, got, tt.want)
		}
	}
}

func TestProfileCipherDeterministicPadding(t *testing.T) {
	// Verify that same input produces same padded plaintext (different ciphertext due to random nonce)
	key := make([]byte, 32)
	rand.Read(key)

	cipher, _ := NewProfileCipher(key)

	encrypted1, _ := cipher.EncryptString("test", 32)
	encrypted2, _ := cipher.EncryptString("test", 32)

	// Ciphertexts should differ (random nonce)
	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("two encryptions of same input should produce different ciphertexts")
	}

	// But both should decrypt to same value
	decrypted1, _ := cipher.DecryptString(encrypted1)
	decrypted2, _ := cipher.DecryptString(encrypted2)

	if decrypted1 != decrypted2 {
		t.Errorf("decrypted values differ: %q vs %q", decrypted1, decrypted2)
	}
}
