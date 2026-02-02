package signalservice

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

// buildEncryptedAttachment creates a Signal-format encrypted attachment:
// IV (16 bytes) || AES-CBC ciphertext (PKCS7 padded) || HMAC-SHA256 (32 bytes)
// The HMAC covers IV + ciphertext.
func buildEncryptedAttachment(t *testing.T, plaintext, aesKey, hmacKey []byte) []byte {
	t.Helper()

	// PKCS7 pad to AES block size.
	padLen := aes.BlockSize - (len(plaintext) % aes.BlockSize)
	padded := append(plaintext, bytes.Repeat([]byte{byte(padLen)}, padLen)...)

	// Random IV.
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		t.Fatal(err)
	}

	// Encrypt.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		t.Fatal(err)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	// Build: IV || ciphertext.
	out := append(iv, ct...)

	// HMAC over IV + ciphertext.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(out)
	out = append(out, mac.Sum(nil)...)

	return out
}

func TestDecryptAttachment(t *testing.T) {
	plaintext := []byte("hello signal contacts")
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	rand.Read(aesKey)
	rand.Read(hmacKey)

	encrypted := buildEncryptedAttachment(t, plaintext, aesKey, hmacKey)

	// key = aesKey || hmacKey (64 bytes)
	key := append(aesKey, hmacKey...)

	got, err := DecryptAttachment(encrypted, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

func TestDecryptAttachment_BadHMAC(t *testing.T) {
	plaintext := []byte("hello")
	aesKey := make([]byte, 32)
	hmacKey := make([]byte, 32)
	rand.Read(aesKey)
	rand.Read(hmacKey)

	encrypted := buildEncryptedAttachment(t, plaintext, aesKey, hmacKey)

	// Corrupt the HMAC.
	encrypted[len(encrypted)-1] ^= 0xff

	key := append(aesKey, hmacKey...)
	_, err := DecryptAttachment(encrypted, key)
	if err == nil {
		t.Fatal("expected HMAC error")
	}
}

func TestDecryptAttachment_ShortKey(t *testing.T) {
	_, err := DecryptAttachment(make([]byte, 100), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for short key")
	}
}

func TestDecryptAttachment_TooShort(t *testing.T) {
	_, err := DecryptAttachment(make([]byte, 10), make([]byte, 64))
	if err == nil {
		t.Fatal("expected error for short data")
	}
}
