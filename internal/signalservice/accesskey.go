package signalservice

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const accessKeyLen = 16

// DeriveAccessKey derives the unidentified access key from a profile key.
// This matches Signal's ProfileKey.deriveAccessKey() implementation.
// Algorithm: AES-256-GCM encrypt 16 zero bytes with profile key as key and zero nonce.
// We only take the ciphertext part (no auth tag).
func DeriveAccessKey(profileKey []byte) ([]byte, error) {
	if len(profileKey) != 32 {
		return nil, fmt.Errorf("profile key must be 32 bytes, got %d", len(profileKey))
	}

	block, err := aes.NewCipher(profileKey)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	// 12-byte zero nonce
	nonce := make([]byte, 12)

	// Encrypt 16 zero bytes with empty AAD
	plaintext := make([]byte, accessKeyLen)
	ciphertext := aesGCM.Seal(nil, nonce, plaintext, nil)

	// Seal returns ciphertext || tag. We only want the first 16 bytes (ciphertext).
	return ciphertext[:accessKeyLen], nil
}
