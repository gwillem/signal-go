package signalservice

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/gwillem/signal-go/internal/store"
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

// deriveAccessKeyForRecipient looks up a recipient's profile key and derives
// their unidentified access key. Returns an error if no profile key is available.
func deriveAccessKeyForRecipient(st *store.Store, recipient string) ([]byte, error) {
	contact, err := st.GetContactByACI(recipient)
	if err != nil {
		return nil, fmt.Errorf("get contact: %w", err)
	}
	if contact == nil || len(contact.ProfileKey) == 0 {
		return nil, fmt.Errorf("no profile key for %s (run sync-contacts or receive a message from them first)", recipient)
	}
	return DeriveAccessKey(contact.ProfileKey)
}
