package signalservice

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
)

const storageIVLength = 12 // AES-GCM nonce length

// DecryptStorageManifest decrypts an encrypted storage manifest.
// Format: 12-byte IV || ciphertext || 16-byte auth tag
func DecryptStorageManifest(key StorageManifestKey, data []byte) ([]byte, error) {
	return decryptStorageData(key[:], data)
}

// DecryptStorageItem decrypts an encrypted storage item.
// Format: 12-byte IV || ciphertext || 16-byte auth tag
func DecryptStorageItem(key StorageItemKey, data []byte) ([]byte, error) {
	return decryptStorageData(key[:], data)
}

// decryptStorageData performs AES-256-GCM decryption.
// Signal uses: 12-byte IV prepended to ciphertext (which includes auth tag).
func decryptStorageData(key []byte, data []byte) ([]byte, error) {
	if len(data) < storageIVLength {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}

	iv := data[:storageIVLength]
	ciphertext := data[storageIVLength:]

	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
