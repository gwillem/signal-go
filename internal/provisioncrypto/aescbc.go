package provisioncrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// EncryptAESCBC encrypts plaintext with AES-256-CBC using PKCS7 padding.
// Returns iv || ciphertext.
func EncryptAESCBC(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aescbc: %w", err)
	}

	padded := PKCS7Pad(plaintext, aes.BlockSize)

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("aescbc: %w", err)
	}

	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	return append(iv, ct...), nil
}

// DecryptAESCBC decrypts AES-256-CBC ciphertext with a given IV, removing PKCS7 padding.
func DecryptAESCBC(key, iv, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aescbc: %w", err)
	}
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("aescbc: ciphertext length %d not a multiple of block size", len(ciphertext))
	}
	if len(iv) != aes.BlockSize {
		return nil, fmt.Errorf("aescbc: invalid IV length %d", len(iv))
	}

	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return PKCS7Unpad(plaintext, aes.BlockSize)
}
