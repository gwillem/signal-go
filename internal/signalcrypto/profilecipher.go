package signalcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const (
	profileEncryptionOverhead = 28 // 12-byte nonce + 16-byte GCM tag
	NamePaddedLength1         = 53
	NamePaddedLength2         = 257
	aboutPaddedLength1        = 128
	aboutPaddedLength2        = 254
	aboutPaddedLength3        = 512
	emojiPaddedLength         = 32
)

// ProfileCipher encrypts profile fields using AES-GCM with the profile key.
type ProfileCipher struct {
	key []byte
}

// NewProfileCipher creates a cipher from a 32-byte profile key.
func NewProfileCipher(profileKey []byte) (*ProfileCipher, error) {
	if len(profileKey) != 32 {
		return nil, fmt.Errorf("profile key must be 32 bytes, got %d", len(profileKey))
	}
	return &ProfileCipher{key: profileKey}, nil
}

// EncryptString encrypts a string to the specified padded length.
func (pc *ProfileCipher) EncryptString(input string, paddedLength int) ([]byte, error) {
	return pc.Encrypt([]byte(input), paddedLength)
}

// Encrypt encrypts data with padding to the specified length.
// Output format: [12-byte nonce][encrypted padded data][16-byte GCM tag]
func (pc *ProfileCipher) Encrypt(input []byte, paddedLength int) ([]byte, error) {
	if len(input) > paddedLength {
		return nil, fmt.Errorf("input too long: %d > %d", len(input), paddedLength)
	}

	// Pad the input
	padded := make([]byte, paddedLength)
	copy(padded, input)

	// Generate random nonce
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt using AES-GCM
	block, err := aes.NewCipher(pc.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}

	// Seal appends the ciphertext and tag to nonce
	return aead.Seal(nonce, nonce, padded, nil), nil
}

// EncryptBoolean encrypts a boolean value.
func (pc *ProfileCipher) EncryptBoolean(value bool) ([]byte, error) {
	data := []byte{0}
	if value {
		data[0] = 1
	}
	return pc.Encrypt(data, 1)
}

// GetTargetNameLength returns the appropriate padded length for a name.
func GetTargetNameLength(name string) int {
	nameLen := len([]byte(name))
	if nameLen <= NamePaddedLength1 {
		return NamePaddedLength1
	}
	return NamePaddedLength2
}

// GetTargetAboutLength returns the appropriate padded length for about text.
func GetTargetAboutLength(about string) int {
	aboutLen := len([]byte(about))
	if aboutLen <= aboutPaddedLength1 {
		return aboutPaddedLength1
	}
	if aboutLen < aboutPaddedLength2 {
		return aboutPaddedLength2
	}
	return aboutPaddedLength3
}

// Decrypt decrypts data encrypted by Encrypt.
// Input format: [12-byte nonce][encrypted padded data][16-byte GCM tag]
func (pc *ProfileCipher) Decrypt(input []byte) ([]byte, error) {
	if len(input) < 12+16+1 {
		return nil, fmt.Errorf("ciphertext too short: %d bytes", len(input))
	}

	nonce := input[:12]
	ciphertext := input[12:]

	block, err := aes.NewCipher(pc.key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("aes-gcm: %w", err)
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}

// DecryptString decrypts and strips null padding from a string field.
func (pc *ProfileCipher) DecryptString(input []byte) (string, error) {
	plaintext, err := pc.Decrypt(input)
	if err != nil {
		return "", err
	}

	// Strip null padding from the end
	end := len(plaintext)
	for end > 0 && plaintext[end-1] == 0 {
		end--
	}

	return string(plaintext[:end]), nil
}
