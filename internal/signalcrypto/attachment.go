package signalcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/gwillem/signal-go/internal/proto"
)

const (
	CDNBaseURL  = "https://cdn.signal.org"
	CDN2BaseURL = "https://cdn2.signal.org"
	CDN3BaseURL = "https://cdn3.signal.org"
)

// DecryptAttachment decrypts a Signal attachment.
// The data format is: IV (16 bytes) || AES-CBC ciphertext || HMAC-SHA256 (32 bytes).
// The key is 64 bytes: 32 bytes AES key + 32 bytes HMAC key.
func DecryptAttachment(data, key []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, fmt.Errorf("attachment: key must be 64 bytes, got %d", len(key))
	}

	ivLen := aes.BlockSize // 16
	macLen := 32

	if len(data) < ivLen+macLen+aes.BlockSize {
		return nil, fmt.Errorf("attachment: data too short (%d bytes)", len(data))
	}

	aesKey := key[:32]
	hmacKey := key[32:]

	iv := data[:ivLen]
	ct := data[ivLen : len(data)-macLen]
	expectedMAC := data[len(data)-macLen:]

	// Verify HMAC over IV + ciphertext.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(data[:len(data)-macLen])
	if !hmac.Equal(mac.Sum(nil), expectedMAC) {
		return nil, fmt.Errorf("attachment: HMAC verification failed")
	}

	if len(ct)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("attachment: ciphertext not block-aligned")
	}

	// Decrypt AES-CBC.
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("attachment: create cipher: %w", err)
	}
	plaintext := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ct)

	// Strip PKCS7 padding.
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("attachment: empty plaintext")
	}
	padLen := int(plaintext[len(plaintext)-1])
	if padLen == 0 || padLen > aes.BlockSize || padLen > len(plaintext) {
		return nil, fmt.Errorf("attachment: invalid PKCS7 padding")
	}
	for _, b := range plaintext[len(plaintext)-padLen:] {
		if int(b) != padLen {
			return nil, fmt.Errorf("attachment: invalid PKCS7 padding bytes")
		}
	}
	return plaintext[:len(plaintext)-padLen], nil
}

// AttachmentURL returns the CDN download URL for an attachment pointer.
func AttachmentURL(ptr *proto.AttachmentPointer) (string, error) {
	cdnNumber := ptr.GetCdnNumber()

	// Select CDN base URL
	base := CDNBaseURL
	switch cdnNumber {
	case 2:
		base = CDN2BaseURL
	case 3:
		base = CDN3BaseURL
	}

	switch {
	case ptr.GetCdnKey() != "":
		return fmt.Sprintf("%s/attachments/%s", base, ptr.GetCdnKey()), nil
	case ptr.GetCdnId() != 0:
		return fmt.Sprintf("%s/attachments/%d", base, ptr.GetCdnId()), nil
	default:
		return "", fmt.Errorf("attachment: no CDN ID or key")
	}
}
