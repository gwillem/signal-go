package signalservice

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/gwillem/signal-go/internal/proto"
)

const (
	cdnBaseURL  = "https://cdn.signal.org"
	cdn2BaseURL = "https://cdn2.signal.org"
	cdn3BaseURL = "https://cdn3.signal.org"
)

// decryptAttachment decrypts a Signal attachment.
// The data format is: IV (16 bytes) || AES-CBC ciphertext || HMAC-SHA256 (32 bytes).
// The key is 64 bytes: 32 bytes AES key + 32 bytes HMAC key.
func decryptAttachment(data, key []byte) ([]byte, error) {
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

// downloadAttachment downloads and decrypts an attachment from Signal's CDN.
func downloadAttachment(ctx context.Context, ptr *proto.AttachmentPointer, tlsConf *tls.Config) ([]byte, error) {
	if ptr == nil {
		return nil, fmt.Errorf("attachment: nil pointer")
	}

	key := ptr.GetKey()
	if len(key) != 64 {
		return nil, fmt.Errorf("attachment: invalid key length %d", len(key))
	}

	url, err := attachmentURL(ptr)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("attachment: create request: %w", err)
	}

	client := &http.Client{}
	if tlsConf != nil {
		client.Transport = &http.Transport{TLSClientConfig: tlsConf}
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("attachment: download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attachment: download status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("attachment: read body: %w", err)
	}

	return decryptAttachment(data, key)
}

func attachmentURL(ptr *proto.AttachmentPointer) (string, error) {
	cdnNumber := ptr.GetCdnNumber()

	// Select CDN base URL
	base := cdnBaseURL
	switch cdnNumber {
	case 2:
		base = cdn2BaseURL
	case 3:
		base = cdn3BaseURL
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
