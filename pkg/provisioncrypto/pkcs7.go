// Package provisioncrypto implements the Signal provisioning envelope
// crypto: HKDF key derivation, HMAC-SHA256, AES-256-CBC, and PKCS#7 padding.
package provisioncrypto

import "fmt"

// PKCS7Pad appends PKCS#7 padding so the result length is a multiple of blockSize.
func PKCS7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	padding := make([]byte, pad)
	for i := range padding {
		padding[i] = byte(pad)
	}
	return append(data, padding...)
}

// PKCS7Unpad removes and validates PKCS#7 padding.
func PKCS7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7: invalid data length %d", len(data))
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, fmt.Errorf("pkcs7: invalid padding byte %d", pad)
	}
	for _, b := range data[len(data)-pad:] {
		if int(b) != pad {
			return nil, fmt.Errorf("pkcs7: inconsistent padding")
		}
	}
	return data[:len(data)-pad], nil
}
