package provisioncrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// ComputeMAC returns HMAC-SHA256(key, data).
func ComputeMAC(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

// VerifyMAC checks that expectedMAC matches HMAC-SHA256(key, data) in constant time.
func VerifyMAC(key, data, expectedMAC []byte) error {
	computed := ComputeMAC(key, data)
	if !hmac.Equal(computed, expectedMAC) {
		return fmt.Errorf("MAC verification failed")
	}
	return nil
}
