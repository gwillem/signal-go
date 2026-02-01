package provisioncrypto

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

const provisioningInfo = "TextSecure Provisioning Message"

// DeriveProvisioningKeys derives a 32-byte AES key and 32-byte MAC key from
// an ECDH shared secret using HKDF-SHA256.
func DeriveProvisioningKeys(sharedSecret []byte) (cipherKey, macKey []byte, err error) {
	r := hkdf.New(sha256.New, sharedSecret, nil, []byte(provisioningInfo))
	keys := make([]byte, 64)
	if _, err := r.Read(keys); err != nil {
		return nil, nil, err
	}
	cipherKey = make([]byte, 32)
	macKey = make([]byte, 32)
	copy(cipherKey, keys[:32])
	copy(macKey, keys[32:])
	return cipherKey, macKey, nil
}
