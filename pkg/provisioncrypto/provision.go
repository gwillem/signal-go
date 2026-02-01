package provisioncrypto

import (
	"fmt"

	"github.com/gwillem/signal-go/pkg/libsignal"
)

const (
	provisionVersion = 0x01
	macSize          = 32
	ivSize           = 16
	// Minimum body: version(1) + iv(16) + at least 1 block(16) + mac(32) = 65
	minBodySize = 1 + ivSize + 16 + macSize
)

// DecryptProvisionEnvelope decrypts a provisioning envelope body using
// the secondary device's private key and the primary's ephemeral public key bytes.
//
// Body wire format: version(1) || iv(16) || ciphertext(variable) || mac(32)
func DecryptProvisionEnvelope(ourKey *libsignal.PrivateKey, theirPublicKeyBytes, body []byte) ([]byte, error) {
	if len(body) < minBodySize {
		return nil, fmt.Errorf("provision: body too short (%d bytes)", len(body))
	}

	if body[0] != provisionVersion {
		return nil, fmt.Errorf("provision: unsupported version 0x%02x", body[0])
	}

	theirPub, err := libsignal.DeserializePublicKey(theirPublicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("provision: deserialize public key: %w", err)
	}
	defer theirPub.Destroy()

	sharedSecret, err := ourKey.Agree(theirPub)
	if err != nil {
		return nil, fmt.Errorf("provision: ECDH agree: %w", err)
	}

	cipherKey, macKey, err := DeriveProvisioningKeys(sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("provision: derive keys: %w", err)
	}

	macOffset := len(body) - macSize
	mac := body[macOffset:]
	authenticated := body[:macOffset]

	if err := VerifyMAC(macKey, authenticated, mac); err != nil {
		return nil, fmt.Errorf("provision: %w", err)
	}

	iv := body[1 : 1+ivSize]
	ct := body[1+ivSize : macOffset]

	plaintext, err := DecryptAESCBC(cipherKey, iv, ct)
	if err != nil {
		return nil, fmt.Errorf("provision: %w", err)
	}

	return plaintext, nil
}
