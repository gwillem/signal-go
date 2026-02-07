package signalservice

import (
	"fmt"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// preKeySet holds the keys generated for one identity (ACI or PNI).
type preKeySet struct {
	SignedPreKey   *libsignal.SignedPreKeyRecord
	KyberLastResort *libsignal.KyberPreKeyRecord
}

// generatePreKeySet generates a signed pre-key and Kyber last-resort pre-key,
// both signed by the given identity private key.
func generatePreKeySet(identityPriv *libsignal.PrivateKey, signedPreKeyID, kyberPreKeyID uint32) (*preKeySet, error) {
	now := uint64(time.Now().UnixMilli())

	// Generate signed EC pre-key.
	ecPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("keygen: generate EC key: %w", err)
	}
	defer ecPriv.Destroy()

	ecPub, err := ecPriv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("keygen: EC public key: %w", err)
	}
	defer ecPub.Destroy()

	ecPubBytes, err := ecPub.Serialize()
	if err != nil {
		return nil, fmt.Errorf("keygen: serialize EC pub: %w", err)
	}

	ecSig, err := identityPriv.Sign(ecPubBytes)
	if err != nil {
		return nil, fmt.Errorf("keygen: sign EC key: %w", err)
	}

	signedPreKey, err := libsignal.NewSignedPreKeyRecord(signedPreKeyID, now, ecPub, ecPriv, ecSig)
	if err != nil {
		return nil, fmt.Errorf("keygen: new signed pre-key: %w", err)
	}

	// Generate Kyber last-resort pre-key.
	kyberKP, err := libsignal.GenerateKyberKeyPair()
	if err != nil {
		signedPreKey.Destroy()
		return nil, fmt.Errorf("keygen: generate Kyber key: %w", err)
	}
	defer kyberKP.Destroy()

	kyberPub, err := kyberKP.PublicKey()
	if err != nil {
		signedPreKey.Destroy()
		return nil, fmt.Errorf("keygen: Kyber public key: %w", err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		signedPreKey.Destroy()
		return nil, fmt.Errorf("keygen: serialize Kyber pub: %w", err)
	}

	kyberSig, err := identityPriv.Sign(kyberPubBytes)
	if err != nil {
		signedPreKey.Destroy()
		return nil, fmt.Errorf("keygen: sign Kyber key: %w", err)
	}

	kyberPreKey, err := libsignal.NewKyberPreKeyRecord(kyberPreKeyID, now, kyberKP, kyberSig)
	if err != nil {
		signedPreKey.Destroy()
		return nil, fmt.Errorf("keygen: new Kyber pre-key: %w", err)
	}

	return &preKeySet{
		SignedPreKey:   signedPreKey,
		KyberLastResort: kyberPreKey,
	}, nil
}
