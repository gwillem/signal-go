package signalservice

import (
	"encoding/base64"
	"fmt"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// Signal's production sealed sender trust root public keys.
// From Signal-Android/app/build.gradle.kts UNIDENTIFIED_SENDER_TRUST_ROOTS.
var sealedSenderTrustRoots = []string{
	"BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF",
	"BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6",
}

// loadTrustRoots decodes and deserializes all sealed sender trust root public keys.
func loadTrustRoots() ([]*libsignal.PublicKey, error) {
	roots := make([]*libsignal.PublicKey, 0, len(sealedSenderTrustRoots))
	for i, b64 := range sealedSenderTrustRoots {
		raw, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("decode trust root %d: %w", i, err)
		}
		key, err := libsignal.DeserializePublicKey(raw)
		if err != nil {
			return nil, fmt.Errorf("deserialize trust root %d: %w", i, err)
		}
		roots = append(roots, key)
	}
	return roots, nil
}
