package signalservice

import (
	"encoding/base64"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// Signal's production sealed sender trust root public keys.
// From Signal-Android/app/build.gradle.kts UNIDENTIFIED_SENDER_TRUST_ROOTS.
var sealedSenderTrustRoots = []string{
	"BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF",
	"BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6",
}

// loadTrustRoot decodes and deserializes the primary sealed sender trust root public key.
func loadTrustRoot() (*libsignal.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(sealedSenderTrustRoots[0])
	if err != nil {
		return nil, err
	}
	return libsignal.DeserializePublicKey(raw)
}
