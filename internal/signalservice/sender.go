package signalservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// SendTextMessage sends a text message to a recipient. It handles session
// establishment (fetching pre-keys if needed), encryption, and HTTP delivery.
// Automatically retries on 410 (stale devices).
func SendTextMessage(ctx context.Context, apiURL string, recipient string, text string, st *store.Store, auth BasicAuth, tlsConf *tls.Config, logger *log.Logger) error {
	timestamp := uint64(time.Now().UnixMilli())
	content := &proto.Content{
		DataMessage: &proto.DataMessage{
			Body:      &text,
			Timestamp: &timestamp,
		},
	}
	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return fmt.Errorf("sender: marshal content: %w", err)
	}

	return sendEncryptedMessage(ctx, apiURL, recipient, contentBytes, st, auth, tlsConf, logger)
}

// envelopeTypeForCiphertext maps libsignal CiphertextMessage types to Signal
// server envelope types. These are different numbering schemes:
//
//	libsignal Whisper (2) → Envelope CIPHERTEXT (1)
//	libsignal PreKey  (3) → Envelope PREKEY_BUNDLE (3)
//	libsignal Plaintext (8) → Envelope PLAINTEXT_CONTENT (8)
func envelopeTypeForCiphertext(ciphertextType uint8) proto.Envelope_Type {
	switch ciphertextType {
	case libsignal.CiphertextMessageTypeWhisper:
		return proto.Envelope_CIPHERTEXT
	case libsignal.CiphertextMessageTypePreKey:
		return proto.Envelope_PREKEY_BUNDLE
	case libsignal.CiphertextMessageTypePlaintext:
		return proto.Envelope_PLAINTEXT_CONTENT
	case libsignal.CiphertextMessageTypeSenderKey:
		return proto.Envelope_SENDERKEY_MESSAGE
	default:
		return proto.Envelope_Type(ciphertextType)
	}
}

// buildPreKeyBundle constructs a libsignal PreKeyBundle from server response data.
func buildPreKeyBundle(identityKeyB64 string, dev PreKeyDeviceInfo) (*libsignal.PreKeyBundle, error) {
	identityKeyBytes, err := base64.RawStdEncoding.DecodeString(identityKeyB64)
	if err != nil {
		return nil, fmt.Errorf("decode identity key: %w", err)
	}
	identityKey, err := libsignal.DeserializePublicKey(identityKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize identity key: %w", err)
	}
	defer identityKey.Destroy()

	if dev.SignedPreKey == nil {
		return nil, fmt.Errorf("missing signed pre-key")
	}

	spkBytes, err := base64.RawStdEncoding.DecodeString(dev.SignedPreKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode signed pre-key: %w", err)
	}
	spk, err := libsignal.DeserializePublicKey(spkBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize signed pre-key: %w", err)
	}
	defer spk.Destroy()

	spkSig, err := base64.RawStdEncoding.DecodeString(dev.SignedPreKey.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signed pre-key signature: %w", err)
	}

	// One-time pre-key (optional). Only use if both key and ID are valid.
	// KeyID=0 means "no pre-key" even if the struct is present.
	var preKey *libsignal.PublicKey
	preKeyID := uint32(math.MaxUint32)
	if dev.PreKey != nil && dev.PreKey.KeyID > 0 && dev.PreKey.PublicKey != "" {
		pkBytes, err := base64.RawStdEncoding.DecodeString(dev.PreKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode pre-key: %w", err)
		}
		preKey, err = libsignal.DeserializePublicKey(pkBytes)
		if err != nil {
			return nil, fmt.Errorf("deserialize pre-key: %w", err)
		}
		defer preKey.Destroy()
		preKeyID = uint32(dev.PreKey.KeyID)
	}

	// Kyber pre-key (optional). Only use if both key and ID are valid.
	var kyberPub *libsignal.KyberPublicKey
	kyberPreKeyID := uint32(math.MaxUint32)
	var kyberSig []byte
	if dev.PqPreKey != nil && dev.PqPreKey.KeyID > 0 && dev.PqPreKey.PublicKey != "" {
		kpkBytes, err := base64.RawStdEncoding.DecodeString(dev.PqPreKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("decode kyber pre-key: %w", err)
		}
		kyberPub, err = libsignal.DeserializeKyberPublicKey(kpkBytes)
		if err != nil {
			return nil, fmt.Errorf("deserialize kyber pre-key: %w", err)
		}
		defer kyberPub.Destroy()
		kyberPreKeyID = uint32(dev.PqPreKey.KeyID)
		kyberSig, err = base64.RawStdEncoding.DecodeString(dev.PqPreKey.Signature)
		if err != nil {
			return nil, fmt.Errorf("decode kyber pre-key signature: %w", err)
		}
	}

	return libsignal.NewPreKeyBundle(
		uint32(dev.RegistrationID),
		uint32(dev.DeviceID),
		preKeyID, preKey,
		uint32(dev.SignedPreKey.KeyID), spk, spkSig,
		identityKey,
		kyberPreKeyID, kyberPub, kyberSig,
	)
}
