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
// If debugDir is non-empty, the Content protobuf is dumped before encryption.
func SendTextMessage(ctx context.Context, apiURL string, recipient string, text string, st *store.Store, auth BasicAuth, tlsConf *tls.Config, logger *log.Logger, debugDir string) error {
	timestamp := uint64(time.Now().UnixMilli())

	// Load account to get profile key and PNI for the message.
	acct, err := st.LoadAccount()
	if err != nil {
		return fmt.Errorf("sender: load account: %w", err)
	}

	// Include fields that iOS requires for proper message display.
	expireTimer := uint32(0)
	requiredProtocolVersion := uint32(0)
	expireTimerVersion := uint32(1)

	dm := &proto.DataMessage{
		Body:                    &text,
		Timestamp:               &timestamp,
		ExpireTimer:             &expireTimer,
		RequiredProtocolVersion: &requiredProtocolVersion,
		ExpireTimerVersion:      &expireTimerVersion,
	}

	// Include profile key if available (required for iOS compatibility).
	if acct != nil && len(acct.ProfileKey) > 0 {
		dm.ProfileKey = acct.ProfileKey
	}

	content := &proto.Content{
		DataMessage: dm,
	}

	// Include PNI signature to help recipients link our ACI and PNI identities.
	// This is required when the recipient discovered us via phone number (PNI).
	pniSig, err := createPniSignatureMessage(st, acct, logger)
	if err != nil {
		logf(logger, "sender: failed to create PNI signature (continuing without): %v", err)
	} else if pniSig != nil {
		content.PniSignatureMessage = pniSig
		logf(logger, "sender: including PNI signature in message")
	}

	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return fmt.Errorf("sender: marshal content: %w", err)
	}

	// Dump Content for debugging comparison with received messages.
	dumpContent(debugDir, "send", recipient, timestamp, contentBytes, logger)

	return sendEncryptedMessage(ctx, apiURL, recipient, contentBytes, st, auth, tlsConf, logger)
}

// createPniSignatureMessage creates a PniSignatureMessage that proves our ACI and PNI
// identities belong to the same account. The PNI identity key signs the ACI public key.
func createPniSignatureMessage(st *store.Store, acct *store.Account, logger *log.Logger) (*proto.PniSignatureMessage, error) {
	if acct == nil || acct.PNI == "" {
		return nil, nil // No PNI available
	}

	// Get ACI identity public key.
	aciPriv, err := st.GetIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("get ACI identity: %w", err)
	}
	aciPub, err := aciPriv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("derive ACI public key: %w", err)
	}
	defer aciPub.Destroy()

	// Switch to PNI identity.
	st.UsePNI(true)
	defer st.UsePNI(false)

	// Get PNI identity key pair.
	pniPriv, err := st.GetIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("get PNI identity: %w", err)
	}
	pniPub, err := pniPriv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("derive PNI public key: %w", err)
	}
	defer pniPub.Destroy()

	// Create IdentityKeyPair for signing.
	pniKeyPair := &libsignal.IdentityKeyPair{
		PublicKey:  pniPub,
		PrivateKey: pniPriv,
	}

	// Sign ACI public key with PNI identity.
	signature, err := pniKeyPair.SignAlternateIdentity(aciPub)
	if err != nil {
		return nil, fmt.Errorf("sign alternate identity: %w", err)
	}

	// Parse PNI UUID to bytes (16 bytes).
	pniBytes, err := uuidToBytes(acct.PNI)
	if err != nil {
		return nil, fmt.Errorf("parse PNI UUID: %w", err)
	}

	return &proto.PniSignatureMessage{
		Pni:       pniBytes,
		Signature: signature,
	}, nil
}

// uuidToBytes converts a UUID string (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) to 16 bytes.
func uuidToBytes(uuidStr string) ([]byte, error) {
	// Remove dashes and decode hex.
	hex := ""
	for _, c := range uuidStr {
		if c != '-' {
			hex += string(c)
		}
	}
	if len(hex) != 32 {
		return nil, fmt.Errorf("invalid UUID length: %d", len(hex))
	}
	result := make([]byte, 16)
	for i := 0; i < 16; i++ {
		var b byte
		_, err := fmt.Sscanf(hex[i*2:i*2+2], "%02x", &b)
		if err != nil {
			return nil, fmt.Errorf("invalid UUID hex at %d: %w", i, err)
		}
		result[i] = b
	}
	return result, nil
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

const paddingBlockSize = 80

// padMessage adds Signal transport padding to a message body.
// Format: [content] [0x80] [0x00...] padded to 80-byte blocks.
// This matches Signal-Android's PushTransportDetails.getPaddedMessageBody().
func padMessage(messageBody []byte) []byte {
	// Calculate padded length. The +1 -1 accounts for the cipher's own padding.
	paddedLen := getPaddedMessageLength(len(messageBody)+1) - 1
	padded := make([]byte, paddedLen)
	copy(padded, messageBody)
	padded[len(messageBody)] = 0x80
	return padded
}

func getPaddedMessageLength(messageLength int) int {
	messageLengthWithTerminator := messageLength + 1
	messagePartCount := messageLengthWithTerminator / paddingBlockSize
	if messageLengthWithTerminator%paddingBlockSize != 0 {
		messagePartCount++
	}
	return messagePartCount * paddingBlockSize
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
