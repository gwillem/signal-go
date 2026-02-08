package signalservice

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// Sender handles encrypting and delivering Signal messages. It operates
// against store interfaces and uses callbacks for HTTP operations.
type Sender struct {
	dataStore     senderDataStore
	cryptoStore   senderCryptoStore
	logger        *log.Logger
	debugDir      string
	localACI      string
	localDeviceID int

	// Callbacks for HTTP operations (provided by Service).
	getPreKeys           func(ctx context.Context, recipient string, deviceID int) (*PreKeyResponse, error)
	sendHTTPMessage      func(ctx context.Context, destination string, msg *outgoingMessageList) error
	sendSealedHTTPMsg    func(ctx context.Context, destination string, msg *outgoingMessageList, accessKey []byte) error
	getSenderCertificate func(ctx context.Context) ([]byte, error)
}

// buildDataMessageContent builds a Content protobuf containing a DataMessage with the given
// text, timestamp, profile key, and optionally a PNI signature. Returns the marshalled bytes.
func (snd *Sender) buildDataMessageContent(text string, timestamp uint64) ([]byte, error) {
	acct, err := snd.dataStore.LoadAccount()
	if err != nil {
		return nil, fmt.Errorf("sender: load account: %w", err)
	}

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

	if acct != nil && len(acct.ProfileKey) > 0 {
		dm.ProfileKey = acct.ProfileKey
	}

	content := &proto.Content{
		DataMessage: dm,
	}

	// Include PNI signature to help recipients link our ACI and PNI identities.
	pniSig, err := snd.createPniSignatureMessage(acct)
	if err != nil {
		logf(snd.logger, "sender: failed to create PNI signature (continuing without): %v", err)
	} else if pniSig != nil {
		content.PniSignatureMessage = pniSig
		logf(snd.logger, "sender: including PNI signature in message")
	}

	return pb.Marshal(content)
}

func (snd *Sender) sendTextMessage(ctx context.Context, recipient string, text string) error {
	timestamp := uint64(time.Now().UnixMilli())

	contentBytes, err := snd.buildDataMessageContent(text, timestamp)
	if err != nil {
		return err
	}

	dumpContent(snd.debugDir, "send", recipient, timestamp, contentBytes, snd.logger)

	return snd.sendEncryptedMessage(ctx, recipient, contentBytes)
}

// sendTextMessageWithIdentity sends a text message using the given identity store
// for encryption. Use this when a non-default identity (e.g. PNI) is needed.
func (snd *Sender) sendTextMessageWithIdentity(ctx context.Context, recipient, text string, identityStore libsignal.IdentityKeyStore) error {
	timestamp := uint64(time.Now().UnixMilli())

	contentBytes, err := snd.buildDataMessageContent(text, timestamp)
	if err != nil {
		return err
	}

	dumpContent(snd.debugDir, "send", recipient, timestamp, contentBytes, snd.logger)

	deviceIDs, skipDevice, err := snd.prepareSendDevices(recipient, nil)
	if err != nil {
		return err
	}
	return snd.withDeviceRetry(recipient, deviceIDs, skipDevice, func(devices []int) error {
		return snd.encryptAndSendWithIdentity(ctx, recipient, contentBytes, devices, timestamp, identityStore)
	})
}

// createPniSignatureMessage creates a PniSignatureMessage that proves our ACI and PNI
// identities belong to the same account. The PNI identity key signs the ACI public key.
func (snd *Sender) createPniSignatureMessage(acct *store.Account) (*proto.PniSignatureMessage, error) {
	if acct == nil || acct.PNI == "" {
		return nil, nil // No PNI available
	}

	// Get ACI identity public key.
	aciPriv, err := snd.cryptoStore.GetIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("get ACI identity: %w", err)
	}
	defer aciPriv.Destroy()
	aciPub, err := aciPriv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("derive ACI public key: %w", err)
	}
	defer aciPub.Destroy()

	// Get PNI identity key pair.
	pniPriv, err := snd.dataStore.GetPNIIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("get PNI identity: %w", err)
	}
	defer pniPriv.Destroy()
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
	pni, err := uuid.Parse(acct.PNI)
	if err != nil {
		return nil, fmt.Errorf("parse PNI UUID: %w", err)
	}

	return &proto.PniSignatureMessage{
		Pni:       pni[:],
		Signature: signature,
	}, nil
}

// sendSealedSenderMessage sends a text message using sealed sender (UNIDENTIFIED_SENDER).
// This hides the sender's identity from the server. Requires:
// - Recipient has a profile key stored (for deriving unidentified access key)
// - Recipient allows unidentified senders
func (snd *Sender) sendSealedSenderMessage(ctx context.Context, recipient string, text string) error {
	timestamp := uint64(time.Now().UnixMilli())

	contentBytes, err := snd.buildDataMessageContent(text, timestamp)
	if err != nil {
		return err
	}

	// Step 1: Get sender certificate from server
	senderCertBytes, err := snd.getSenderCertificate(ctx)
	if err != nil {
		return fmt.Errorf("sealed sender: get sender certificate: %w", err)
	}

	senderCert, err := libsignal.DeserializeSenderCertificate(senderCertBytes)
	if err != nil {
		return fmt.Errorf("sealed sender: deserialize sender certificate: %w", err)
	}
	defer senderCert.Destroy()

	logf(snd.logger, "sealed sender: got sender certificate")

	// Step 2: Get recipient's profile key to derive the access key
	// Step 3: Derive unidentified access key from recipient's profile key.
	accessKey, err := deriveAccessKeyForRecipient(snd.dataStore, recipient)
	if err != nil {
		return fmt.Errorf("sealed sender: %w", err)
	}

	logf(snd.logger, "sealed sender: derived access key from profile key")

	// Step 4: Encrypt and send using sealed sender
	return snd.sendSealedEncrypted(ctx, recipient, contentBytes, senderCert, accessKey)
}

// sendSealedEncrypted encrypts content with sealed sender and sends it.
// Handles 409 (device mismatch) and 410 (stale sessions) with retry.
func (snd *Sender) sendSealedEncrypted(ctx context.Context, recipient string,
	contentBytes []byte, senderCert *libsignal.SenderCertificate, accessKey []byte,
) error {
	paddedContent := padMessage(contentBytes)

	deviceIDs, _ := snd.initialDevices(recipient, false)

	return snd.withDeviceRetry(recipient, deviceIDs, 0, func(devices []int) error {
		return snd.trySendSealed(ctx, recipient, paddedContent, senderCert, accessKey, devices)
	})
}

// trySendSealed encrypts and sends sealed sender messages to the given devices.
func (snd *Sender) trySendSealed(ctx context.Context, recipient string,
	paddedContent []byte, senderCert *libsignal.SenderCertificate, accessKey []byte,
	deviceIDs []int,
) error {
	now := time.Now()
	timestamp := uint64(now.UnixMilli())

	var messages []outgoingMessage

	for _, deviceID := range deviceIDs {
		addr, err := libsignal.NewAddress(recipient, uint32(deviceID))
		if err != nil {
			return fmt.Errorf("sealed sender: create address: %w", err)
		}

		// Establish session if needed
		session, err := snd.cryptoStore.LoadSession(addr)
		if err != nil {
			addr.Destroy()
			return fmt.Errorf("sealed sender: load session: %w", err)
		}

		var registrationID int

		if session == nil {
			// Fetch pre-keys and establish session
			preKeyResp, err := snd.getPreKeys(ctx, recipient, deviceID)
			if err != nil {
				addr.Destroy()
				return fmt.Errorf("sealed sender: get pre-keys: %w", err)
			}
			if len(preKeyResp.Devices) == 0 {
				addr.Destroy()
				return fmt.Errorf("sealed sender: no devices in pre-key response")
			}

			dev := preKeyResp.Devices[0]
			registrationID = dev.RegistrationID

			bundle, err := buildPreKeyBundle(preKeyResp.IdentityKey, dev)
			if err != nil {
				addr.Destroy()
				return fmt.Errorf("sealed sender: build pre-key bundle: %w", err)
			}

			if err := libsignal.ProcessPreKeyBundle(bundle, addr, snd.cryptoStore, snd.cryptoStore, now); err != nil {
				bundle.Destroy()
				addr.Destroy()
				return fmt.Errorf("sealed sender: process pre-key bundle: %w", err)
			}
			bundle.Destroy()
		} else {
			regID, err := session.RemoteRegistrationID()
			session.Destroy()
			if err != nil {
				addr.Destroy()
				return fmt.Errorf("sealed sender: get registration id: %w", err)
			}
			registrationID = int(regID)
		}

		// Encrypt the inner message
		ciphertext, err := libsignal.Encrypt(paddedContent, addr, snd.cryptoStore, snd.cryptoStore, now)
		if err != nil {
			addr.Destroy()
			return fmt.Errorf("sealed sender: encrypt: %w", err)
		}

		// Capture ciphertext type before destroying (for diagnostics)
		innerType, _ := ciphertext.Type()

		// Create USMC wrapping the encrypted message with sender certificate
		usmc, err := libsignal.NewUnidentifiedSenderMessageContent(
			ciphertext,
			senderCert,
			libsignal.ContentHintResendable,
			nil, // no group ID for 1:1 messages
		)
		ciphertext.Destroy()
		if err != nil {
			addr.Destroy()
			return fmt.Errorf("sealed sender: create USMC: %w", err)
		}

		// Seal the message (encrypt outer layer with recipient's identity key)
		sealed, err := libsignal.SealedSenderEncrypt(addr, usmc, snd.cryptoStore)
		usmc.Destroy()
		addr.Destroy()
		if err != nil {
			return fmt.Errorf("sealed sender: seal: %w", err)
		}

		messages = append(messages, outgoingMessage{
			Type:                      proto.Envelope_UNIDENTIFIED_SENDER,
			DestinationDeviceID:       deviceID,
			DestinationRegistrationID: registrationID,
			Content:                   base64.StdEncoding.EncodeToString(sealed),
		})

		logf(snd.logger, "sealed sender: prepared message for device %d (inner type=%d, PreKey=%v)", deviceID, innerType, innerType == libsignal.CiphertextMessageTypePreKey)
	}

	// Send via sealed sender endpoint
	msgList := &outgoingMessageList{
		Destination: recipient,
		Timestamp:   timestamp,
		Messages:    messages,
		Urgent:      true,
	}

	logf(snd.logger, "sealed sender: sending to %s (%d devices)", recipient, len(messages))

	return snd.sendSealedHTTPMsg(ctx, recipient, msgList, accessKey)
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
