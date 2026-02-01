package signalservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// SendTextMessage sends a text message to a recipient. It handles session
// establishment (fetching pre-keys if needed), encryption, and HTTP delivery.
func SendTextMessage(ctx context.Context, apiURL string, recipient string, text string, st *store.Store, auth BasicAuth, tlsConf *tls.Config) error {
	now := time.Now()
	timestamp := uint64(now.UnixMilli())

	// Build Content protobuf.
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

	// Create address for device 1 (primary device).
	addr, err := libsignal.NewAddress(recipient, 1)
	if err != nil {
		return fmt.Errorf("sender: create address: %w", err)
	}
	defer addr.Destroy()

	httpClient := NewHTTPClient(apiURL, tlsConf)

	// Check if session exists.
	session, err := st.LoadSession(addr)
	if err != nil {
		return fmt.Errorf("sender: load session: %w", err)
	}

	var registrationID int

	if session == nil {
		// No session — fetch pre-keys and establish one.
		preKeyResp, err := httpClient.GetPreKeys(ctx, recipient, 1, auth)
		if err != nil {
			return fmt.Errorf("sender: get pre-keys: %w", err)
		}

		if len(preKeyResp.Devices) == 0 {
			return fmt.Errorf("sender: no devices in pre-key response")
		}

		dev := preKeyResp.Devices[0]
		registrationID = dev.RegistrationID

		bundle, err := buildPreKeyBundle(preKeyResp.IdentityKey, dev)
		if err != nil {
			return fmt.Errorf("sender: build pre-key bundle: %w", err)
		}
		defer bundle.Destroy()

		if err := libsignal.ProcessPreKeyBundle(bundle, addr, st, st, now); err != nil {
			return fmt.Errorf("sender: process pre-key bundle: %w", err)
		}
	} else {
		session.Destroy()
		// Use a cached registration ID — for an established session we use 0
		// and the server will route by session info.
		registrationID = 0
	}

	// Encrypt.
	ciphertext, err := libsignal.Encrypt(contentBytes, addr, st, st, now)
	if err != nil {
		return fmt.Errorf("sender: encrypt: %w", err)
	}
	defer ciphertext.Destroy()

	msgType, err := ciphertext.Type()
	if err != nil {
		return fmt.Errorf("sender: ciphertext type: %w", err)
	}

	ctBytes, err := ciphertext.Serialize()
	if err != nil {
		return fmt.Errorf("sender: serialize ciphertext: %w", err)
	}

	// Build outgoing message.
	msgList := &OutgoingMessageList{
		Destination: recipient,
		Timestamp:   timestamp,
		Messages: []OutgoingMessage{
			{
				Type:                      int(msgType),
				DestinationDeviceID:       1,
				DestinationRegistrationID: registrationID,
				Content:                   base64.StdEncoding.EncodeToString(ctBytes),
			},
		},
		Urgent: true,
	}

	return httpClient.SendMessage(ctx, recipient, msgList, auth)
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

	// One-time pre-key (optional).
	var preKey *libsignal.PublicKey
	var preKeyID uint32
	if dev.PreKey != nil {
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

	// Kyber pre-key (optional but expected).
	var kyberPub *libsignal.KyberPublicKey
	var kyberPreKeyID uint32
	var kyberSig []byte
	if dev.PqPreKey != nil {
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
