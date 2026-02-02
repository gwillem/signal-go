package signalservice

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// SendRetryReceipt sends a DecryptionErrorMessage back to a sender whose
// message we could not decrypt. The message is wrapped as PlaintextContent
// and sent unencrypted (type=PLAINTEXT) so no session is required.
func SendRetryReceipt(ctx context.Context, apiURL string, st *store.Store,
	auth BasicAuth, tlsConf *tls.Config,
	senderACI string, senderDevice uint32,
	originalContent []byte, originalType uint8, originalTimestamp uint64,
) error {
	dem, err := libsignal.NewDecryptionErrorMessage(originalContent, originalType, originalTimestamp, senderDevice)
	if err != nil {
		return fmt.Errorf("retry receipt: create DEM: %w", err)
	}
	defer dem.Destroy()

	pc, err := libsignal.NewPlaintextContentFromDecryptionError(dem)
	if err != nil {
		return fmt.Errorf("retry receipt: create PlaintextContent: %w", err)
	}
	defer pc.Destroy()

	serialized, err := pc.Serialize()
	if err != nil {
		return fmt.Errorf("retry receipt: serialize: %w", err)
	}

	timestamp := uint64(time.Now().UnixMilli())
	msgList := &OutgoingMessageList{
		Destination: senderACI,
		Timestamp:   timestamp,
		Messages: []OutgoingMessage{
			{
				Type:                proto.Envelope_PLAINTEXT_CONTENT,
				DestinationDeviceID: int(senderDevice),
				Content:             base64.StdEncoding.EncodeToString(serialized),
			},
		},
		Urgent: true,
	}

	httpClient := NewHTTPClient(apiURL, tlsConf)
	return httpClient.SendMessage(ctx, senderACI, msgList, auth)
}

// HandleRetryReceipt processes an incoming retry receipt (DecryptionErrorMessage)
// from a peer who couldn't decrypt our message. It archives the broken session
// and sends a null message to establish a fresh session.
func HandleRetryReceipt(ctx context.Context, apiURL string, st *store.Store,
	auth BasicAuth, tlsConf *tls.Config,
	requesterACI string, requesterDevice uint32,
) error {
	// Archive the broken session.
	if err := st.ArchiveSession(requesterACI, requesterDevice); err != nil {
		return fmt.Errorf("handle retry: archive session: %w", err)
	}

	// Send a null message to force new session establishment.
	return SendNullMessage(ctx, apiURL, requesterACI, st, auth, tlsConf)
}

// SendNullMessage sends a NullMessage (with random padding) to the recipient.
// This forces pre-key bundle fetch and new session establishment if no session
// exists (e.g. after archival).
func SendNullMessage(ctx context.Context, apiURL string, recipient string,
	st *store.Store, auth BasicAuth, tlsConf *tls.Config,
) error {
	padding := make([]byte, 140)
	if _, err := rand.Read(padding); err != nil {
		return fmt.Errorf("null message: random padding: %w", err)
	}

	content := &proto.Content{
		NullMessage: &proto.NullMessage{
			Padding: padding,
		},
	}
	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return fmt.Errorf("null message: marshal: %w", err)
	}

	return sendEncryptedMessage(ctx, apiURL, recipient, contentBytes, st, auth, tlsConf)
}

// sendEncryptedMessage encrypts and sends arbitrary Content bytes to a recipient.
// It handles session establishment (fetching pre-keys if needed).
func sendEncryptedMessage(ctx context.Context, apiURL string, recipient string,
	contentBytes []byte, st *store.Store, auth BasicAuth, tlsConf *tls.Config,
) error {
	now := time.Now()
	timestamp := uint64(now.UnixMilli())

	addr, err := libsignal.NewAddress(recipient, 1)
	if err != nil {
		return fmt.Errorf("send: create address: %w", err)
	}
	defer addr.Destroy()

	httpClient := NewHTTPClient(apiURL, tlsConf)

	session, err := st.LoadSession(addr)
	if err != nil {
		return fmt.Errorf("send: load session: %w", err)
	}

	var registrationID int

	if session == nil {
		preKeyResp, err := httpClient.GetPreKeys(ctx, recipient, 1, auth)
		if err != nil {
			return fmt.Errorf("send: get pre-keys: %w", err)
		}
		if len(preKeyResp.Devices) == 0 {
			return fmt.Errorf("send: no devices in pre-key response")
		}

		dev := preKeyResp.Devices[0]
		registrationID = dev.RegistrationID

		bundle, err := buildPreKeyBundle(preKeyResp.IdentityKey, dev)
		if err != nil {
			return fmt.Errorf("send: build pre-key bundle: %w", err)
		}
		defer bundle.Destroy()

		if err := libsignal.ProcessPreKeyBundle(bundle, addr, st, st, now); err != nil {
			return fmt.Errorf("send: process pre-key bundle: %w", err)
		}
	} else {
		session.Destroy()
	}

	ciphertext, err := libsignal.Encrypt(contentBytes, addr, st, st, now)
	if err != nil {
		return fmt.Errorf("send: encrypt: %w", err)
	}
	defer ciphertext.Destroy()

	msgType, err := ciphertext.Type()
	if err != nil {
		return fmt.Errorf("send: ciphertext type: %w", err)
	}

	ctBytes, err := ciphertext.Serialize()
	if err != nil {
		return fmt.Errorf("send: serialize ciphertext: %w", err)
	}

	msgList := &OutgoingMessageList{
		Destination: recipient,
		Timestamp:   timestamp,
		Messages: []OutgoingMessage{
			{
				Type:                      envelopeTypeForCiphertext(msgType),
				DestinationDeviceID:       1,
				DestinationRegistrationID: registrationID,
				Content:                   base64.StdEncoding.EncodeToString(ctBytes),
			},
		},
		Urgent: true,
	}

	return httpClient.SendMessage(ctx, recipient, msgList, auth)
}
