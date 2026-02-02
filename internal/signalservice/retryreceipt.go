package signalservice

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
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
	logger *log.Logger,
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

	httpClient := NewHTTPClient(apiURL, tlsConf, logger)
	return httpClient.SendMessage(ctx, senderACI, msgList, auth)
}

// HandleRetryReceipt processes an incoming retry receipt (DecryptionErrorMessage)
// from a peer who couldn't decrypt our message. It archives the broken session
// and sends a null message to establish a fresh session.
func HandleRetryReceipt(ctx context.Context, apiURL string, st *store.Store,
	auth BasicAuth, tlsConf *tls.Config,
	requesterACI string, requesterDevice uint32,
	logger *log.Logger,
) error {
	// Archive the broken session.
	if err := st.ArchiveSession(requesterACI, requesterDevice); err != nil {
		return fmt.Errorf("handle retry: archive session: %w", err)
	}

	// Send a null message to force new session establishment.
	return SendNullMessage(ctx, apiURL, requesterACI, st, auth, tlsConf, logger)
}

// SendNullMessage sends a NullMessage (with random padding) to the recipient.
// This forces pre-key bundle fetch and new session establishment if no session
// exists (e.g. after archival).
func SendNullMessage(ctx context.Context, apiURL string, recipient string,
	st *store.Store, auth BasicAuth, tlsConf *tls.Config, logger *log.Logger,
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

	return sendEncryptedMessage(ctx, apiURL, recipient, contentBytes, st, auth, tlsConf, logger)
}

// sendEncryptedMessage encrypts and sends arbitrary Content bytes to a recipient.
// It handles session establishment (fetching pre-keys if needed) and retries on:
//   - 410 (stale devices): deletes stale sessions and retries
//   - 409 (mismatched devices): adds missing devices and retries
//
// The local device ID is extracted from auth.Username ("{aci}.{deviceId}") and
// excluded from the device list when sending to self (sync messages).
func sendEncryptedMessage(ctx context.Context, apiURL string, recipient string,
	contentBytes []byte, st *store.Store, auth BasicAuth, tlsConf *tls.Config, logger *log.Logger,
) error {
	httpClient := NewHTTPClient(apiURL, tlsConf, logger)

	// Parse local device ID from auth username ("{aci}.{deviceId}").
	localDeviceID := 0
	if parts := strings.SplitN(auth.Username, ".", 2); len(parts) == 2 {
		fmt.Sscanf(parts[1], "%d", &localDeviceID)
	}
	logf(logger, "send: localDeviceID=%d recipient=%s", localDeviceID, recipient)

	// Start with device 1. The server will tell us about additional devices via 409.
	deviceIDs := []int{1}

	const maxAttempts = 5
	for attempt := range maxAttempts {
		logf(logger, "send: attempt %d/%d devices=%v", attempt+1, maxAttempts, deviceIDs)
		err := encryptAndSend(ctx, httpClient, recipient, contentBytes, deviceIDs, st, auth)
		if err == nil {
			return nil
		}
		if attempt == maxAttempts-1 {
			return err
		}

		var staleErr *StaleDevicesError
		var mismatchErr *MismatchedDevicesError

		switch {
		case errors.As(err, &staleErr):
			logf(logger, "send: 410 stale=%v devices=%v", staleErr.StaleDevices, deviceIDs)
			// 410: the server rejected the entire batch. Archive all
			// sessions so the retry re-establishes with fresh PreKey messages.
			for _, deviceID := range deviceIDs {
				_ = st.ArchiveSession(recipient, uint32(deviceID))
			}
			// Remove stale devices from the list — they may no longer
			// exist on the server. If the server still needs them, it
			// will re-add them via 409 on the next attempt.
			for _, deviceID := range staleErr.StaleDevices {
				deviceIDs = slices.DeleteFunc(deviceIDs, func(id int) bool { return id == deviceID })
			}
			// Always keep at least device 1 (primary).
			if len(deviceIDs) == 0 {
				deviceIDs = []int{1}
			}
		case errors.As(err, &mismatchErr):
			logf(logger, "send: 409 missing=%v extra=%v, archiving all sessions for devices=%v",
				mismatchErr.MissingDevices, mismatchErr.ExtraDevices, deviceIDs)
			// 409: the server rejected the entire batch. Archive all
			// sessions so the retry re-establishes with fresh PreKey messages.
			for _, deviceID := range deviceIDs {
				_ = st.ArchiveSession(recipient, uint32(deviceID))
			}
			// Adjust the device list per the server's response.
			for _, deviceID := range mismatchErr.MissingDevices {
				if deviceID != localDeviceID {
					deviceIDs = append(deviceIDs, deviceID)
				}
			}
			for _, deviceID := range mismatchErr.ExtraDevices {
				deviceIDs = slices.DeleteFunc(deviceIDs, func(id int) bool { return id == deviceID })
			}
		default:
			return err
		}
	}
	return nil
}

// encryptAndSend performs a single encrypt-and-send attempt for the given device IDs.
func encryptAndSend(ctx context.Context, httpClient *HTTPClient, recipient string,
	contentBytes []byte, deviceIDs []int, st *store.Store, auth BasicAuth,
) error {
	now := time.Now()
	timestamp := uint64(now.UnixMilli())

	var messages []OutgoingMessage

	for _, deviceID := range deviceIDs {
		addr, err := libsignal.NewAddress(recipient, uint32(deviceID))
		if err != nil {
			return fmt.Errorf("send: create address for device %d: %w", deviceID, err)
		}

		session, err := st.LoadSession(addr)
		if err != nil {
			addr.Destroy()
			return fmt.Errorf("send: load session for device %d: %w", deviceID, err)
		}

		var registrationID int

		if session == nil {
			preKeyResp, err := httpClient.GetPreKeys(ctx, recipient, deviceID, auth)
			if err != nil {
				addr.Destroy()
				return fmt.Errorf("send: get pre-keys for device %d: %w", deviceID, err)
			}
			if len(preKeyResp.Devices) == 0 {
				addr.Destroy()
				return fmt.Errorf("send: no devices in pre-key response for device %d", deviceID)
			}

			dev := preKeyResp.Devices[0]
			registrationID = dev.RegistrationID

			bundle, err := buildPreKeyBundle(preKeyResp.IdentityKey, dev)
			if err != nil {
				addr.Destroy()
				return fmt.Errorf("send: build pre-key bundle for device %d: %w", deviceID, err)
			}

			if err := libsignal.ProcessPreKeyBundle(bundle, addr, st, st, now); err != nil {
				bundle.Destroy()
				addr.Destroy()
				return fmt.Errorf("send: process pre-key bundle for device %d: %w", deviceID, err)
			}
			bundle.Destroy()
		} else {
			session.Destroy()
		}

		ciphertext, err := libsignal.Encrypt(contentBytes, addr, st, st, now)
		addr.Destroy()
		if err != nil {
			return fmt.Errorf("send: encrypt for device %d: %w", deviceID, err)
		}

		msgType, err := ciphertext.Type()
		if err != nil {
			ciphertext.Destroy()
			return fmt.Errorf("send: ciphertext type for device %d: %w", deviceID, err)
		}

		ctBytes, err := ciphertext.Serialize()
		ciphertext.Destroy()
		if err != nil {
			return fmt.Errorf("send: serialize ciphertext for device %d: %w", deviceID, err)
		}

		messages = append(messages, OutgoingMessage{
			Type:                      envelopeTypeForCiphertext(msgType),
			DestinationDeviceID:       deviceID,
			DestinationRegistrationID: registrationID,
			Content:                   base64.StdEncoding.EncodeToString(ctBytes),
		})
	}

	msgList := &OutgoingMessageList{
		Destination: recipient,
		Timestamp:   timestamp,
		Messages:    messages,
		Urgent:      true,
	}

	return httpClient.SendMessage(ctx, recipient, msgList, auth)
}
