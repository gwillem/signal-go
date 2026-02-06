package signalservice

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// sendRetryReceipt sends a DecryptionErrorMessage back to a sender whose
// message we could not decrypt. The message is wrapped as PlaintextContent
// and sent unencrypted (type=PLAINTEXT) so no session is required.
func (s *Service) sendRetryReceipt(ctx context.Context,
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

	return s.withDeviceRetry(senderACI, []int{int(senderDevice)}, 0, func(devices []int) error {
		return s.SendMessage(ctx, senderACI, msgList)
	})
}

// handleRetryReceipt processes an incoming retry receipt (DecryptionErrorMessage)
// from a peer who couldn't decrypt our message. It archives the broken session
// and sends a null message to establish a fresh session.
func (s *Service) handleRetryReceipt(ctx context.Context,
	requesterACI string, requesterDevice uint32,
) error {
	// Archive the broken session.
	if err := s.store.ArchiveSession(requesterACI, requesterDevice); err != nil {
		return fmt.Errorf("handle retry: archive session: %w", err)
	}

	// Send a null message to establish a fresh session. Start with device 1 and
	// the requesting device to avoid an extra 409 round trip discovering it.
	initialDevices := []int{1}
	if requesterDevice != 1 {
		initialDevices = append(initialDevices, int(requesterDevice))
	}
	return s.sendNullMessageWithDevices(ctx, requesterACI, initialDevices)
}

// sendNullMessage sends a NullMessage (with random padding) to the recipient.
// This forces pre-key bundle fetch and new session establishment if no session
// exists (e.g. after archival).
func (s *Service) sendNullMessage(ctx context.Context, recipient string) error {
	contentBytes, err := makeNullMessageContent()
	if err != nil {
		return err
	}
	return s.sendEncryptedMessage(ctx, recipient, contentBytes)
}

// sendNullMessageWithDevices sends a NullMessage starting with the given device list.
// Used for retry receipt handling where we know some devices upfront.
func (s *Service) sendNullMessageWithDevices(ctx context.Context, recipient string, initialDevices []int) error {
	contentBytes, err := makeNullMessageContent()
	if err != nil {
		return err
	}
	return s.sendEncryptedMessageWithDevices(ctx, recipient, initialDevices, contentBytes)
}

// makeNullMessageContent creates a serialized NullMessage with random padding.
func makeNullMessageContent() ([]byte, error) {
	padding := make([]byte, 140)
	if _, err := rand.Read(padding); err != nil {
		return nil, fmt.Errorf("null message: random padding: %w", err)
	}

	content := &proto.Content{
		NullMessage: &proto.NullMessage{
			Padding: padding,
		},
	}
	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return nil, fmt.Errorf("null message: marshal: %w", err)
	}
	return contentBytes, nil
}

// sendEncryptedMessage encrypts and sends arbitrary Content bytes to a recipient.
// It handles session establishment (fetching pre-keys if needed) and retries on:
//   - 410 (stale devices): deletes stale sessions and retries
//   - 409 (mismatched devices): adds missing devices and retries
//
// The local device ID is excluded from the device list when sending to self (sync messages).
func (s *Service) sendEncryptedMessage(ctx context.Context, recipient string, contentBytes []byte) error {
	sendingToSelf := recipient == s.localACI
	logf(s.logger, "send: localDeviceID=%d recipient=%s sendingToSelf=%v", s.localDeviceID, recipient, sendingToSelf)

	deviceIDs, skipDevice := s.initialDevices(recipient, sendingToSelf)
	if sendingToSelf && len(deviceIDs) == 0 {
		return fmt.Errorf("send: no other devices to send to (you only have device %d)", s.localDeviceID)
	}

	return s.withDeviceRetry(recipient, deviceIDs, skipDevice, func(devices []int) error {
		return s.encryptAndSend(ctx, recipient, contentBytes, devices)
	})
}

// sendEncryptedMessageWithTimestamp is like sendEncryptedMessage but uses an explicit timestamp.
// This is needed for sync messages where the envelope timestamp must match the DataMessage timestamp.
func (s *Service) sendEncryptedMessageWithTimestamp(ctx context.Context, recipient string, contentBytes []byte, timestamp uint64) error {
	sendingToSelf := recipient == s.localACI
	logf(s.logger, "send: localDeviceID=%d recipient=%s sendingToSelf=%v timestamp=%d", s.localDeviceID, recipient, sendingToSelf, timestamp)

	deviceIDs, skipDevice := s.initialDevices(recipient, sendingToSelf)
	if sendingToSelf && len(deviceIDs) == 0 {
		return fmt.Errorf("send: no other devices to send to (you only have device %d)", s.localDeviceID)
	}

	return s.withDeviceRetry(recipient, deviceIDs, skipDevice, func(devices []int) error {
		return s.encryptAndSendWithTimestamp(ctx, recipient, contentBytes, devices, timestamp)
	})
}

// sendEncryptedMessageWithDevices encrypts and sends Content bytes starting with the
// given initial device list. Like sendEncryptedMessage, it handles the 409/410 retry
// loop, but starts with a known device list to reduce round trips.
func (s *Service) sendEncryptedMessageWithDevices(ctx context.Context, recipient string, initialDevices []int, contentBytes []byte) error {
	sendingToSelf := recipient == s.localACI

	// Filter out own device if sending to self.
	deviceIDs := make([]int, 0, len(initialDevices))
	for _, d := range initialDevices {
		if !sendingToSelf || d != s.localDeviceID {
			deviceIDs = append(deviceIDs, d)
		}
	}
	if len(deviceIDs) == 0 {
		deviceIDs = []int{1}
	}

	skipDevice := 0
	if sendingToSelf {
		skipDevice = s.localDeviceID
	}

	logf(s.logger, "send: recipient=%s devices=%v", recipient, deviceIDs)

	return s.withDeviceRetry(recipient, deviceIDs, skipDevice, func(devices []int) error {
		return s.encryptAndSend(ctx, recipient, contentBytes, devices)
	})
}

// encryptAndSend performs a single encrypt-and-send attempt for the given device IDs.
func (s *Service) encryptAndSend(ctx context.Context, recipient string, contentBytes []byte, deviceIDs []int) error {
	return s.encryptAndSendWithTimestamp(ctx, recipient, contentBytes, deviceIDs, uint64(time.Now().UnixMilli()))
}

// encryptAndSendWithTimestamp performs a single encrypt-and-send attempt with an explicit timestamp.
// This is used for sync messages where the envelope timestamp must match the DataMessage timestamp.
func (s *Service) encryptAndSendWithTimestamp(ctx context.Context, recipient string, contentBytes []byte, deviceIDs []int, timestamp uint64) error {
	now := time.Now()

	// Add Signal transport padding before encryption.
	// Format: [content] [0x80] [0x00...] padded to 80-byte blocks.
	paddedContent := padMessage(contentBytes)

	var messages []OutgoingMessage

	var skippedDevices []int

	for _, deviceID := range deviceIDs {
		addr, err := libsignal.NewAddress(recipient, uint32(deviceID))
		if err != nil {
			return fmt.Errorf("send: create address for device %d: %w", deviceID, err)
		}

		session, err := s.store.LoadSession(addr)
		if err != nil {
			addr.Destroy()
			return fmt.Errorf("send: load session for device %d: %w", deviceID, err)
		}

		var registrationID int

		if session == nil {
			// No session exists, fetch pre-keys and establish one.
			preKeyResp, err := s.GetPreKeys(ctx, recipient, deviceID)
			if err != nil {
				addr.Destroy()
				// 404 means the device no longer exists — skip it and clean up.
				if strings.Contains(err.Error(), "status 404") {
					logf(s.logger, "send: device %d not found (404), removing", deviceID)
					_ = s.store.ArchiveSession(recipient, uint32(deviceID))
					skippedDevices = append(skippedDevices, deviceID)
					continue
				}
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

			if err := libsignal.ProcessPreKeyBundle(bundle, addr, s.store, s.store, now); err != nil {
				bundle.Destroy()
				addr.Destroy()
				return fmt.Errorf("send: process pre-key bundle for device %d: %w", deviceID, err)
			}
			bundle.Destroy()
		} else {
			// Session exists, get registration ID from the session record.
			regID, err := session.RemoteRegistrationID()
			session.Destroy()
			if err != nil {
				addr.Destroy()
				return fmt.Errorf("send: get registration id for device %d: %w", deviceID, err)
			}
			registrationID = int(regID)
		}

		ciphertext, err := libsignal.Encrypt(paddedContent, addr, s.store, s.store, now)
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

	// Remove any skipped (gone) devices from the stored device list.
	if len(skippedDevices) > 0 {
		remaining, _ := s.store.GetDevices(recipient)
		for _, skip := range skippedDevices {
			remaining = slices.DeleteFunc(remaining, func(id int) bool { return id == skip })
		}
		_ = s.store.SetDevices(recipient, remaining)
	}

	if len(messages) == 0 {
		return fmt.Errorf("send: no reachable devices for %s", recipient)
	}

	msgList := &OutgoingMessageList{
		Destination: recipient,
		Timestamp:   timestamp,
		Messages:    messages,
		Urgent:      true,
	}

	// Log outgoing message details for debugging.
	for _, m := range messages {
		logf(s.logger, "outgoing: device=%d type=%v regID=%d contentLen=%d paddedLen=%d",
			m.DestinationDeviceID, m.Type, m.DestinationRegistrationID, len(contentBytes), len(paddedContent))
	}

	return s.SendMessage(ctx, recipient, msgList)
}
