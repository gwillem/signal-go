package signalservice

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"iter"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/signalws"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// receiverContext groups the parameters needed by handleEnvelope.
type receiverContext struct {
	service     *Service
	localUUID   string
	localDevice uint32
}

// Message represents a received Signal message.
type Message struct {
	Sender       string    // sender ACI UUID
	SenderNumber string    // sender phone number (if known from contacts)
	SenderName   string    // sender display name (if known from contacts)
	Device       uint32    // sender device ID
	Timestamp    time.Time // sender timestamp
	Body         string    // text content
	SyncTo       string    // recipient ACI if this is a SyncMessage (sent by our other device)
	SyncToNumber string    // recipient phone number (if known from contacts)
}

// receiveMessages connects to the authenticated WebSocket and returns an iterator
// that yields received text messages. The iterator stops when the context is
// cancelled or when the caller breaks out of the range loop.
func (s *Service) receiveMessages(ctx context.Context) iter.Seq2[Message, error] {
	return func(yield func(Message, error) bool) {
		wsEndpoint := s.wsURL + "/v1/websocket/"
		headers := buildWebSocketHeaders(s.auth)
		logf(s.logger, "connecting to WebSocket url=%s user=%s", wsEndpoint, s.auth.Username)
		conn, err := signalws.DialPersistent(ctx, wsEndpoint, s.tlsConfig,
			signalws.WithHeaders(headers),
			signalws.WithKeepAliveCallback(func(rtt time.Duration) {
				logf(s.logger, "keep-alive OK rtt=%s", rtt)
			}),
		)
		if err != nil {
			yield(Message{}, fmt.Errorf("receiver: dial: %w", err))
			return
		}
		defer conn.Close()
		logf(s.logger, "connected, waiting for messages")

		for {
			wsMsg, err := conn.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					logf(s.logger, "context cancelled, stopping")
					return
				}
				logf(s.logger, "read error: %v", err)
				if !yield(Message{}, fmt.Errorf("receiver: read: %w", err)) {
					return
				}
				continue
			}

			logf(s.logger, "ws message type=%v", wsMsg.GetType())

			// Only process REQUEST messages.
			if wsMsg.GetType() != proto.WebSocketMessage_REQUEST {
				if wsMsg.GetType() == proto.WebSocketMessage_RESPONSE {
					resp := wsMsg.GetResponse()
					logf(s.logger, "ws response id=%d status=%d message=%s", resp.GetId(), resp.GetStatus(), resp.GetMessage())
				}
				continue
			}
			req := wsMsg.GetRequest()
			logf(s.logger, "ws request verb=%s path=%s id=%d bodyLen=%d", req.GetVerb(), req.GetPath(), req.GetId(), len(req.GetBody()))

			if req.GetVerb() != "PUT" || req.GetPath() != "/api/v1/message" {
				// ACK non-message requests.
				if req.GetId() != 0 {
					_ = conn.SendResponse(ctx, req.GetId(), 200, "OK")
				}
				continue
			}

			rc := &receiverContext{
				service:     s,
				localUUID:   s.localACI,
				localDevice: uint32(s.localDeviceID),
			}
			msg, err := handleEnvelope(ctx, req.GetBody(), rc)
			if err != nil {
				// ACK even on decrypt failure — server won't retry.
				_ = conn.SendResponse(ctx, req.GetId(), 200, "OK")
				if !yield(Message{}, fmt.Errorf("receiver: %w", err)) {
					return
				}
				continue
			}

			// ACK after successful decryption.
			_ = conn.SendResponse(ctx, req.GetId(), 200, "OK")

			if msg == nil {
				// Non-text message (typing indicator, receipt, etc.) — skip.
				continue
			}

			if !yield(*msg, nil) {
				return
			}
		}
	}
}

// handleEnvelope parses an Envelope protobuf and decrypts the content.
// Returns nil, nil for envelopes that don't contain a text message (e.g. delivery receipts).
func handleEnvelope(ctx context.Context, data []byte, rc *receiverContext) (*Message, error) {
	st := rc.service.store
	logger := rc.service.logger

	var env proto.Envelope
	if err := pb.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	dumpEnvelope(rc.service.debugDir, data, &env, logger)

	envType := env.GetType()
	logf(logger, "envelope type=%v sender=%s device=%d timestamp=%d contentLen=%d destination=%s",
		envType, env.GetSourceServiceId(), env.GetSourceDevice(), env.GetTimestamp(), len(env.GetContent()), env.GetDestinationServiceId())

	// Switch to PNI identity if message is addressed to our PNI.
	// iPhone sends messages to PNI when the contact was discovered via phone number lookup (CDSI).
	destServiceID := env.GetDestinationServiceId()
	if strings.HasPrefix(destServiceID, "PNI:") {
		logf(logger, "message addressed to PNI, switching to PNI identity for decryption")
		st.UsePNI(true)
		defer st.UsePNI(false)
	}

	// Only handle known envelope types.
	switch envType {
	case proto.Envelope_CIPHERTEXT, proto.Envelope_PREKEY_BUNDLE, proto.Envelope_UNIDENTIFIED_SENDER, proto.Envelope_PLAINTEXT_CONTENT:
		// Proceed below.
	default:
		logf(logger, "skipping unsupported envelope type=%v", envType)
		return nil, nil
	}

	content := env.GetContent()
	if len(content) == 0 {
		return nil, fmt.Errorf("empty envelope content")
	}

	senderACI := env.GetSourceServiceId()
	senderDevice := env.GetSourceDevice()

	// Handle PLAINTEXT_CONTENT (retry receipts).
	if envType == proto.Envelope_PLAINTEXT_CONTENT {
		return handlePlaintextContent(ctx, content, senderACI, senderDevice, rc)
	}

	var plaintext []byte

	switch envType {
	case proto.Envelope_UNIDENTIFIED_SENDER:
		logf(logger, "decrypting sealed sender message (version byte=0x%02x, len=%d)", content[0], len(content))

		// Log identity key fingerprint for debugging sealed sender decryption failures.
		if identityKey, err := st.GetIdentityKeyPair(); err == nil {
			if pub, err := identityKey.PublicKey(); err == nil {
				if data, err := pub.Serialize(); err == nil && len(data) >= 8 {
					logf(logger, "sealed sender: trying ACI identity key fingerprint=%x", data[:8])
				}
				pub.Destroy()
			}
			identityKey.Destroy()
		}

		// Step 1: Decrypt outer sealed sender layer → USMC (uses only identity key for ECDH).
		// The identity is already selected based on envelope destination (lines 148-155).
		usmc, err := libsignal.SealedSenderDecryptToUSMC(content, st)
		if err != nil {
			return nil, fmt.Errorf("sealed sender decrypt outer: %w", err)
		}
		defer usmc.Destroy()

		// Step 2: Validate sender certificate.
		cert, err := usmc.GetSenderCert()
		if err != nil {
			return nil, fmt.Errorf("sealed sender get cert: %w", err)
		}
		defer cert.Destroy()

		trustRoots, err := loadTrustRoots()
		if err != nil {
			return nil, fmt.Errorf("load trust roots: %w", err)
		}
		for _, root := range trustRoots {
			defer root.Destroy()
		}

		valid, err := cert.ValidateWithTrustRoots(trustRoots, env.GetServerTimestamp())
		if err != nil {
			return nil, fmt.Errorf("sealed sender validate cert: %w", err)
		}
		if !valid {
			return nil, fmt.Errorf("sealed sender: invalid sender certificate")
		}

		// Extract sender info from certificate.
		senderACI, err = cert.SenderUUID()
		if err != nil {
			return nil, fmt.Errorf("sealed sender sender UUID: %w", err)
		}
		senderDevice, err = cert.DeviceID()
		if err != nil {
			return nil, fmt.Errorf("sealed sender device ID: %w", err)
		}
		logf(logger, "sealed sender from=%s device=%d", senderACI, senderDevice)

		// Step 3: Decrypt inner message (supports Kyber/PQXDH via full store).
		msgType, err := usmc.MsgType()
		if err != nil {
			return nil, fmt.Errorf("sealed sender msg type: %w", err)
		}
		innerContent, err := usmc.Contents()
		if err != nil {
			return nil, fmt.Errorf("sealed sender contents: %w", err)
		}

		addr, err := libsignal.NewAddress(senderACI, senderDevice)
		if err != nil {
			return nil, fmt.Errorf("sealed sender address: %w", err)
		}
		defer addr.Destroy()

		switch msgType {
		case libsignal.CiphertextMessageTypePreKey:
			logf(logger, "sealed sender: decrypting inner pre-key message")
			preKeyMsg, err := libsignal.DeserializePreKeySignalMessage(innerContent)
			if err != nil {
				// Inner deserialize failed — sender is known, send retry receipt.
				sendRetryReceiptAsync(ctx, rc, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
				return nil, fmt.Errorf("sealed sender deserialize pre-key: %w", err)
			}
			defer preKeyMsg.Destroy()
			plaintext, err = libsignal.DecryptPreKeyMessage(preKeyMsg, addr, st, st, st, st, st)
			if err != nil {
				// Inner decrypt failed — sender is known, send retry receipt.
				sendRetryReceiptAsync(ctx, rc, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
				return nil, fmt.Errorf("sealed sender decrypt pre-key: %w", err)
			}

		case libsignal.CiphertextMessageTypeWhisper:
			logf(logger, "sealed sender: decrypting inner whisper message")
			sigMsg, err := libsignal.DeserializeSignalMessage(innerContent)
			if err != nil {
				sendRetryReceiptAsync(ctx, rc, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
				return nil, fmt.Errorf("sealed sender deserialize whisper: %w", err)
			}
			defer sigMsg.Destroy()
			plaintext, err = libsignal.DecryptMessage(sigMsg, addr, st, st)
			if err != nil {
				sendRetryReceiptAsync(ctx, rc, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
				return nil, fmt.Errorf("sealed sender decrypt whisper: %w", err)
			}

		default:
			return nil, fmt.Errorf("sealed sender: unsupported inner message type %d", msgType)
		}

	case proto.Envelope_PREKEY_BUNDLE, proto.Envelope_CIPHERTEXT:
		addr, err := libsignal.NewAddress(senderACI, senderDevice)
		if err != nil {
			return nil, fmt.Errorf("create address: %w", err)
		}
		defer addr.Destroy()

		switch envType {
		case proto.Envelope_PREKEY_BUNDLE:
			logf(logger, "decrypting pre-key message")
			preKeyMsg, err := libsignal.DeserializePreKeySignalMessage(content)
			if err != nil {
				return nil, fmt.Errorf("deserialize pre-key message: %w", err)
			}
			defer preKeyMsg.Destroy()

			// Log pre-key message details for debugging
			if signedPreKeyID, err := preKeyMsg.SignedPreKeyID(); err == nil {
				logf(logger, "pre-key message signed_pre_key_id=%d", signedPreKeyID)
			}
			if preKeyID, err := preKeyMsg.PreKeyID(); err == nil {
				logf(logger, "pre-key message pre_key_id=%d (0 means none)", preKeyID)
			}
			if version, err := preKeyMsg.Version(); err == nil {
				logf(logger, "pre-key message version=%d", version)
			}

			plaintext, err = libsignal.DecryptPreKeyMessage(preKeyMsg, addr, st, st, st, st, st)
			if err != nil {
				return nil, fmt.Errorf("decrypt pre-key message: %w", err)
			}

		case proto.Envelope_CIPHERTEXT:
			logf(logger, "decrypting ciphertext message")
			sigMsg, err := libsignal.DeserializeSignalMessage(content)
			if err != nil {
				return nil, fmt.Errorf("deserialize signal message: %w", err)
			}
			defer sigMsg.Destroy()

			plaintext, err = libsignal.DecryptMessage(sigMsg, addr, st, st)
			if err != nil {
				return nil, fmt.Errorf("decrypt message: %w", err)
			}
		}
	}

	// Strip Signal transport padding: content is followed by 0x80 then 0x00 bytes.
	plaintext = stripPadding(plaintext)

	// Dump received Content for debugging comparison with sent messages.
	dumpContent(rc.service.debugDir, "recv", senderACI, env.GetTimestamp(), plaintext, logger)

	// Parse decrypted Content protobuf.
	var contentProto proto.Content
	if err := pb.Unmarshal(plaintext, &contentProto); err != nil {
		return nil, fmt.Errorf("unmarshal content: %w", err)
	}

	// Log what's inside the Content.
	logf(logger, "content hasDataMessage=%v hasSyncMessage=%v hasTypingMessage=%v hasReceiptMessage=%v hasCallMessage=%v",
		contentProto.DataMessage != nil, contentProto.SyncMessage != nil,
		contentProto.TypingMessage != nil, contentProto.ReceiptMessage != nil,
		contentProto.CallMessage != nil)

	// Log DataMessage details for debugging.
	if dm := contentProto.GetDataMessage(); dm != nil {
		logf(logger, "RECV DataMessage: timestamp=%d bodyLen=%d hasProfileKey=%v hasGroupContext=%v hasQuote=%v hasExpireTimer=%v",
			dm.GetTimestamp(), len(dm.GetBody()), len(dm.ProfileKey) > 0,
			dm.GetGroupV2() != nil, dm.GetQuote() != nil, dm.ExpireTimer != nil)
	}

	// Extract text body from DataMessage (direct message).
	if dm := contentProto.GetDataMessage(); dm != nil && dm.Body != nil {
		// Store sender's profile key if provided (needed for sealed sender replies).
		if len(dm.ProfileKey) == 32 {
			if err := saveContactProfileKey(st, senderACI, dm.ProfileKey, logger); err != nil {
				logf(logger, "failed to save profile key: %v", err)
			}
		}

		msg := &Message{
			Sender:    senderACI,
			Device:    senderDevice,
			Timestamp: time.UnixMilli(int64(env.GetTimestamp())),
			Body:      dm.GetBody(),
		}
		populateContactInfo(msg, st)
		return msg, nil
	}

	// Handle SyncMessage subtypes.
	if sm := contentProto.GetSyncMessage(); sm != nil {
		// SyncMessage.Sent: message sent by our other device.
		if sent := sm.GetSent(); sent != nil {
			if dm := sent.GetMessage(); dm != nil && dm.Body != nil {
				recipient := sent.GetDestinationServiceId()
				msg := &Message{
					Sender:    senderACI,
					Device:    senderDevice,
					Timestamp: time.UnixMilli(int64(sent.GetTimestamp())),
					Body:      dm.GetBody(),
					SyncTo:    recipient,
				}
				populateContactInfo(msg, st)
				return msg, nil
			}
		}

		// SyncMessage.Contacts: contact sync from primary device.
		if contacts := sm.GetContacts(); contacts != nil {
			if err := handleContactSync(ctx, contacts, st, rc.service.tlsConfig, logger); err != nil {
				logf(logger, "contact sync error: %v", err)
			}
			return nil, nil
		}
	}

	logf(logger, "skipping non-text content")
	return nil, nil
}

// handlePlaintextContent processes a PLAINTEXT_CONTENT envelope, which contains
// a DecryptionErrorMessage (retry receipt) from a peer who couldn't decrypt our message.
func handlePlaintextContent(ctx context.Context, content []byte, senderACI string, senderDevice uint32, rc *receiverContext) (*Message, error) {
	logf(rc.service.logger, "handling PLAINTEXT_CONTENT from=%s device=%d", senderACI, senderDevice)

	// Deserialize PlaintextContent to extract the body.
	pc, err := libsignal.DeserializePlaintextContent(content)
	if err != nil {
		return nil, fmt.Errorf("plaintext content deserialize: %w", err)
	}
	defer pc.Destroy()

	body, err := pc.Body()
	if err != nil {
		return nil, fmt.Errorf("plaintext content body: %w", err)
	}

	// Extract DecryptionErrorMessage from the serialized Content body.
	dem, err := libsignal.ExtractDecryptionErrorFromContent(body)
	if err != nil {
		return nil, fmt.Errorf("extract decryption error: %w", err)
	}
	defer dem.Destroy()

	ts, _ := dem.Timestamp()
	devID, _ := dem.DeviceID()
	logf(rc.service.logger, "received retry receipt from=%s device=%d originalTimestamp=%d originalDevice=%d", senderACI, senderDevice, ts, devID)

	// Ignore old retry receipts (older than 1 minute) to break retry loops.
	ageMs := uint64(time.Now().UnixMilli()) - ts
	if ageMs > 60*1000 {
		logf(rc.service.logger, "ignoring old retry receipt (age=%dms)", ageMs)
		return nil, nil
	}

	// Handle the retry receipt: archive session and send null message.
	if err := rc.service.handleRetryReceipt(ctx, senderACI, senderDevice); err != nil {
		logf(rc.service.logger, "handle retry receipt error: %v", err)
	}

	return nil, nil // Retry receipts are not user-visible.
}

// sendRetryReceiptAsync sends a retry receipt to the sender in a fire-and-forget
// goroutine. Errors are logged but don't block message processing.
func sendRetryReceiptAsync(ctx context.Context, rc *receiverContext, senderACI string, senderDevice uint32, innerContent []byte, msgType uint8, timestamp uint64) {
	logf(rc.service.logger, "sending retry receipt to=%s device=%d timestamp=%d", senderACI, senderDevice, timestamp)
	go func() {
		if err := rc.service.sendRetryReceipt(ctx, senderACI, senderDevice, innerContent, msgType, timestamp); err != nil {
			logf(rc.service.logger, "retry receipt send error: %v", err)
		} else {
			logf(rc.service.logger, "retry receipt sent to=%s device=%d", senderACI, senderDevice)
		}
	}()
}

// handleContactSync downloads the contact attachment, parses the contact stream, and saves contacts.
func handleContactSync(ctx context.Context, contacts *proto.SyncMessage_Contacts, st *store.Store, tlsConf *tls.Config, logger *log.Logger) error {
	blob := contacts.GetBlob()
	if blob == nil {
		return fmt.Errorf("contact sync: no attachment blob")
	}

	logf(logger, "downloading contact sync attachment (cdnId=%d cdnKey=%s size=%d)",
		blob.GetCdnId(), blob.GetCdnKey(), blob.GetSize())

	data, err := DownloadAttachment(ctx, blob, tlsConf)
	if err != nil {
		return fmt.Errorf("contact sync: download: %w", err)
	}

	parsed, err := ParseContactStream(data)
	if err != nil {
		return fmt.Errorf("contact sync: parse: %w", err)
	}

	var storeContacts []*store.Contact
	for _, cd := range parsed {
		aci := cd.GetAci()
		if aci == "" {
			continue
		}
		storeContacts = append(storeContacts, &store.Contact{
			ACI:    aci,
			Number: cd.GetNumber(),
			Name:   cd.GetName(),
		})
	}

	if err := st.SaveContacts(storeContacts); err != nil {
		return fmt.Errorf("contact sync: save: %w", err)
	}

	logf(logger, "contact sync complete: saved %d contacts", len(storeContacts))
	return nil
}

// populateContactInfo fills SenderNumber/SenderName/SyncToNumber from the contact store.
func populateContactInfo(msg *Message, st *store.Store) {
	if c, _ := st.GetContactByACI(msg.Sender); c != nil {
		msg.SenderNumber = c.Number
		msg.SenderName = c.Name
	}
	if msg.SyncTo != "" {
		if c, _ := st.GetContactByACI(msg.SyncTo); c != nil {
			msg.SyncToNumber = c.Number
		}
	}
}

// saveContactProfileKey stores or updates a contact's profile key.
// This is needed for sealed sender - we derive the unidentified access key from it.
func saveContactProfileKey(st *store.Store, aci string, profileKey []byte, logger *log.Logger) error {
	// Get existing contact or create new one
	contact, err := st.GetContactByACI(aci)
	if err != nil {
		return err
	}
	if contact == nil {
		contact = &store.Contact{ACI: aci}
	}

	// Only update if we don't have a profile key or it changed
	if len(contact.ProfileKey) == 0 || !bytes.Equal(contact.ProfileKey, profileKey) {
		contact.ProfileKey = profileKey
		if err := st.SaveContact(contact); err != nil {
			return err
		}
		logf(logger, "saved profile key for %s", aci)
	}
	return nil
}

// logf logs a formatted message if the logger is non-nil.
func logf(logger *log.Logger, format string, args ...any) {
	if logger != nil {
		logger.Printf(format, args...)
	}
}

// stripPadding removes Signal transport padding from decrypted plaintext.
// The padding format is: [content] [0x80] [0x00...] padded to 80-byte blocks.
func stripPadding(data []byte) []byte {
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == 0x80 {
			return data[:i]
		}
		if data[i] != 0x00 {
			break
		}
	}
	return data // malformed padding, return as-is
}

// buildWebSocketHeaders constructs the HTTP headers for the authenticated WebSocket.
func buildWebSocketHeaders(auth BasicAuth) http.Header {
	h := http.Header{}
	h.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString(
		[]byte(auth.Username+":"+auth.Password)))
	h.Set("X-Signal-Agent", "signal-go")
	h.Set("X-Signal-Receive-Stories", "false")
	return h
}
