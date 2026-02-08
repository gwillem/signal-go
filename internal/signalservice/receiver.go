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
	"github.com/gwillem/signal-go/internal/signalcrypto"
	"github.com/gwillem/signal-go/internal/signalws"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// Receiver handles incoming Signal messages: decryption, routing, contact/group
// enrichment, and retry receipts. It is created by Service.ReceiveMessages and
// operates against interfaces to enable testing with mocks.
type Receiver struct {
	dataStore   receiverDataStore
	cryptoStore cryptoStore
	logger      *log.Logger
	debugDir    string
	localACI    string
	tlsConfig   *tls.Config

	// Callbacks for cross-boundary operations (provided by Service).
	sendRetryReceipt   func(ctx context.Context, senderACI string, senderDevice uint32, content []byte, msgType uint8, timestamp uint64) error
	handleRetryReceipt func(ctx context.Context, requesterACI string, requesterDevice uint32) error
	getProfile         func(ctx context.Context, aci string, profileKey []byte) (*profileResponse, error)
	fetchGroupDetails  func(ctx context.Context, group *store.Group) error
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
	SyncToName   string    // recipient display name (if known from contacts)
	GroupID      string    // group identifier (hex) if this is a group message
	GroupName    string    // group name (if known)
}

// ReceiveMessages connects to the authenticated WebSocket and returns an iterator
// that yields received text messages. The iterator stops when the context is
// cancelled or when the caller breaks out of the range loop.
func (s *Service) ReceiveMessages(ctx context.Context) iter.Seq2[Message, error] {
	return func(yield func(Message, error) bool) {
		if !s.receiving.CompareAndSwap(false, true) {
			yield(Message{}, fmt.Errorf("receiver: already running"))
			return
		}
		defer s.receiving.Store(false)

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

		r := &Receiver{
			dataStore:          s.store,
			cryptoStore:        s.store,
			logger:             s.logger,
			debugDir:           s.debugDir,
			localACI:           s.localACI,
			tlsConfig:          s.tlsConfig,
			sendRetryReceipt:   s.sendRetryReceipt,
			handleRetryReceipt: s.handleRetryReceipt,
			getProfile:         s.GetProfile,
			fetchGroupDetails:  s.FetchGroupDetails,
		}
		r.run(ctx, conn, yield)
	}
}

// run is the main message loop for the Receiver.
func (r *Receiver) run(ctx context.Context, conn wsConn, yield func(Message, error) bool) {
	for {
		wsMsg, err := conn.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				logf(r.logger, "context cancelled, stopping")
				return
			}
			logf(r.logger, "read error: %v", err)
			if !yield(Message{}, fmt.Errorf("receiver: read: %w", err)) {
				return
			}
			continue
		}

		logf(r.logger, "ws message type=%v", wsMsg.GetType())

		// Only process REQUEST messages.
		if wsMsg.GetType() != proto.WebSocketMessage_REQUEST {
			if wsMsg.GetType() == proto.WebSocketMessage_RESPONSE {
				resp := wsMsg.GetResponse()
				logf(r.logger, "ws response id=%d status=%d message=%s", resp.GetId(), resp.GetStatus(), resp.GetMessage())
			}
			continue
		}
		req := wsMsg.GetRequest()
		logf(r.logger, "ws request verb=%s path=%s id=%d bodyLen=%d", req.GetVerb(), req.GetPath(), req.GetId(), len(req.GetBody()))

		if req.GetVerb() != "PUT" || req.GetPath() != "/api/v1/message" {
			// ACK non-message requests.
			if req.GetId() != 0 {
				_ = conn.SendResponse(ctx, req.GetId(), 200, "OK")
			}
			continue
		}

		msg, err := r.handleEnvelope(ctx, req.GetBody())
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

// handleEnvelope parses an Envelope protobuf and decrypts the content.
// Returns nil, nil for envelopes that don't contain a text message (e.g. delivery receipts).
func (r *Receiver) handleEnvelope(ctx context.Context, data []byte) (*Message, error) {
	var env proto.Envelope
	if err := pb.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	dumpEnvelope(r.debugDir, data, &env, r.logger)

	envType := env.GetType()
	logf(r.logger, "envelope type=%v sender=%s device=%d timestamp=%d contentLen=%d destination=%s",
		envType, env.GetSourceServiceId(), env.GetSourceDevice(), env.GetTimestamp(), len(env.GetContent()), env.GetDestinationServiceId())

	// Use PNI identity if message is addressed to our PNI.
	// iPhone sends messages to PNI when the contact was discovered via phone number lookup (CDSI).
	var identityStore libsignal.IdentityKeyStore = r.cryptoStore
	destServiceID := env.GetDestinationServiceId()
	if strings.HasPrefix(destServiceID, "PNI:") {
		logf(r.logger, "message addressed to PNI, using PNI identity for decryption")
		identityStore = r.dataStore.PNI()
	}

	// Only handle known envelope types.
	switch envType {
	case proto.Envelope_CIPHERTEXT, proto.Envelope_PREKEY_BUNDLE, proto.Envelope_UNIDENTIFIED_SENDER, proto.Envelope_PLAINTEXT_CONTENT:
		// Proceed below.
	default:
		logf(r.logger, "skipping unsupported envelope type=%v", envType)
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
		return r.handlePlaintextContent(ctx, content, senderACI, senderDevice)
	}

	var plaintext []byte

	switch envType {
	case proto.Envelope_UNIDENTIFIED_SENDER:
		pt, aci, dev, msg, err := r.decryptSealedSender(ctx, content, &env, identityStore)
		if err != nil {
			return nil, err
		}
		if msg != nil {
			return msg, nil // plaintext content handled inline
		}
		plaintext, senderACI, senderDevice = pt, aci, dev

	case proto.Envelope_PREKEY_BUNDLE, proto.Envelope_CIPHERTEXT:
		pt, err := r.decryptCiphertextOrPreKey(envType, content, senderACI, senderDevice, identityStore)
		if err != nil {
			return nil, err
		}
		plaintext = pt
	}

	// Strip Signal transport padding: content is followed by 0x80 then 0x00 bytes.
	plaintext = stripPadding(plaintext)

	// Dump received Content for debugging comparison with sent messages.
	dumpContent(r.debugDir, "recv", senderACI, env.GetTimestamp(), plaintext, r.logger)

	// Parse decrypted Content protobuf.
	var contentProto proto.Content
	if err := pb.Unmarshal(plaintext, &contentProto); err != nil {
		return nil, fmt.Errorf("unmarshal content: %w", err)
	}

	// Log what's inside the Content.
	logf(r.logger, "content hasDataMessage=%v hasSyncMessage=%v hasTypingMessage=%v hasReceiptMessage=%v hasCallMessage=%v hasSKDM=%v hasDecryptionError=%v",
		contentProto.DataMessage != nil, contentProto.SyncMessage != nil,
		contentProto.TypingMessage != nil, contentProto.ReceiptMessage != nil,
		contentProto.CallMessage != nil, len(contentProto.SenderKeyDistributionMessage) > 0,
		len(contentProto.DecryptionErrorMessage) > 0)

	// Log DecryptionErrorMessage details (retry request from recipient who couldn't decrypt our message).
	if dem := contentProto.GetDecryptionErrorMessage(); len(dem) > 0 {
		var errMsg proto.DecryptionErrorMessage
		if err := pb.Unmarshal(dem, &errMsg); err != nil {
			logf(r.logger, "failed to unmarshal DecryptionErrorMessage: %v", err)
		} else {
			logf(r.logger, "RETRY REQUEST: timestamp=%d deviceId=%d ratchetKeyLen=%d",
				errMsg.GetTimestamp(), errMsg.GetDeviceId(), len(errMsg.GetRatchetKey()))
		}
	}

	// Process sender key distribution message if present.
	// This must happen before we try to decrypt any sender key messages from this sender.
	if skdm := contentProto.GetSenderKeyDistributionMessage(); len(skdm) > 0 {
		if err := r.processSenderKeyDistribution(senderACI, senderDevice, skdm); err != nil {
			// Log but don't fail - the sender can resend the distribution message
			logf(r.logger, "failed to process sender key distribution: %v", err)
		}
	}

	// Log DataMessage details for debugging.
	if dm := contentProto.GetDataMessage(); dm != nil {
		bodyPreview := dm.GetBody()
		if len(bodyPreview) > 30 {
			bodyPreview = bodyPreview[:30] + "..."
		}
		logf(r.logger, "RECV DataMessage: timestamp=%d body=%q hasProfileKey=%v hasGroupContext=%v hasQuote=%v hasExpireTimer=%v",
			dm.GetTimestamp(), bodyPreview, len(dm.ProfileKey) > 0,
			dm.GetGroupV2() != nil, dm.GetQuote() != nil, dm.ExpireTimer != nil)
	}

	// Extract text body from DataMessage (direct or group message).
	if dm := contentProto.GetDataMessage(); dm != nil && dm.Body != nil {
		// Store sender's profile key if provided (needed for sealed sender replies).
		if len(dm.ProfileKey) == 32 {
			if err := r.saveContactProfileKey(senderACI, dm.ProfileKey); err != nil {
				logf(r.logger, "failed to save profile key: %v", err)
			}
		}

		msg := &Message{
			Sender:    senderACI,
			Device:    senderDevice,
			Timestamp: time.UnixMilli(int64(env.GetTimestamp())),
			Body:      dm.GetBody(),
		}

		// Handle group context if present
		if gv2 := dm.GetGroupV2(); gv2 != nil && len(gv2.GetMasterKey()) == 32 {
			r.populateGroupInfo(msg, gv2.GetMasterKey(), int(gv2.GetRevision()))
		}

		r.populateContactInfo(ctx, msg)
		return msg, nil
	}

	// Handle SyncMessage subtypes.
	if sm := contentProto.GetSyncMessage(); sm != nil {
		logf(r.logger, "SyncMessage: sent=%v contacts=%v request=%v read=%v keys=%v",
			sm.Sent != nil, sm.Contacts != nil, sm.Request != nil, sm.Read != nil, sm.Keys != nil)

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

				// Handle group context if present
				if gv2 := dm.GetGroupV2(); gv2 != nil && len(gv2.GetMasterKey()) == 32 {
					r.populateGroupInfo(msg, gv2.GetMasterKey(), int(gv2.GetRevision()))
				}

				r.populateContactInfo(ctx, msg)
				return msg, nil
			}
		}

		// SyncMessage.Contacts: contact sync from primary device.
		if contacts := sm.GetContacts(); contacts != nil {
			if err := r.handleContactSync(ctx, contacts); err != nil {
				logf(r.logger, "contact sync error: %v", err)
			}
			return nil, nil
		}
	}

	// Handle DecryptionErrorMessage (retry receipt) inside Content proto.
	// Signal-Android sends retry receipts this way (encrypted, inside Content).
	if demBytes := contentProto.GetDecryptionErrorMessage(); len(demBytes) > 0 {
		logf(r.logger, "received DecryptionErrorMessage in Content from=%s device=%d", senderACI, senderDevice)
		return r.handleDecryptionErrorBytes(ctx, demBytes, senderACI, senderDevice)
	}

	logf(r.logger, "skipping non-text content")
	return nil, nil
}

// decryptSealedSender decrypts a sealed sender (UNIDENTIFIED_SENDER) envelope.
// Returns decrypted plaintext, sender ACI, sender device, and optionally a Message
// if the inner content was plaintext (retry receipt) handled inline.
func (r *Receiver) decryptSealedSender(ctx context.Context, content []byte, env *proto.Envelope, identityStore libsignal.IdentityKeyStore) ([]byte, string, uint32, *Message, error) {
	logf(r.logger, "decrypting sealed sender message (version byte=0x%02x, len=%d)", content[0], len(content))

	// Log identity key fingerprint for debugging sealed sender decryption failures.
	if identityKey, err := identityStore.GetIdentityKeyPair(); err == nil {
		if pub, err := identityKey.PublicKey(); err == nil {
			if data, err := pub.Serialize(); err == nil && len(data) >= 8 {
				logf(r.logger, "sealed sender: trying identity key fingerprint=%x", data[:8])
			}
			pub.Destroy()
		}
		identityKey.Destroy()
	}

	// Step 1: Decrypt outer sealed sender layer → USMC (uses only identity key for ECDH).
	usmc, err := libsignal.SealedSenderDecryptToUSMC(content, identityStore)
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("sealed sender decrypt outer: %w", err)
	}
	defer usmc.Destroy()

	// Step 2: Validate sender certificate.
	cert, err := usmc.GetSenderCert()
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("sealed sender get cert: %w", err)
	}
	defer cert.Destroy()

	trustRoots, err := loadTrustRoots()
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("load trust roots: %w", err)
	}
	for _, root := range trustRoots {
		defer root.Destroy()
	}

	valid, err := cert.ValidateWithTrustRoots(trustRoots, env.GetServerTimestamp())
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("sealed sender validate cert: %w", err)
	}
	if !valid {
		return nil, "", 0, nil, fmt.Errorf("sealed sender: invalid sender certificate")
	}

	// Extract sender info from certificate.
	senderACI, err := cert.SenderUUID()
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("sealed sender sender UUID: %w", err)
	}
	senderDevice, err := cert.DeviceID()
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("sealed sender device ID: %w", err)
	}
	logf(r.logger, "sealed sender from=%s device=%d", senderACI, senderDevice)

	// Step 3: Decrypt inner message (supports Kyber/PQXDH via full store).
	msgType, err := usmc.MsgType()
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("sealed sender msg type: %w", err)
	}
	innerContent, err := usmc.Contents()
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("sealed sender contents: %w", err)
	}

	addr, err := libsignal.NewAddress(senderACI, senderDevice)
	if err != nil {
		return nil, "", 0, nil, fmt.Errorf("sealed sender address: %w", err)
	}
	defer addr.Destroy()

	st := r.cryptoStore
	var plaintext []byte
	switch msgType {
	case libsignal.CiphertextMessageTypePreKey:
		logf(r.logger, "sealed sender: decrypting inner pre-key message")
		preKeyMsg, err := libsignal.DeserializePreKeySignalMessage(innerContent)
		if err != nil {
			r.sendRetryReceiptAsync(ctx, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
			return nil, "", 0, nil, fmt.Errorf("sealed sender deserialize pre-key: %w", err)
		}
		defer preKeyMsg.Destroy()
		plaintext, err = libsignal.DecryptPreKeyMessage(preKeyMsg, addr, st, identityStore, st, st, st)
		if err != nil {
			r.sendRetryReceiptAsync(ctx, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
			return nil, "", 0, nil, fmt.Errorf("sealed sender decrypt pre-key: %w", err)
		}

	case libsignal.CiphertextMessageTypeWhisper:
		logf(r.logger, "sealed sender: decrypting inner whisper message")
		sigMsg, err := libsignal.DeserializeSignalMessage(innerContent)
		if err != nil {
			r.sendRetryReceiptAsync(ctx, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
			return nil, "", 0, nil, fmt.Errorf("sealed sender deserialize whisper: %w", err)
		}
		defer sigMsg.Destroy()
		plaintext, err = libsignal.DecryptMessage(sigMsg, addr, st, identityStore)
		if err != nil {
			r.sendRetryReceiptAsync(ctx, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
			return nil, "", 0, nil, fmt.Errorf("sealed sender decrypt whisper: %w", err)
		}

	case libsignal.CiphertextMessageTypeSenderKey:
		logf(r.logger, "sealed sender: decrypting inner sender key message")
		plaintext, err = libsignal.GroupDecryptMessage(innerContent, addr, st)
		if err != nil {
			r.sendRetryReceiptAsync(ctx, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
			return nil, "", 0, nil, fmt.Errorf("sealed sender decrypt sender key: %w", err)
		}

	case libsignal.CiphertextMessageTypePlaintext:
		logf(r.logger, "sealed sender: processing plaintext message (retry receipt)")
		msg, err := r.handlePlaintextContent(ctx, innerContent, senderACI, senderDevice)
		return nil, "", 0, msg, err

	default:
		return nil, "", 0, nil, fmt.Errorf("sealed sender: unsupported inner message type %d", msgType)
	}

	return plaintext, senderACI, senderDevice, nil, nil
}

// decryptCiphertextOrPreKey decrypts a PREKEY_BUNDLE or CIPHERTEXT envelope.
func (r *Receiver) decryptCiphertextOrPreKey(envType proto.Envelope_Type, content []byte, senderACI string, senderDevice uint32, identityStore libsignal.IdentityKeyStore) ([]byte, error) {
	addr, err := libsignal.NewAddress(senderACI, senderDevice)
	if err != nil {
		return nil, fmt.Errorf("create address: %w", err)
	}
	defer addr.Destroy()

	st := r.cryptoStore

	switch envType {
	case proto.Envelope_PREKEY_BUNDLE:
		logf(r.logger, "decrypting pre-key message")
		preKeyMsg, err := libsignal.DeserializePreKeySignalMessage(content)
		if err != nil {
			return nil, fmt.Errorf("deserialize pre-key message: %w", err)
		}
		defer preKeyMsg.Destroy()

		if signedPreKeyID, err := preKeyMsg.SignedPreKeyID(); err == nil {
			logf(r.logger, "pre-key message signed_pre_key_id=%d", signedPreKeyID)
		}
		if preKeyID, err := preKeyMsg.PreKeyID(); err == nil {
			logf(r.logger, "pre-key message pre_key_id=%d (0 means none)", preKeyID)
		}
		if version, err := preKeyMsg.Version(); err == nil {
			logf(r.logger, "pre-key message version=%d", version)
		}

		return libsignal.DecryptPreKeyMessage(preKeyMsg, addr, st, identityStore, st, st, st)

	case proto.Envelope_CIPHERTEXT:
		logf(r.logger, "decrypting ciphertext message")
		sigMsg, err := libsignal.DeserializeSignalMessage(content)
		if err != nil {
			return nil, fmt.Errorf("deserialize signal message: %w", err)
		}
		defer sigMsg.Destroy()

		return libsignal.DecryptMessage(sigMsg, addr, st, identityStore)

	default:
		return nil, fmt.Errorf("unexpected envelope type: %v", envType)
	}
}

// handlePlaintextContent processes a PLAINTEXT_CONTENT envelope, which contains
// a DecryptionErrorMessage (retry receipt) from a peer who couldn't decrypt our message.
func (r *Receiver) handlePlaintextContent(ctx context.Context, content []byte, senderACI string, senderDevice uint32) (*Message, error) {
	logf(r.logger, "handling PLAINTEXT_CONTENT from=%s device=%d", senderACI, senderDevice)

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

	return r.processRetryReceipt(ctx, dem, senderACI, senderDevice)
}

// handleDecryptionErrorBytes processes a serialized DecryptionErrorMessage
// received inside a Content proto (field 8).
func (r *Receiver) handleDecryptionErrorBytes(ctx context.Context, demBytes []byte, senderACI string, senderDevice uint32) (*Message, error) {
	dem, err := libsignal.DeserializeDecryptionErrorMessage(demBytes)
	if err != nil {
		return nil, fmt.Errorf("deserialize DEM: %w", err)
	}
	defer dem.Destroy()

	return r.processRetryReceipt(ctx, dem, senderACI, senderDevice)
}

// processRetryReceipt handles a DecryptionErrorMessage: logs it, checks age,
// and archives session + sends null message if fresh enough.
func (r *Receiver) processRetryReceipt(ctx context.Context, dem *libsignal.DecryptionErrorMessage, senderACI string, senderDevice uint32) (*Message, error) {
	ts, _ := dem.Timestamp()
	devID, _ := dem.DeviceID()
	logf(r.logger, "received retry receipt from=%s device=%d originalTimestamp=%d originalDevice=%d", senderACI, senderDevice, ts, devID)

	// Ignore old retry receipts (older than 1 minute) to break retry loops.
	ageMs := uint64(time.Now().UnixMilli()) - ts
	if ageMs > 60*1000 {
		logf(r.logger, "ignoring old retry receipt (age=%dms)", ageMs)
		return nil, nil
	}

	if err := r.handleRetryReceipt(ctx, senderACI, senderDevice); err != nil {
		logf(r.logger, "handle retry receipt error: %v", err)
	}

	return nil, nil
}

// sendRetryReceiptAsync sends a retry receipt to the sender in a fire-and-forget
// goroutine. Errors are logged but don't block message processing.
func (r *Receiver) sendRetryReceiptAsync(ctx context.Context, senderACI string, senderDevice uint32, innerContent []byte, msgType uint8, timestamp uint64) {
	logf(r.logger, "sending retry receipt to=%s device=%d timestamp=%d", senderACI, senderDevice, timestamp)
	go func() {
		if err := r.sendRetryReceipt(ctx, senderACI, senderDevice, innerContent, msgType, timestamp); err != nil {
			logf(r.logger, "retry receipt send error: %v", err)
		} else {
			logf(r.logger, "retry receipt sent to=%s device=%d", senderACI, senderDevice)
		}
	}()
}

// handleContactSync downloads the contact attachment, parses the contact stream, and saves contacts.
func (r *Receiver) handleContactSync(ctx context.Context, contacts *proto.SyncMessage_Contacts) error {
	blob := contacts.GetBlob()
	if blob == nil {
		return fmt.Errorf("contact sync: no attachment blob")
	}

	logf(r.logger, "downloading contact sync attachment (cdnId=%d cdnKey=%s cdnNumber=%d size=%d)",
		blob.GetCdnId(), blob.GetCdnKey(), blob.GetCdnNumber(), blob.GetSize())

	data, err := downloadAttachment(ctx, blob, r.tlsConfig)
	if err != nil {
		return fmt.Errorf("contact sync: download: %w", err)
	}

	parsed, err := parseContactStream(data)
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

	if err := r.dataStore.SaveContacts(storeContacts); err != nil {
		return fmt.Errorf("contact sync: save: %w", err)
	}

	logf(r.logger, "contact sync complete: saved %d contacts", len(storeContacts))
	return nil
}

// populateContactInfo fills SenderNumber/SenderName/SyncToNumber/SyncToName from the contact store.
// If a contact has a profile key but no cached name, it fetches the profile from the server.
// For the local account (sync messages from own devices), falls back to the account table.
func (r *Receiver) populateContactInfo(ctx context.Context, msg *Message) {
	if c, _ := r.dataStore.GetContactByACI(msg.Sender); c != nil {
		msg.SenderNumber = c.Number
		msg.SenderName = c.Name
		// If we have profile key but no name, try fetching from server
		if msg.SenderName == "" && len(c.ProfileKey) == 32 {
			name := r.fetchAndCacheProfileName(ctx, msg.Sender, c.ProfileKey)
			if name != "" {
				msg.SenderName = name
			}
		}
	}
	// Fallback for local account: use account table for number and profile key.
	// Handles both cases: contact not found, or contact found without name/profile key.
	if msg.Sender == r.localACI && (msg.SenderNumber == "" || msg.SenderName == "") {
		if acct, _ := r.dataStore.LoadAccount(); acct != nil {
			if msg.SenderNumber == "" {
				msg.SenderNumber = acct.Number
			}
			if msg.SenderName == "" && len(acct.ProfileKey) == 32 {
				msg.SenderName = r.fetchAndCacheProfileName(ctx, msg.Sender, acct.ProfileKey)
			}
		}
	}
	if msg.SyncTo != "" {
		if c, _ := r.dataStore.GetContactByACI(msg.SyncTo); c != nil {
			msg.SyncToNumber = c.Number
			msg.SyncToName = c.Name
			// If we have profile key but no name, try fetching from server
			if msg.SyncToName == "" && len(c.ProfileKey) == 32 {
				name := r.fetchAndCacheProfileName(ctx, msg.SyncTo, c.ProfileKey)
				if name != "" {
					msg.SyncToName = name
				}
			}
		}
	}
}

// fetchAndCacheProfileName fetches a user's profile from the server, decrypts the name,
// and caches it in the contact store. Returns the name or empty string on failure.
func (r *Receiver) fetchAndCacheProfileName(ctx context.Context, aci string, profileKey []byte) string {
	logf(r.logger, "fetching profile for %s", aci)

	// Fetch profile from server
	profile, err := r.getProfile(ctx, aci, profileKey)
	if err != nil {
		logf(r.logger, "failed to fetch profile for %s: %v", aci, err)
		return ""
	}

	// Decrypt name
	if profile.Name == "" {
		logf(r.logger, "profile for %s has no name field", aci)
		return ""
	}

	cipher, err := signalcrypto.NewProfileCipher(profileKey)
	if err != nil {
		logf(r.logger, "failed to create profile cipher: %v", err)
		return ""
	}

	nameBytes, err := base64.StdEncoding.DecodeString(profile.Name)
	if err != nil {
		logf(r.logger, "failed to decode profile name: %v", err)
		return ""
	}

	name, err := cipher.DecryptString(nameBytes)
	if err != nil {
		logf(r.logger, "failed to decrypt profile name: %v", err)
		return ""
	}

	if name == "" {
		return ""
	}

	logf(r.logger, "fetched profile name for %s: %q", aci, name)

	// Cache the name in contact store
	contact, _ := r.dataStore.GetContactByACI(aci)
	if contact != nil {
		contact.Name = name
		if err := r.dataStore.SaveContact(contact); err != nil {
			logf(r.logger, "failed to cache profile name: %v", err)
		}
	}

	return name
}

// saveContactProfileKey stores or updates a contact's profile key.
// This is needed for sealed sender - we derive the unidentified access key from it.
func (r *Receiver) saveContactProfileKey(aci string, profileKey []byte) error {
	// Get existing contact or create new one
	contact, err := r.dataStore.GetContactByACI(aci)
	if err != nil {
		return err
	}
	if contact == nil {
		contact = &store.Contact{ACI: aci}
	}

	// Only update if we don't have a profile key or it changed
	if len(contact.ProfileKey) == 0 || !bytes.Equal(contact.ProfileKey, profileKey) {
		contact.ProfileKey = profileKey
		if err := r.dataStore.SaveContact(contact); err != nil {
			return err
		}
		logf(r.logger, "saved profile key for %s", aci)
	}
	return nil
}

// processSenderKeyDistribution processes a sender key distribution message,
// storing the sender key for later use in decrypting group messages.
func (r *Receiver) processSenderKeyDistribution(senderACI string, senderDevice uint32, skdmBytes []byte) error {
	logf(r.logger, "processing sender key distribution from=%s device=%d len=%d", senderACI, senderDevice, len(skdmBytes))

	// Deserialize the distribution message
	skdm, err := libsignal.DeserializeSenderKeyDistributionMessage(skdmBytes)
	if err != nil {
		return fmt.Errorf("deserialize SKDM: %w", err)
	}
	defer skdm.Destroy()

	// Create the sender address
	addr, err := libsignal.NewAddress(senderACI, senderDevice)
	if err != nil {
		return fmt.Errorf("create address: %w", err)
	}
	defer addr.Destroy()

	// Process the distribution message - this stores the sender key in the store
	if err := libsignal.ProcessSenderKeyDistributionMessage(addr, skdm, r.cryptoStore); err != nil {
		return fmt.Errorf("process SKDM: %w", err)
	}

	logf(r.logger, "stored sender key from=%s device=%d", senderACI, senderDevice)
	return nil
}

// populateGroupInfo extracts group info from a master key and populates the message.
// It also stores/updates the group in the database for future reference.
func (r *Receiver) populateGroupInfo(msg *Message, masterKeyBytes []byte, revision int) {
	if len(masterKeyBytes) != 32 {
		return
	}

	// Convert to GroupMasterKey
	var masterKey libsignal.GroupMasterKey
	copy(masterKey[:], masterKeyBytes)

	// Derive group identifier
	groupID, err := libsignal.GroupIdentifierFromMasterKey(masterKey)
	if err != nil {
		logf(r.logger, "failed to derive group identifier: %v", err)
		return
	}

	msg.GroupID = groupID.String()
	logf(r.logger, "group message groupID=%s revision=%d", msg.GroupID, revision)

	// Check if we have this group stored
	existing, err := r.dataStore.GetGroup(msg.GroupID)
	if err != nil {
		logf(r.logger, "failed to get group: %v", err)
	}

	if existing != nil {
		// Use cached name
		msg.GroupName = existing.Name
		// Update revision if newer
		if revision > existing.Revision {
			existing.Revision = revision
			if err := r.dataStore.SaveGroup(existing); err != nil {
				logf(r.logger, "failed to update group revision: %v", err)
			}
		}
		// Fetch name if not yet known
		if existing.Name == "" {
			r.fetchGroupName(existing)
			msg.GroupName = existing.Name
		}
	} else {
		// Store new group
		newGroup := &store.Group{
			GroupID:   msg.GroupID,
			MasterKey: masterKeyBytes,
			Revision:  revision,
		}
		if err := r.dataStore.SaveGroup(newGroup); err != nil {
			logf(r.logger, "failed to save group: %v", err)
		} else {
			logf(r.logger, "stored new group groupID=%s", msg.GroupID)
			r.fetchGroupName(newGroup)
			msg.GroupName = newGroup.Name
		}
	}
}

// fetchGroupName fetches the group name from the Groups V2 API and updates the group in the store.
func (r *Receiver) fetchGroupName(group *store.Group) {
	if err := r.fetchGroupDetails(context.Background(), group); err != nil {
		logf(r.logger, "failed to fetch group name for %s: %v", group.GroupID, err)
		return
	}
	if group.Name != "" {
		logf(r.logger, "fetched group name for %s: %q", group.GroupID, group.Name)
		if err := r.dataStore.SaveGroup(group); err != nil {
			logf(r.logger, "failed to save group name: %v", err)
		}
	}
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
