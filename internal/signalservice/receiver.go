package signalservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"iter"
	"log"
	"net/http"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/signalws"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// Message represents a received Signal message.
type Message struct {
	Sender    string    // sender ACI UUID
	Device    uint32    // sender device ID
	Timestamp time.Time // sender timestamp
	Body      string    // text content
	SyncTo    string    // recipient ACI if this is a SyncMessage (sent by our other device)
}

// ReceiveMessages connects to the authenticated WebSocket and returns an iterator
// that yields received text messages. The iterator stops when the context is
// cancelled or when the caller breaks out of the range loop.
// If logger is nil, logging is disabled.
func ReceiveMessages(ctx context.Context, wsURL string, st *store.Store, auth BasicAuth, localUUID string, localDeviceID uint32, tlsConf *tls.Config, logger *log.Logger, debugDir string) iter.Seq2[Message, error] {
	return func(yield func(Message, error) bool) {
		wsEndpoint := wsURL + "/v1/websocket/"
		headers := buildWebSocketHeaders(auth)
		logf(logger, "connecting to WebSocket url=%s user=%s", wsEndpoint, auth.Username)
		conn, err := signalws.DialPersistent(ctx, wsEndpoint, tlsConf,
			signalws.WithHeaders(headers),
			signalws.WithKeepAliveCallback(func(rtt time.Duration) {
				logf(logger, "keep-alive OK rtt=%s", rtt)
			}),
		)
		if err != nil {
			yield(Message{}, fmt.Errorf("receiver: dial: %w", err))
			return
		}
		defer conn.Close()
		logf(logger, "connected, waiting for messages")

		for {
			wsMsg, err := conn.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					logf(logger, "context cancelled, stopping")
					return
				}
				logf(logger, "read error: %v", err)
				if !yield(Message{}, fmt.Errorf("receiver: read: %w", err)) {
					return
				}
				continue
			}

			logf(logger, "ws message type=%v", wsMsg.GetType())

			// Only process REQUEST messages.
			if wsMsg.GetType() != proto.WebSocketMessage_REQUEST {
				if wsMsg.GetType() == proto.WebSocketMessage_RESPONSE {
					resp := wsMsg.GetResponse()
					logf(logger, "ws response id=%d status=%d message=%s", resp.GetId(), resp.GetStatus(), resp.GetMessage())
				}
				continue
			}
			req := wsMsg.GetRequest()
			logf(logger, "ws request verb=%s path=%s id=%d bodyLen=%d", req.GetVerb(), req.GetPath(), req.GetId(), len(req.GetBody()))

			if req.GetVerb() != "PUT" || req.GetPath() != "/api/v1/message" {
				// ACK non-message requests.
				if req.GetId() != 0 {
					_ = conn.SendResponse(ctx, req.GetId(), 200, "OK")
				}
				continue
			}

			msg, err := handleEnvelope(req.GetBody(), st, localUUID, localDeviceID, logger, debugDir)
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
func handleEnvelope(data []byte, st *store.Store, localUUID string, localDeviceID uint32, logger *log.Logger, debugDir string) (*Message, error) {
	var env proto.Envelope
	if err := pb.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	dumpEnvelope(debugDir, data, &env, logger)

	envType := env.GetType()
	logf(logger, "envelope type=%v sender=%s device=%d timestamp=%d contentLen=%d",
		envType, env.GetSourceServiceId(), env.GetSourceDevice(), env.GetTimestamp(), len(env.GetContent()))

	// Only handle known envelope types.
	switch envType {
	case proto.Envelope_CIPHERTEXT, proto.Envelope_PREKEY_BUNDLE, proto.Envelope_UNIDENTIFIED_SENDER:
		// Proceed with decryption below.
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

	var plaintext []byte

	switch envType {
	case proto.Envelope_UNIDENTIFIED_SENDER:
		logf(logger, "decrypting sealed sender message (version byte=0x%02x, len=%d)", content[0], len(content))

		// Step 1: Decrypt outer sealed sender layer → USMC (uses only identity key for ECDH).
		// This ECDH uses our local identity key. If the sender cached our old identity
		// key (e.g. after a re-link), decryption produces garbage and the inner protobuf
		// parse fails with "protobuf encoding was invalid". The sender's client will
		// eventually refresh our key and retry.
		usmc, err := libsignal.SealedSenderDecryptToUSMC(content, st)
		if err != nil {
			return nil, fmt.Errorf("sealed sender decrypt outer (if recent re-link, sender has stale identity key): %w", err)
		}
		defer usmc.Destroy()

		// Step 2: Validate sender certificate.
		cert, err := usmc.GetSenderCert()
		if err != nil {
			return nil, fmt.Errorf("sealed sender get cert: %w", err)
		}
		defer cert.Destroy()

		trustRoot, err := loadTrustRoot()
		if err != nil {
			return nil, fmt.Errorf("load trust root: %w", err)
		}
		defer trustRoot.Destroy()

		valid, err := cert.Validate(trustRoot, env.GetServerTimestamp())
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
				return nil, fmt.Errorf("sealed sender deserialize pre-key: %w", err)
			}
			defer preKeyMsg.Destroy()
			plaintext, err = libsignal.DecryptPreKeyMessage(preKeyMsg, addr, st, st, st, st, st)
			if err != nil {
				return nil, fmt.Errorf("sealed sender decrypt pre-key: %w", err)
			}

		case libsignal.CiphertextMessageTypeWhisper:
			logf(logger, "sealed sender: decrypting inner whisper message")
			sigMsg, err := libsignal.DeserializeSignalMessage(innerContent)
			if err != nil {
				return nil, fmt.Errorf("sealed sender deserialize whisper: %w", err)
			}
			defer sigMsg.Destroy()
			plaintext, err = libsignal.DecryptMessage(sigMsg, addr, st, st)
			if err != nil {
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

	// Extract text body from DataMessage (direct message).
	if dm := contentProto.GetDataMessage(); dm != nil && dm.Body != nil {
		return &Message{
			Sender:    senderACI,
			Device:    senderDevice,
			Timestamp: time.UnixMilli(int64(env.GetTimestamp())),
			Body:      dm.GetBody(),
		}, nil
	}

	// Extract text body from SyncMessage.Sent (message sent by our other device).
	if sm := contentProto.GetSyncMessage(); sm != nil {
		if sent := sm.GetSent(); sent != nil {
			if dm := sent.GetMessage(); dm != nil && dm.Body != nil {
				recipient := sent.GetDestinationServiceId()
				return &Message{
					Sender:    senderACI,
					Device:    senderDevice,
					Timestamp: time.UnixMilli(int64(sent.GetTimestamp())),
					Body:      dm.GetBody(),
					SyncTo:    recipient,
				}, nil
			}
		}
	}

	logf(logger, "skipping non-text content")
	return nil, nil
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
