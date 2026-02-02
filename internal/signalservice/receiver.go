package signalservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"iter"
	"log/slog"
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
// If logger is nil, a no-op logger is used.
func ReceiveMessages(ctx context.Context, wsURL string, st *store.Store, auth BasicAuth, tlsConf *tls.Config, logger *slog.Logger) iter.Seq2[Message, error] {
	if logger == nil {
		logger = slog.New(discardHandler{})
	}
	return func(yield func(Message, error) bool) {
		wsEndpoint := wsURL + "/v1/websocket/"
		headers := buildWebSocketHeaders(auth)
		logger.Info("connecting to WebSocket", "url", wsEndpoint, "user", auth.Username)
		conn, err := signalws.DialPersistent(ctx, wsEndpoint, tlsConf,
			signalws.WithHeaders(headers),
			signalws.WithKeepAliveCallback(func(rtt time.Duration) {
				logger.Debug("keep-alive OK", "rtt", rtt)
			}),
		)
		if err != nil {
			yield(Message{}, fmt.Errorf("receiver: dial: %w", err))
			return
		}
		defer conn.Close()
		logger.Info("connected, waiting for messages")

		for {
			wsMsg, err := conn.ReadMessage(ctx)
			if err != nil {
				if ctx.Err() != nil {
					logger.Info("context cancelled, stopping")
					return
				}
				logger.Warn("read error", "error", err)
				if !yield(Message{}, fmt.Errorf("receiver: read: %w", err)) {
					return
				}
				continue
			}

			logger.Debug("ws message", "type", wsMsg.GetType())

			// Only process REQUEST messages.
			if wsMsg.GetType() != proto.WebSocketMessage_REQUEST {
				if wsMsg.GetType() == proto.WebSocketMessage_RESPONSE {
					resp := wsMsg.GetResponse()
					logger.Debug("ws response", "id", resp.GetId(), "status", resp.GetStatus(), "message", resp.GetMessage())
				}
				continue
			}
			req := wsMsg.GetRequest()
			logger.Debug("ws request", "verb", req.GetVerb(), "path", req.GetPath(), "id", req.GetId(), "bodyLen", len(req.GetBody()))

			if req.GetVerb() != "PUT" || req.GetPath() != "/api/v1/message" {
				// ACK non-message requests.
				if req.GetId() != 0 {
					_ = conn.SendResponse(ctx, req.GetId(), 200, "OK")
				}
				continue
			}

			msg, err := handleEnvelope(req.GetBody(), st, logger)
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
func handleEnvelope(data []byte, st *store.Store, logger *slog.Logger) (*Message, error) {
	if logger == nil {
		logger = slog.New(discardHandler{})
	}
	var env proto.Envelope
	if err := pb.Unmarshal(data, &env); err != nil {
		return nil, fmt.Errorf("unmarshal envelope: %w", err)
	}

	envType := env.GetType()
	logger.Info("envelope",
		"type", envType,
		"sender", env.GetSourceServiceId(),
		"device", env.GetSourceDevice(),
		"timestamp", env.GetTimestamp(),
		"contentLen", len(env.GetContent()),
	)

	// Only handle CIPHERTEXT and PREKEY_BUNDLE envelopes.
	switch envType {
	case proto.Envelope_CIPHERTEXT, proto.Envelope_PREKEY_BUNDLE:
		// Proceed with decryption below.
	default:
		logger.Info("skipping unsupported envelope type", "type", envType)
		return nil, nil
	}

	content := env.GetContent()
	if len(content) == 0 {
		return nil, fmt.Errorf("empty envelope content")
	}

	senderACI := env.GetSourceServiceId()
	senderDevice := env.GetSourceDevice()

	addr, err := libsignal.NewAddress(senderACI, senderDevice)
	if err != nil {
		return nil, fmt.Errorf("create address: %w", err)
	}
	defer addr.Destroy()

	var plaintext []byte

	switch envType {
	case proto.Envelope_PREKEY_BUNDLE:
		logger.Debug("decrypting pre-key message")
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
		logger.Debug("decrypting ciphertext message")
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

	// Strip Signal transport padding: content is followed by 0x80 then 0x00 bytes.
	plaintext = stripPadding(plaintext)

	// Parse decrypted Content protobuf.
	var contentProto proto.Content
	if err := pb.Unmarshal(plaintext, &contentProto); err != nil {
		return nil, fmt.Errorf("unmarshal content: %w", err)
	}

	// Log what's inside the Content.
	logger.Debug("content",
		"hasDataMessage", contentProto.DataMessage != nil,
		"hasSyncMessage", contentProto.SyncMessage != nil,
		"hasTypingMessage", contentProto.TypingMessage != nil,
		"hasReceiptMessage", contentProto.ReceiptMessage != nil,
		"hasCallMessage", contentProto.CallMessage != nil,
	)

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

	logger.Info("skipping non-text content")
	return nil, nil
}

// discardHandler is a slog.Handler that discards all log records.
type discardHandler struct{}

func (discardHandler) Enabled(context.Context, slog.Level) bool  { return false }
func (discardHandler) Handle(context.Context, slog.Record) error { return nil }
func (d discardHandler) WithAttrs([]slog.Attr) slog.Handler      { return d }
func (d discardHandler) WithGroup(string) slog.Handler            { return d }

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
