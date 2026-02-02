package signalservice

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// setupAliceAndBob creates two parties where Alice can encrypt messages to Bob.
// Bob's SQLite store is returned with pre-keys loaded for decryption.
// The returned encryptAsAlice function encrypts text as Alice → Bob.
func setupAliceAndBob(t *testing.T) (bobStore *store.Store, senderACI string, encryptAsAlice func(text string) ([]byte, uint8)) {
	t.Helper()

	// Alice (sender) identity.
	aliceIdentityPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	// Bob (receiver) — set up with SQLite store.
	dbPath := filepath.Join(t.TempDir(), "bob.db")
	bobSt, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bobSt.Close() })

	bobIdentityPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	bobSt.SetIdentity(bobIdentityPriv, 42)

	bobIdentityPub, err := bobIdentityPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobIdentityPub.Destroy()

	// Bob's signed pre-key.
	bobSPKPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobSPKPriv.Destroy()

	bobSPKPub, err := bobSPKPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobSPKPub.Destroy()

	bobSPKPubBytes, err := bobSPKPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	bobSPKSig, err := bobIdentityPriv.Sign(bobSPKPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Bob's one-time pre-key.
	bobPreKeyPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPreKeyPriv.Destroy()

	bobPreKeyPub, err := bobPreKeyPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPreKeyPub.Destroy()

	// Bob's Kyber pre-key.
	bobKyberKP, err := libsignal.GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer bobKyberKP.Destroy()

	bobKyberPub, err := bobKyberKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobKyberPub.Destroy()

	bobKyberPubBytes, err := bobKyberPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	bobKyberSig, err := bobIdentityPriv.Sign(bobKyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Store Bob's pre-keys.
	bobPreKeyRec, err := libsignal.NewPreKeyRecord(100, bobPreKeyPub, bobPreKeyPriv)
	if err != nil {
		t.Fatal(err)
	}
	bobSt.StorePreKey(100, bobPreKeyRec)

	bobSPKRec, err := libsignal.NewSignedPreKeyRecord(1, 1000, bobSPKPub, bobSPKPriv, bobSPKSig)
	if err != nil {
		t.Fatal(err)
	}
	bobSt.StoreSignedPreKey(1, bobSPKRec)

	bobKyberRec, err := libsignal.NewKyberPreKeyRecord(200, 1000, bobKyberKP, bobKyberSig)
	if err != nil {
		t.Fatal(err)
	}
	bobSt.StoreKyberPreKey(200, bobKyberRec)

	// Alice's session store (in-memory) for encrypting to Bob.
	aliceSessionStore := libsignal.NewMemorySessionStore()
	aliceIdentityStore := libsignal.NewMemoryIdentityKeyStore(aliceIdentityPriv, 1)

	// Process Bob's pre-key bundle on Alice's side.
	bobAddr, err := libsignal.NewAddress("bob-aci", 2)
	if err != nil {
		t.Fatal(err)
	}
	defer bobAddr.Destroy()

	bundle, err := libsignal.NewPreKeyBundle(
		42, 2,
		100, bobPreKeyPub,
		1, bobSPKPub, bobSPKSig,
		bobIdentityPub,
		200, bobKyberPub, bobKyberSig,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()

	if err := libsignal.ProcessPreKeyBundle(bundle, bobAddr, aliceSessionStore, aliceIdentityStore, time.Now()); err != nil {
		t.Fatal(err)
	}

	senderACI = "alice-aci"

	encryptAsAlice = func(text string) ([]byte, uint8) {
		t.Helper()
		timestamp := uint64(time.Now().UnixMilli())
		content := &proto.Content{
			DataMessage: &proto.DataMessage{
				Body:      &text,
				Timestamp: &timestamp,
			},
		}
		contentBytes, err := pb.Marshal(content)
		if err != nil {
			t.Fatal(err)
		}

		addr, err := libsignal.NewAddress("bob-aci", 2)
		if err != nil {
			t.Fatal(err)
		}
		defer addr.Destroy()

		ciphertext, err := libsignal.Encrypt(contentBytes, addr, aliceSessionStore, aliceIdentityStore, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		defer ciphertext.Destroy()

		msgType, err := ciphertext.Type()
		if err != nil {
			t.Fatal(err)
		}

		ct, err := ciphertext.Serialize()
		if err != nil {
			t.Fatal(err)
		}

		return ct, msgType
	}

	return bobSt, senderACI, encryptAsAlice
}

// buildEnvelopeWSMessage builds a WebSocketMessage containing an Envelope, as the server would send.
func buildEnvelopeWSMessage(t *testing.T, requestID uint64, senderACI string, senderDevice uint32, envelopeType proto.Envelope_Type, content []byte) []byte {
	t.Helper()

	timestamp := uint64(time.Now().UnixMilli())
	env := &proto.Envelope{
		Type:            envelopeType.Enum(),
		SourceServiceId: &senderACI,
		SourceDevice:    &senderDevice,
		Timestamp:       &timestamp,
		Content:         content,
	}
	envBytes, err := pb.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	verb := "PUT"
	path := "/api/v1/message"
	wsMsg := &proto.WebSocketMessage{
		Type: proto.WebSocketMessage_REQUEST.Enum(),
		Request: &proto.WebSocketRequestMessage{
			Id:   &requestID,
			Verb: &verb,
			Path: &path,
			Body: envBytes,
		},
	}
	data, err := pb.Marshal(wsMsg)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// wsServer starts a test WebSocket server that calls handler for each connection.
// The handler receives the accepted websocket and should send messages/read ACKs.
// The server blocks the handler goroutine until done is closed, preventing
// PersistentConn from reconnecting and replaying messages.
func wsServer(t *testing.T, handler func(ws *websocket.Conn, ctx context.Context)) (*httptest.Server, chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()
		handler(ws, r.Context())
		// Block until test is done to prevent reconnect loops.
		<-done
	}))
	t.Cleanup(func() {
		close(done)
		srv.Close()
	})
	return srv, done
}

func TestHandleEnvelopeDirect(t *testing.T) {
	bobStore, senderACI, encryptAsAlice := setupAliceAndBob(t)
	ct, _ := encryptAsAlice("direct test")

	timestamp := uint64(time.Now().UnixMilli())
	senderDevice := uint32(1)
	env := &proto.Envelope{
		Type:            proto.Envelope_PREKEY_BUNDLE.Enum(),
		SourceServiceId: &senderACI,
		SourceDevice:    &senderDevice,
		Timestamp:       &timestamp,
		Content:         ct,
	}
	envBytes, err := pb.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := handleEnvelope(envBytes, bobStore, "bob-aci", 2, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil {
		t.Fatal("expected message, got nil")
	}
	if msg.Body != "direct test" {
		t.Errorf("body: got %q, want %q", msg.Body, "direct test")
	}
	if msg.Sender != senderACI {
		t.Errorf("sender: got %q, want %q", msg.Sender, senderACI)
	}
}

func TestHandleEnvelopeSkipsDeliveryReceipt(t *testing.T) {
	bobStore, senderACI, _ := setupAliceAndBob(t)

	senderDevice := uint32(1)
	timestamp := uint64(time.Now().UnixMilli())
	env := &proto.Envelope{
		Type:            proto.Envelope_SERVER_DELIVERY_RECEIPT.Enum(),
		SourceServiceId: &senderACI,
		SourceDevice:    &senderDevice,
		Timestamp:       &timestamp,
	}
	envBytes, err := pb.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	msg, err := handleEnvelope(envBytes, bobStore, "bob-aci", 2, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if msg != nil {
		t.Errorf("expected nil for delivery receipt, got %+v", msg)
	}
}

func TestDumpEnvelope(t *testing.T) {
	bobStore, senderACI, encryptAsAlice := setupAliceAndBob(t)
	ct, _ := encryptAsAlice("dump test")

	timestamp := uint64(time.Now().UnixMilli())
	senderDevice := uint32(1)
	env := &proto.Envelope{
		Type:            proto.Envelope_PREKEY_BUNDLE.Enum(),
		SourceServiceId: &senderACI,
		SourceDevice:    &senderDevice,
		Timestamp:       &timestamp,
		Content:         ct,
	}
	envBytes, err := pb.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	debugDir := t.TempDir()

	msg, err := handleEnvelope(envBytes, bobStore, "bob-aci", 2, nil, debugDir)
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil || msg.Body != "dump test" {
		t.Fatalf("unexpected message: %+v", msg)
	}

	// Verify a .bin file was written with the correct raw bytes.
	entries, err := os.ReadDir(debugDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 dump file, got %d", len(entries))
	}

	name := entries[0].Name()
	if !strings.HasSuffix(name, ".bin") {
		t.Errorf("expected .bin extension, got %q", name)
	}
	if !strings.Contains(name, "PREKEY_BUNDLE") {
		t.Errorf("expected filename to contain PREKEY_BUNDLE, got %q", name)
	}
	if !strings.Contains(name, senderACI[:8]) {
		t.Errorf("expected filename to contain sender prefix, got %q", name)
	}

	// Verify contents match the raw envelope bytes.
	dumped, err := LoadDump(filepath.Join(debugDir, name))
	if err != nil {
		t.Fatal(err)
	}
	if len(dumped) != len(envBytes) {
		t.Errorf("dump size: got %d, want %d", len(dumped), len(envBytes))
	}
	for i := range dumped {
		if dumped[i] != envBytes[i] {
			t.Fatalf("dump mismatch at byte %d", i)
		}
	}
}

func TestDumpEnvelopeNoOpWhenEmpty(t *testing.T) {
	bobStore, senderACI, encryptAsAlice := setupAliceAndBob(t)
	ct, _ := encryptAsAlice("no dump test")

	timestamp := uint64(time.Now().UnixMilli())
	senderDevice := uint32(1)
	env := &proto.Envelope{
		Type:            proto.Envelope_PREKEY_BUNDLE.Enum(),
		SourceServiceId: &senderACI,
		SourceDevice:    &senderDevice,
		Timestamp:       &timestamp,
		Content:         ct,
	}
	envBytes, err := pb.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}

	// Pass empty debugDir — should not create any files.
	msg, err := handleEnvelope(envBytes, bobStore, "bob-aci", 2, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if msg == nil || msg.Body != "no dump test" {
		t.Fatalf("unexpected message: %+v", msg)
	}
}

func TestReceivePreKeyMessage(t *testing.T) {
	bobStore, senderACI, encryptAsAlice := setupAliceAndBob(t)
	ct, _ := encryptAsAlice("Hello Bob!")

	srv, _ := wsServer(t, func(ws *websocket.Conn, ctx context.Context) {
		// Verify auth in query params is tested via URL construction test.
		data := buildEnvelopeWSMessage(t, 1, senderACI, 1, proto.Envelope_PREKEY_BUNDLE, ct)
		if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
		// Read the ACK.
		_, ackData, err := ws.Read(ctx)
		if err != nil {
			t.Errorf("ws read ack: %v", err)
			return
		}
		var ackMsg proto.WebSocketMessage
		if err := pb.Unmarshal(ackData, &ackMsg); err != nil {
			t.Errorf("unmarshal ack: %v", err)
			return
		}
		if ackMsg.GetResponse().GetStatus() != 200 {
			t.Errorf("expected status 200, got %d", ackMsg.GetResponse().GetStatus())
		}
		if ackMsg.GetResponse().GetId() != 1 {
			t.Errorf("expected id 1, got %d", ackMsg.GetResponse().GetId())
		}
	})

	wsURL := "ws" + srv.URL[4:]
	auth := BasicAuth{Username: "bob-aci.2", Password: "password"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var received []Message
	for msg, err := range ReceiveMessages(ctx, wsURL, bobStore, auth, "bob-aci", 2, nil, nil, "") {
		if err != nil {
			continue
		}
		received = append(received, msg)
		cancel() // Got our message, stop.
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 message, got %d", len(received))
	}
	if received[0].Body != "Hello Bob!" {
		t.Errorf("body: got %q, want %q", received[0].Body, "Hello Bob!")
	}
	if received[0].Sender != senderACI {
		t.Errorf("sender: got %q, want %q", received[0].Sender, senderACI)
	}
	if received[0].Device != 1 {
		t.Errorf("device: got %d, want 1", received[0].Device)
	}
}

func TestReceiveCiphertextMessage(t *testing.T) {
	bobStore, senderACI, encryptAsAlice := setupAliceAndBob(t)

	// First message is PreKey — decrypt manually to establish session on Bob's side.
	ct1, _ := encryptAsAlice("first")

	aliceAddr, err := libsignal.NewAddress(senderACI, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceAddr.Destroy()

	preKeyMsg, err := libsignal.DeserializePreKeySignalMessage(ct1)
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyMsg.Destroy()

	_, err = libsignal.DecryptPreKeyMessage(preKeyMsg, aliceAddr, bobStore, bobStore, bobStore, bobStore, bobStore)
	if err != nil {
		t.Fatal(err)
	}

	// Second message from Alice. Map ciphertext type to envelope type dynamically,
	// since without a full ratchet exchange it may still be PreKey.
	ct2, msgType := encryptAsAlice("second message")
	envType := proto.Envelope_PREKEY_BUNDLE
	if msgType == libsignal.CiphertextMessageTypeWhisper {
		envType = proto.Envelope_CIPHERTEXT
	}

	srv, _ := wsServer(t, func(ws *websocket.Conn, ctx context.Context) {
		data := buildEnvelopeWSMessage(t, 42, senderACI, 1, envType, ct2)
		if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
		if _, _, err := ws.Read(ctx); err != nil {
			return
		}
	})

	wsURL := "ws" + srv.URL[4:]
	auth := BasicAuth{Username: "bob-aci.2", Password: "password"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var received []Message
	for msg, err := range ReceiveMessages(ctx, wsURL, bobStore, auth, "bob-aci", 2, nil, nil, "") {
		if err != nil {
			continue
		}
		received = append(received, msg)
		cancel()
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 message, got %d", len(received))
	}
	if received[0].Body != "second message" {
		t.Errorf("body: got %q, want %q", received[0].Body, "second message")
	}
}

func TestReceiveMultipleMessages(t *testing.T) {
	bobStore, senderACI, encryptAsAlice := setupAliceAndBob(t)

	// Send delivery receipt (skipped) then a real text message.
	ct, _ := encryptAsAlice("actual text")

	srv, _ := wsServer(t, func(ws *websocket.Conn, ctx context.Context) {
		// Delivery receipt — skipped.
		data := buildEnvelopeWSMessage(t, 1, senderACI, 1, proto.Envelope_SERVER_DELIVERY_RECEIPT, nil)
		if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
		if _, _, err := ws.Read(ctx); err != nil {
			return
		}

		// Real text message.
		data = buildEnvelopeWSMessage(t, 2, senderACI, 1, proto.Envelope_PREKEY_BUNDLE, ct)
		if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
		if _, _, err := ws.Read(ctx); err != nil {
			return
		}
	})

	wsURL := "ws" + srv.URL[4:]
	auth := BasicAuth{Username: "bob-aci.2", Password: "password"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var received []Message
	for msg, err := range ReceiveMessages(ctx, wsURL, bobStore, auth, "bob-aci", 2, nil, nil, "") {
		if err != nil {
			continue
		}
		received = append(received, msg)
		cancel()
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 message, got %d", len(received))
	}
	if received[0].Body != "actual text" {
		t.Errorf("body: got %q, want %q", received[0].Body, "actual text")
	}
}

func TestReceiveWebSocketHeaders(t *testing.T) {
	auth := BasicAuth{Username: "abc-123.2", Password: "mypass"}
	headers := buildWebSocketHeaders(auth)

	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		t.Fatal("missing Authorization header")
	}
	if !strings.HasPrefix(authHeader, "Basic ") {
		t.Errorf("Authorization header should start with 'Basic ', got %q", authHeader)
	}

	agent := headers.Get("X-Signal-Agent")
	if agent != "signal-go" {
		t.Errorf("X-Signal-Agent: got %q, want %q", agent, "signal-go")
	}

	stories := headers.Get("X-Signal-Receive-Stories")
	if stories != "false" {
		t.Errorf("X-Signal-Receive-Stories: got %q, want %q", stories, "false")
	}
}

func TestReceiveBreakClosesConnection(t *testing.T) {
	bobStore, senderACI, encryptAsAlice := setupAliceAndBob(t)

	ct1, _ := encryptAsAlice("message 1")
	ct2, _ := encryptAsAlice("message 2")

	srv, _ := wsServer(t, func(ws *websocket.Conn, ctx context.Context) {
		data := buildEnvelopeWSMessage(t, 1, senderACI, 1, proto.Envelope_PREKEY_BUNDLE, ct1)
		if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
		if _, _, err := ws.Read(ctx); err != nil {
			return
		}

		data = buildEnvelopeWSMessage(t, 2, senderACI, 1, proto.Envelope_PREKEY_BUNDLE, ct2)
		if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
			return
		}
		// Client may break before reading ACK.
		ws.Read(ctx)
	})

	wsURL := "ws" + srv.URL[4:]
	auth := BasicAuth{Username: "bob-aci.2", Password: "password"}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	count := 0
	for msg, err := range ReceiveMessages(ctx, wsURL, bobStore, auth, "bob-aci", 2, nil, nil, "") {
		if err != nil {
			continue
		}
		count++
		_ = msg
		break // Break after first message.
	}

	if count != 1 {
		t.Errorf("expected 1 message before break, got %d", count)
	}
}
