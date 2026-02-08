package signalservice

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
)

func TestSendRetryReceipt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	priv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()
	if err := st.SetIdentity(priv, 1); err != nil {
		t.Fatal(err)
	}

	// Generate recipient identity and establish a session.
	bobPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPriv.Destroy()

	preKeyResp := makeTestPreKeys(t, bobPriv, 1, 1)

	bobAddr, err := libsignal.NewAddress("sender-aci", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer bobAddr.Destroy()

	bundle, err := buildPreKeyBundle(preKeyResp.IdentityKey, preKeyResp.Devices[0])
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()

	if err := libsignal.ProcessPreKeyBundle(bundle, bobAddr, st, st, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Encrypt a message to create realistic ciphertext for the DEM.
	ct, err := libsignal.Encrypt([]byte("hello"), bobAddr, st, st, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer ct.Destroy()

	ctBytes, err := ct.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	msgType, err := ct.Type()
	if err != nil {
		t.Fatal(err)
	}

	// Wire up Sender with callback to capture the outgoing message.
	var receivedMsg *outgoingMessageList

	snd := newTestSender(t, st, "me", 1)
	snd.sendHTTPMessage = func(_ context.Context, _ string, msg *outgoingMessageList) error {
		receivedMsg = msg
		return nil
	}

	var timestamp uint64 = 1700000000000
	err = snd.sendRetryReceipt(context.Background(), "sender-aci", 1, ctBytes, msgType, timestamp)
	if err != nil {
		t.Fatal(err)
	}

	if receivedMsg == nil {
		t.Fatal("expected message to be sent")
	}
	if receivedMsg.Destination != "sender-aci" {
		t.Errorf("destination: got %q", receivedMsg.Destination)
	}
	if len(receivedMsg.Messages) != 1 {
		t.Fatalf("messages: got %d", len(receivedMsg.Messages))
	}
	// Message is now sent encrypted (PREKEY_BUNDLE for first message).
	if receivedMsg.Messages[0].Type != proto.Envelope_PREKEY_BUNDLE {
		t.Errorf("type: got %d, want %d", receivedMsg.Messages[0].Type, proto.Envelope_PREKEY_BUNDLE)
	}
	if receivedMsg.Messages[0].Content == "" {
		t.Error("content should not be empty")
	}
}

func TestHandleRetryReceipt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	myPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer myPriv.Destroy()
	if err := st.SetIdentity(myPriv, 1); err != nil {
		t.Fatal(err)
	}

	// Generate requester identity and establish a session.
	requesterPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer requesterPriv.Destroy()

	preKeyResp := makeTestPreKeys(t, requesterPriv, 1, 1)

	requesterAddr, err := libsignal.NewAddress("requester-aci", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer requesterAddr.Destroy()

	bundle, err := buildPreKeyBundle(preKeyResp.IdentityKey, preKeyResp.Devices[0])
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()

	if err := libsignal.ProcessPreKeyBundle(bundle, requesterAddr, st, st, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Verify session exists.
	session, err := st.LoadSession(requesterAddr)
	if err != nil {
		t.Fatal(err)
	}
	if session == nil {
		t.Fatal("expected session to exist before HandleRetryReceipt")
	}
	session.Destroy()

	// Wire up Sender with callbacks.
	var nullMsgReceived bool

	snd := newTestSender(t, st, "me", 1)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		resp := makeTestPreKeys(t, requesterPriv, deviceID, 1)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, _ *outgoingMessageList) error {
		nullMsgReceived = true
		return nil
	}

	err = snd.handleRetryReceipt(context.Background(), "requester-aci", 1)
	if err != nil {
		t.Fatal(err)
	}

	// Verify session was re-established.
	session, err = st.LoadSession(requesterAddr)
	if err != nil {
		t.Fatal(err)
	}
	if session != nil {
		session.Destroy()
	}

	if !nullMsgReceived {
		t.Error("expected null message to be sent")
	}
}
