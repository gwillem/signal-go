package signalservice

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
)

func TestSendRetryReceipt(t *testing.T) {
	// Set up a store with identity.
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
	st.SetIdentity(priv, 1)

	// Create a real ciphertext for the DecryptionErrorMessage.
	alice := libsignal.NewMemorySessionStore()
	aliceIdentity := libsignal.NewMemoryIdentityKeyStore(priv, 1)

	bobPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPriv.Destroy()

	bobPub, err := bobPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPub.Destroy()

	spk, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spk.Destroy()

	spkPub, err := spk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPub.Destroy()

	spkPubBytes, err := spkPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	spkSig, err := bobPriv.Sign(spkPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	kyberKP, err := libsignal.GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberKP.Destroy()

	kyberPub, err := kyberKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	kyberSig, err := bobPriv.Sign(kyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	preKeyPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyPriv.Destroy()

	preKeyPub, err := preKeyPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyPub.Destroy()

	bobAddr, err := libsignal.NewAddress("sender-aci", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer bobAddr.Destroy()

	bundle, err := libsignal.NewPreKeyBundle(1, 1, 1, preKeyPub, 1, spkPub, spkSig, bobPub, 1, kyberPub, kyberSig)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()

	if err := libsignal.ProcessPreKeyBundle(bundle, bobAddr, alice, aliceIdentity, time.Now()); err != nil {
		t.Fatal(err)
	}

	ct, err := libsignal.Encrypt([]byte("hello"), bobAddr, alice, aliceIdentity, time.Now())
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

	// Track the HTTP request.
	var receivedMsg *OutgoingMessageList
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/v1/messages/sender-aci" {
			body, _ := io.ReadAll(r.Body)
			receivedMsg = new(OutgoingMessageList)
			json.Unmarshal(body, receivedMsg)
			w.WriteHeader(http.StatusOK)
		} else {
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	auth := BasicAuth{Username: "me.1", Password: "pass"}
	var timestamp uint64 = 1700000000000

	err = SendRetryReceipt(context.Background(), srv.URL, st, auth, nil, "sender-aci", 1, ctBytes, msgType, timestamp)
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
	if receivedMsg.Messages[0].Type != proto.Envelope_PLAINTEXT_CONTENT {
		t.Errorf("type: got %d, want %d", receivedMsg.Messages[0].Type, proto.Envelope_PLAINTEXT_CONTENT)
	}
	if receivedMsg.Messages[0].Content == "" {
		t.Error("content should not be empty")
	}
}

func TestHandleRetryReceipt(t *testing.T) {
	// Set up store with a session that we'll archive.
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
	st.SetIdentity(myPriv, 1)

	// Create a session with the requester.
	requesterPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer requesterPriv.Destroy()

	requesterPub, err := requesterPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer requesterPub.Destroy()

	spk, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spk.Destroy()

	spkPub, err := spk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPub.Destroy()

	spkPubBytes, err := spkPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	spkSig, err := requesterPriv.Sign(spkPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	kyberKP, err := libsignal.GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberKP.Destroy()

	kyberPub, err := kyberKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	kyberSig, err := requesterPriv.Sign(kyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	preKeyPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyPriv.Destroy()

	preKeyPub, err := preKeyPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyPub.Destroy()

	requesterAddr, err := libsignal.NewAddress("requester-aci", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer requesterAddr.Destroy()

	// Process pre-key bundle to establish a session.
	bundle, err := libsignal.NewPreKeyBundle(1, 1, 1, preKeyPub, 1, spkPub, spkSig, requesterPub, 1, kyberPub, kyberSig)
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

	// Set up mock server for the null message send.
	// We need to serve pre-keys (since session will be archived) and accept the message.
	enc := base64.RawStdEncoding.EncodeToString
	requesterPubBytes, err := requesterPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	preKeyPubBytes, err := preKeyPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	var nullMsgReceived bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/keys/requester-aci/1":
			// Serve fresh pre-keys for new session.
			json.NewEncoder(w).Encode(PreKeyResponse{
				IdentityKey: enc(requesterPubBytes),
				Devices: []PreKeyDeviceInfo{
					{
						DeviceID:       1,
						RegistrationID: 1,
						SignedPreKey: &SignedPreKeyEntity{
							KeyID:     1,
							PublicKey: enc(spkPubBytes),
							Signature: enc(spkSig),
						},
						PreKey: &PreKeyEntity{
							KeyID:     1,
							PublicKey: enc(preKeyPubBytes),
						},
						PqPreKey: &KyberPreKeyEntity{
							KeyID:     1,
							PublicKey: enc(kyberPubBytes),
							Signature: enc(kyberSig),
						},
					},
				},
			})

		case r.Method == http.MethodPut && r.URL.Path == "/v1/messages/requester-aci":
			nullMsgReceived = true
			w.WriteHeader(http.StatusOK)

		default:
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	auth := BasicAuth{Username: "me.1", Password: "pass"}

	err = HandleRetryReceipt(context.Background(), srv.URL, st, auth, nil, "requester-aci", 1)
	if err != nil {
		t.Fatal(err)
	}

	// Verify session was archived (a new session was created by null message).
	session, err = st.LoadSession(requesterAddr)
	if err != nil {
		t.Fatal(err)
	}
	// Session should exist again after null message re-established it.
	if session != nil {
		session.Destroy()
	}

	if !nullMsgReceived {
		t.Error("expected null message to be sent")
	}
}
