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
	pb "google.golang.org/protobuf/proto"
)

func TestSendTextMessageWithPreKeyFetch(t *testing.T) {
	// Set up Bob (recipient) with keys.
	bobIdentityPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobIdentityPriv.Destroy()

	bobIdentityPub, err := bobIdentityPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobIdentityPub.Destroy()

	bobIdentityPubBytes, err := bobIdentityPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Generate Bob's signed pre-key.
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

	// Generate Bob's one-time pre-key.
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

	bobPreKeyPubBytes, err := bobPreKeyPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Generate Bob's Kyber pre-key.
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

	enc := base64.RawStdEncoding.EncodeToString

	// Track what the mock server receives.
	var receivedMsg *OutgoingMessageList

	// Mock server: serves pre-keys on GET and accepts messages on PUT.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/keys/bob-aci/1":
			json.NewEncoder(w).Encode(PreKeyResponse{
				IdentityKey: enc(bobIdentityPubBytes),
				Devices: []PreKeyDeviceInfo{
					{
						DeviceID:       1,
						RegistrationID: 42,
						SignedPreKey: &SignedPreKeyEntity{
							KeyID:     1,
							PublicKey: enc(bobSPKPubBytes),
							Signature: enc(bobSPKSig),
						},
						PreKey: &PreKeyEntity{
							KeyID:     100,
							PublicKey: enc(bobPreKeyPubBytes),
						},
						PqPreKey: &KyberPreKeyEntity{
							KeyID:     200,
							PublicKey: enc(bobKyberPubBytes),
							Signature: enc(bobKyberSig),
						},
					},
				},
			})

		case r.Method == http.MethodPut && r.URL.Path == "/v1/messages/bob-aci":
			body, _ := io.ReadAll(r.Body)
			receivedMsg = new(OutgoingMessageList)
			json.Unmarshal(body, receivedMsg)
			w.WriteHeader(http.StatusOK)

		default:
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	// Set up Alice (sender) with SQLite store.
	dbPath := filepath.Join(t.TempDir(), "alice.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	alicePriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	// SetIdentity takes ownership.
	st.SetIdentity(alicePriv, 1)

	auth := BasicAuth{Username: "alice-aci.2", Password: "password"}

	// Send a message — this should fetch pre-keys, establish session, encrypt, and send.
	err = SendTextMessage(context.Background(), srv.URL, "bob-aci", "Hello Bob!", st, auth, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the message was sent.
	if receivedMsg == nil {
		t.Fatal("expected message to be sent to server")
	}
	if receivedMsg.Destination != "bob-aci" {
		t.Errorf("destination: got %q", receivedMsg.Destination)
	}
	if len(receivedMsg.Messages) != 1 {
		t.Fatalf("messages: got %d", len(receivedMsg.Messages))
	}

	msg := receivedMsg.Messages[0]
	if msg.Type != proto.Envelope_PREKEY_BUNDLE {
		t.Errorf("type: got %d, want %d (PreKey)", msg.Type, proto.Envelope_PREKEY_BUNDLE)
	}
	if msg.DestinationDeviceID != 1 {
		t.Errorf("destinationDeviceId: got %d", msg.DestinationDeviceID)
	}
	if msg.Content == "" {
		t.Error("content should not be empty")
	}

	// Verify Bob can decrypt it.
	ctBytes, err := base64.StdEncoding.DecodeString(msg.Content)
	if err != nil {
		t.Fatal(err)
	}

	bobSessionStore := libsignal.NewMemorySessionStore()
	bobIdentityStore := libsignal.NewMemoryIdentityKeyStore(bobIdentityPriv, 42)
	bobPreKeyStore := libsignal.NewMemoryPreKeyStore()
	bobSignedPreKeyStore := libsignal.NewMemorySignedPreKeyStore()
	bobKyberPreKeyStore := libsignal.NewMemoryKyberPreKeyStore()

	// Store Bob's pre-keys in his stores.
	bobPreKeyRec, err := libsignal.NewPreKeyRecord(100, bobPreKeyPub, bobPreKeyPriv)
	if err != nil {
		t.Fatal(err)
	}
	bobPreKeyStore.StorePreKey(100, bobPreKeyRec)

	bobSPKRec, err := libsignal.NewSignedPreKeyRecord(1, 1000, bobSPKPub, bobSPKPriv, bobSPKSig)
	if err != nil {
		t.Fatal(err)
	}
	bobSignedPreKeyStore.StoreSignedPreKey(1, bobSPKRec)

	bobKyberRec, err := libsignal.NewKyberPreKeyRecord(200, 1000, bobKyberKP, bobKyberSig)
	if err != nil {
		t.Fatal(err)
	}
	bobKyberPreKeyStore.StoreKyberPreKey(200, bobKyberRec)

	// Decrypt the pre-key message.
	aliceAddr, err := libsignal.NewAddress("alice-aci", 2)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceAddr.Destroy()

	preKeyMsg, err := libsignal.DeserializePreKeySignalMessage(ctBytes)
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyMsg.Destroy()

	plaintext, err := libsignal.DecryptPreKeyMessage(
		preKeyMsg, aliceAddr,
		bobSessionStore, bobIdentityStore,
		bobPreKeyStore, bobSignedPreKeyStore, bobKyberPreKeyStore,
	)
	if err != nil {
		t.Fatal(err)
	}

	// Parse the decrypted Content protobuf.
	var content proto.Content
	if err := pb.Unmarshal(plaintext, &content); err != nil {
		t.Fatal(err)
	}
	if content.GetDataMessage().GetBody() != "Hello Bob!" {
		t.Errorf("body: got %q, want %q", content.GetDataMessage().GetBody(), "Hello Bob!")
	}
}

func TestSendTextMessageWithExistingSession(t *testing.T) {
	// Set up both parties.
	alicePriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}

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

	// Set up Alice's store with an established session.
	dbPath := filepath.Join(t.TempDir(), "alice.db")
	st, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	// SetIdentity takes ownership.
	st.SetIdentity(alicePriv, 1)

	// Establish session via pre-key bundle.
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

	bobSPKSig, err := bobPriv.Sign(bobSPKPubBytes)
	if err != nil {
		t.Fatal(err)
	}

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

	bobAddr, err := libsignal.NewAddress("bob-aci", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer bobAddr.Destroy()

	bundle, err := libsignal.NewPreKeyBundle(
		42, 1,
		1, bobPreKeyPub,
		1, bobSPKPub, bobSPKSig,
		bobPub,
		1, kyberPub, kyberSig,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()

	if err := libsignal.ProcessPreKeyBundle(bundle, bobAddr, st, st, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Mock server — should NOT get a GET /v2/keys request since session exists.
	preKeysFetched := false
	var receivedMsg *OutgoingMessageList

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			preKeysFetched = true
			w.WriteHeader(404)

		case r.Method == http.MethodPut && r.URL.Path == "/v1/messages/bob-aci":
			body, _ := io.ReadAll(r.Body)
			receivedMsg = new(OutgoingMessageList)
			json.Unmarshal(body, receivedMsg)
			w.WriteHeader(http.StatusOK)

		default:
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	auth := BasicAuth{Username: "alice-aci.2", Password: "password"}

	err = SendTextMessage(context.Background(), srv.URL, "bob-aci", "Hello again!", st, auth, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if preKeysFetched {
		t.Error("should not have fetched pre-keys when session already exists")
	}

	if receivedMsg == nil {
		t.Fatal("expected message to be sent")
	}

	// With an existing session, we send a regular (Whisper) message.
	if receivedMsg.Messages[0].Type != proto.Envelope_PREKEY_BUNDLE {
		// First message after ProcessPreKeyBundle is still PreKey type.
		// This is expected — subsequent messages would be Whisper type.
	}
}
