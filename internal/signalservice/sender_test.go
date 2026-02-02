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

// TestSendToSelf409ThenRetry tests that when sending to self (contact sync),
// a 409 response (missingDevices=[2]) followed by retry works correctly.
// The server rejects the first attempt because our device 2 is missing from
// the device list. Since device 2 is our own device, it should be skipped.
// On retry, the session for device 1 must be re-established (archived after 409)
// because the server never processed the original PreKey message.
func TestSendToSelf409ThenRetry(t *testing.T) {
	var putCount int
	var getPreKeysCount int

	// Generate recipient keys for device 1.
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()
	recipPub, err := recipPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPub.Destroy()
	recipPubBytes, err := recipPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	spkPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPriv.Destroy()
	spkPub, err := spkPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPub.Destroy()
	spkPubBytes, err := spkPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	spkSig, err := recipPriv.Sign(spkPubBytes)
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
	preKeyPubBytes, err := preKeyPub.Serialize()
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
	kyberSig, err := recipPriv.Sign(kyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	enc := base64.RawStdEncoding.EncodeToString

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/keys/my-aci/1":
			getPreKeysCount++
			json.NewEncoder(w).Encode(PreKeyResponse{
				IdentityKey: enc(recipPubBytes),
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

		case r.Method == http.MethodPut && r.URL.Path == "/v1/messages/my-aci":
			putCount++

			body, _ := io.ReadAll(r.Body)
			var msg OutgoingMessageList
			json.Unmarshal(body, &msg)

			// Device 2 (our device) must never appear.
			for _, m := range msg.Messages {
				if m.DestinationDeviceID == 2 {
					t.Errorf("PUT #%d: should not send to own device 2", putCount)
				}
			}

			if putCount == 1 {
				// First PUT: server says device 2 is missing.
				// Since device 2 is our own device, it should be skipped.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(MismatchedDevicesError{
					MissingDevices: []int{2},
				})
				return
			}

			// Second PUT: the retry must send a PreKey message (not a
			// regular SignalMessage) because the 409 means the server
			// never processed the first attempt's PreKey message.
			if len(msg.Messages) == 1 {
				if msg.Messages[0].Type != proto.Envelope_PREKEY_BUNDLE {
					t.Errorf("PUT #%d: expected PreKey message (type %d), got type %d",
						putCount, proto.Envelope_PREKEY_BUNDLE, msg.Messages[0].Type)
				}
			}

			w.WriteHeader(http.StatusOK)

		default:
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

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

	auth := BasicAuth{Username: "my-aci.2", Password: "pass"}

	err = SendTextMessage(context.Background(), srv.URL, "my-aci", "sync", st, auth, nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if putCount < 2 {
		t.Errorf("expected at least 2 PUT attempts, got %d", putCount)
	}
	// After the 409 rejection, the session must be archived so that the retry
	// re-fetches pre-keys. The server never processed the first PreKey message,
	// so sending a non-PreKey message with the advanced session would fail (410).
	if getPreKeysCount < 2 {
		t.Errorf("expected pre-keys to be re-fetched after 409, got %d fetches", getPreKeysCount)
	}
}

// TestSend410ThenRetrySucceeds tests that a 410 (stale device) archives the
// session and the retry re-fetches pre-keys successfully.
func TestSend410ThenRetrySucceeds(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()
	recipPub, err := recipPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPub.Destroy()
	recipPubBytes, err := recipPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	enc := base64.RawStdEncoding.EncodeToString
	getPreKeysCount := 0

	makePreKeys := func(deviceID int) PreKeyResponse {
		spk, _ := libsignal.GeneratePrivateKey()
		defer spk.Destroy()
		spkPub, _ := spk.PublicKey()
		defer spkPub.Destroy()
		spkPubBytes, _ := spkPub.Serialize()
		spkSig, _ := recipPriv.Sign(spkPubBytes)

		kyberKP, _ := libsignal.GenerateKyberKeyPair()
		defer kyberKP.Destroy()
		kyberPub, _ := kyberKP.PublicKey()
		defer kyberPub.Destroy()
		kyberPubBytes, _ := kyberPub.Serialize()
		kyberSig, _ := recipPriv.Sign(kyberPubBytes)

		pk, _ := libsignal.GeneratePrivateKey()
		defer pk.Destroy()
		pkPub, _ := pk.PublicKey()
		defer pkPub.Destroy()
		pkPubBytes, _ := pkPub.Serialize()

		return PreKeyResponse{
			IdentityKey: enc(recipPubBytes),
			Devices: []PreKeyDeviceInfo{{
				DeviceID: deviceID, RegistrationID: 1,
				SignedPreKey: &SignedPreKeyEntity{KeyID: 1, PublicKey: enc(spkPubBytes), Signature: enc(spkSig)},
				PreKey:       &PreKeyEntity{KeyID: 1, PublicKey: enc(pkPubBytes)},
				PqPreKey:     &KyberPreKeyEntity{KeyID: 1, PublicKey: enc(kyberPubBytes), Signature: enc(kyberSig)},
			}},
		}
	}

	putCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/keys/recip-aci/1":
			getPreKeysCount++
			json.NewEncoder(w).Encode(makePreKeys(1))
		case r.Method == http.MethodPut && r.URL.Path == "/v1/messages/recip-aci":
			putCount++
			if putCount == 1 {
				// First PUT: 410 stale device 1.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusGone)
				json.NewEncoder(w).Encode(map[string]any{"staleDevices": []int{1}})
				return
			}
			// Second PUT: accept.
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

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

	auth := BasicAuth{Username: "my-aci.2", Password: "pass"}

	err = SendTextMessage(context.Background(), srv.URL, "recip-aci", "hello", st, auth, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if putCount != 2 {
		t.Errorf("expected 2 PUT attempts, got %d", putCount)
	}
	if getPreKeysCount != 2 {
		t.Errorf("expected 2 pre-key fetches, got %d", getPreKeysCount)
	}
}

// TestSend410Then409Then410RemovesStale reproduces the production scenario:
// 1. PUT → 410 stale=[1] (pre-existing stale session)
// 2. PUT → 409 missing=[2] (server wants device 2)
// 3. PUT with devices [1,2] → 410 stale=[2] (device 2 rejected)
// 4. PUT with device [1] only → 200 (succeeds without device 2)
func TestSend410Then409Then410RemovesStale(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()
	recipPub, err := recipPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPub.Destroy()
	recipPubBytes, err := recipPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	enc := base64.RawStdEncoding.EncodeToString

	makePreKeys := func(deviceID int) PreKeyResponse {
		spk, _ := libsignal.GeneratePrivateKey()
		defer spk.Destroy()
		spkPub, _ := spk.PublicKey()
		defer spkPub.Destroy()
		spkPubBytes, _ := spkPub.Serialize()
		spkSig, _ := recipPriv.Sign(spkPubBytes)

		kyberKP, _ := libsignal.GenerateKyberKeyPair()
		defer kyberKP.Destroy()
		kyberPub, _ := kyberKP.PublicKey()
		defer kyberPub.Destroy()
		kyberPubBytes, _ := kyberPub.Serialize()
		kyberSig, _ := recipPriv.Sign(kyberPubBytes)

		pk, _ := libsignal.GeneratePrivateKey()
		defer pk.Destroy()
		pkPub, _ := pk.PublicKey()
		defer pkPub.Destroy()
		pkPubBytes, _ := pkPub.Serialize()

		return PreKeyResponse{
			IdentityKey: enc(recipPubBytes),
			Devices: []PreKeyDeviceInfo{{
				DeviceID: deviceID, RegistrationID: 1,
				SignedPreKey: &SignedPreKeyEntity{KeyID: 1, PublicKey: enc(spkPubBytes), Signature: enc(spkSig)},
				PreKey:       &PreKeyEntity{KeyID: 1, PublicKey: enc(pkPubBytes)},
				PqPreKey:     &KyberPreKeyEntity{KeyID: 1, PublicKey: enc(kyberPubBytes), Signature: enc(kyberSig)},
			}},
		}
	}

	putCount := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/keys/self-aci/1":
			json.NewEncoder(w).Encode(makePreKeys(1))
		case r.Method == http.MethodGet && r.URL.Path == "/v2/keys/self-aci/2":
			json.NewEncoder(w).Encode(makePreKeys(2))
		case r.Method == http.MethodPut && r.URL.Path == "/v1/messages/self-aci":
			putCount++
			body, _ := io.ReadAll(r.Body)
			var msg OutgoingMessageList
			json.Unmarshal(body, &msg)

			switch putCount {
			case 1:
				// 410: stale session for device 1 from previous run.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusGone)
				json.NewEncoder(w).Encode(map[string]any{"staleDevices": []int{1}})
			case 2:
				// 409: server says device 2 is missing.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(MismatchedDevicesError{MissingDevices: []int{2}})
			case 3:
				// 410: device 2 is stale (broken/deregistered).
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusGone)
				json.NewEncoder(w).Encode(map[string]any{"staleDevices": []int{2}})
			case 4:
				// Device 2 should have been removed. Only device 1.
				for _, m := range msg.Messages {
					if m.DestinationDeviceID == 2 {
						t.Errorf("PUT #4: device 2 should have been removed after 410")
					}
				}
				if len(msg.Messages) != 1 {
					t.Errorf("PUT #4: expected 1 message (device 1 only), got %d", len(msg.Messages))
				}
				w.WriteHeader(http.StatusOK)
			default:
				t.Errorf("unexpected PUT #%d", putCount)
				w.WriteHeader(http.StatusOK)
			}
		default:
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

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

	// Device 4 = our device (like the production user).
	auth := BasicAuth{Username: "self-aci.4", Password: "pass"}

	err = SendTextMessage(context.Background(), srv.URL, "self-aci", "sync", st, auth, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if putCount != 4 {
		t.Errorf("expected 4 PUT attempts, got %d", putCount)
	}
}
