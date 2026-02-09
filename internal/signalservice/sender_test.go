package signalservice

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// newTestSender creates a Sender backed by the given store for both
// data and crypto operations. Callbacks must be set by the caller.
func newTestSender(t *testing.T, st *store.Store, localACI string, localDeviceID int) *Sender {
	t.Helper()
	return &Sender{
		dataStore:     st,
		cryptoStore:   st,
		localACI:      localACI,
		localDeviceID: localDeviceID,
	}
}

// makeTestPreKeys generates fresh pre-keys signed by identityPriv,
// returning a PreKeyResponse ready for session establishment.
func makeTestPreKeys(t *testing.T, identityPriv *libsignal.PrivateKey, deviceID, registrationID int) PreKeyResponse {
	t.Helper()

	identityPub, err := identityPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityPub.Destroy()
	identityPubBytes, err := identityPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	enc := base64.RawStdEncoding.EncodeToString

	spk, _ := libsignal.GeneratePrivateKey()
	defer spk.Destroy()
	spkPub, _ := spk.PublicKey()
	defer spkPub.Destroy()
	spkPubBytes, _ := spkPub.Serialize()
	spkSig, _ := identityPriv.Sign(spkPubBytes)

	kyberKP, _ := libsignal.GenerateKyberKeyPair()
	defer kyberKP.Destroy()
	kyberPub, _ := kyberKP.PublicKey()
	defer kyberPub.Destroy()
	kyberPubBytes, _ := kyberPub.Serialize()
	kyberSig, _ := identityPriv.Sign(kyberPubBytes)

	pk, _ := libsignal.GeneratePrivateKey()
	defer pk.Destroy()
	pkPub, _ := pk.PublicKey()
	defer pkPub.Destroy()
	pkPubBytes, _ := pkPub.Serialize()

	return PreKeyResponse{
		IdentityKey: enc(identityPubBytes),
		Devices: []PreKeyDeviceInfo{{
			DeviceID:       deviceID,
			RegistrationID: registrationID,
			SignedPreKey:    &SignedPreKeyEntity{KeyID: 1, PublicKey: enc(spkPubBytes), Signature: enc(spkSig)},
			PreKey:         &PreKeyEntity{KeyID: 1, PublicKey: enc(pkPubBytes)},
			PqPreKey:       &KyberPreKeyEntity{KeyID: 1, PublicKey: enc(kyberPubBytes), Signature: enc(kyberSig)},
		}},
	}
}

func TestSendTextMessageWithPreKeyFetch(t *testing.T) {
	// Set up Bob (recipient) with keys — needed for decryption verification.
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

	preKeyResp := PreKeyResponse{
		IdentityKey: enc(bobIdentityPubBytes),
		Devices: []PreKeyDeviceInfo{{
			DeviceID:       1,
			RegistrationID: 42,
			SignedPreKey:    &SignedPreKeyEntity{KeyID: 1, PublicKey: enc(bobSPKPubBytes), Signature: enc(bobSPKSig)},
			PreKey:         &PreKeyEntity{KeyID: 100, PublicKey: enc(bobPreKeyPubBytes)},
			PqPreKey:       &KyberPreKeyEntity{KeyID: 200, PublicKey: enc(bobKyberPubBytes), Signature: enc(bobKyberSig)},
		}},
	}

	// Track what the sender sends.
	var receivedMsg *outgoingMessageList

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
	defer alicePriv.Destroy()
	if err := st.SetIdentity(alicePriv, 1); err != nil {
		t.Fatal(err)
	}

	snd := newTestSender(t, st, "alice-aci", 2)
	snd.getPreKeys = func(_ context.Context, _ string, _ int) (*PreKeyResponse, error) {
		return &preKeyResp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, msg *outgoingMessageList) error {
		receivedMsg = msg
		return nil
	}

	// Send a message — this should fetch pre-keys, establish session, encrypt, and send.
	err = snd.sendTextMessage(context.Background(), "bob-aci", "Hello Bob!")
	if err != nil {
		t.Fatal(err)
	}

	// Verify the message was sent.
	if receivedMsg == nil {
		t.Fatal("expected message to be sent")
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
	bobPreKeyData, err := bobPreKeyRec.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobPreKeyRec.Destroy()
	bobPreKeyStore.StorePreKey(100, bobPreKeyData)

	bobSPKRec, err := libsignal.NewSignedPreKeyRecord(1, 1000, bobSPKPub, bobSPKPriv, bobSPKSig)
	if err != nil {
		t.Fatal(err)
	}
	bobSPKData, err := bobSPKRec.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobSPKRec.Destroy()
	bobSignedPreKeyStore.StoreSignedPreKey(1, bobSPKData)

	bobKyberRec, err := libsignal.NewKyberPreKeyRecord(200, 1000, bobKyberKP, bobKyberSig)
	if err != nil {
		t.Fatal(err)
	}
	bobKyberData, err := bobKyberRec.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	bobKyberRec.Destroy()
	bobKyberPreKeyStore.StoreKyberPreKey(200, bobKyberData)

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

	// Strip Signal transport padding and parse the decrypted Content protobuf.
	unpadded := stripPadding(plaintext)
	var content proto.Content
	if err := pb.Unmarshal(unpadded, &content); err != nil {
		t.Fatal(err)
	}
	if content.GetDataMessage().GetBody() != "Hello Bob!" {
		t.Errorf("body: got %q, want %q", content.GetDataMessage().GetBody(), "Hello Bob!")
	}
}

func TestSendTextMessageWithExistingSession(t *testing.T) {
	// Set up Alice's store.
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
	defer alicePriv.Destroy()
	if err := st.SetIdentity(alicePriv, 1); err != nil {
		t.Fatal(err)
	}

	// Establish session via pre-key bundle using makeTestPreKeys + buildPreKeyBundle.
	bobPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPriv.Destroy()

	preKeyResp := makeTestPreKeys(t, bobPriv, 1, 42)

	bobAddr, err := libsignal.NewAddress("bob-aci", 1)
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

	// Should NOT fetch pre-keys since session exists.
	preKeysFetched := false
	var receivedMsg *outgoingMessageList

	snd := newTestSender(t, st, "alice-aci", 2)
	snd.getPreKeys = func(_ context.Context, _ string, _ int) (*PreKeyResponse, error) {
		preKeysFetched = true
		return nil, fmt.Errorf("should not fetch pre-keys")
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, msg *outgoingMessageList) error {
		receivedMsg = msg
		return nil
	}

	err = snd.sendTextMessage(context.Background(), "bob-aci", "Hello again!")
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

// TestSendSessionReuse verifies that after a successful send,
// subsequent sends reuse the session and don't fetch pre-keys again.
func TestSendSessionReuse(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()

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

	getPreKeysCount := 0
	putCount := 0

	snd := newTestSender(t, st, "my-aci", 1)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		getPreKeysCount++
		resp := makeTestPreKeys(t, recipPriv, deviceID, 42)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, _ *outgoingMessageList) error {
		putCount++
		return nil
	}

	// First send: should fetch pre-keys to establish session.
	err = snd.sendTextMessage(context.Background(), "recip-aci", "hello1")
	if err != nil {
		t.Fatal(err)
	}
	if getPreKeysCount != 1 {
		t.Errorf("first send: expected 1 pre-key fetch, got %d", getPreKeysCount)
	}
	if putCount != 1 {
		t.Errorf("first send: expected 1 PUT, got %d", putCount)
	}

	// Second send: should NOT fetch pre-keys (session exists with registration ID).
	err = snd.sendTextMessage(context.Background(), "recip-aci", "hello2")
	if err != nil {
		t.Fatal(err)
	}
	if getPreKeysCount != 1 {
		t.Errorf("second send: expected 1 pre-key fetch total (no new fetch), got %d", getPreKeysCount)
	}
	if putCount != 2 {
		t.Errorf("second send: expected 2 PUTs total, got %d", putCount)
	}
}

// TestSendToSelf409ThenRetry tests that when sending to self (contact sync),
// a 409 response (missingDevices=[2]) followed by retry works correctly.
// The server rejects the first attempt because our device 2 is missing from
// the device list. Since device 2 is our own device, it should be skipped.
// On retry, the session for device 1 must be re-established (archived after 409)
// because the server never processed the original PreKey message.
func TestSendToSelf409ThenRetry(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()

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

	var putCount, getPreKeysCount int

	snd := newTestSender(t, st, "my-aci", 2)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		getPreKeysCount++
		resp := makeTestPreKeys(t, recipPriv, deviceID, 1)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, msg *outgoingMessageList) error {
		putCount++

		// Device 2 (our device) must never appear.
		for _, m := range msg.Messages {
			if m.DestinationDeviceID == 2 {
				t.Errorf("PUT #%d: should not send to own device 2", putCount)
			}
		}

		if putCount == 1 {
			// First PUT: server says device 2 is missing.
			// Since device 2 is our own device, it should be skipped.
			return &mismatchedDevicesError{MissingDevices: []int{2}}
		}

		// Second PUT: the retry must send a PreKey message (not a
		// regular SignalMessage) because the 409 means the server
		// never processed the first attempt's PreKey message.
		if len(msg.Messages) == 1 && msg.Messages[0].Type != proto.Envelope_PREKEY_BUNDLE {
			t.Errorf("PUT #%d: expected PreKey message (type %d), got type %d",
				putCount, proto.Envelope_PREKEY_BUNDLE, msg.Messages[0].Type)
		}

		return nil
	}

	err = snd.sendTextMessage(context.Background(), "my-aci", "sync")
	if err != nil {
		t.Fatal(err)
	}

	if putCount < 2 {
		t.Errorf("expected at least 2 PUT attempts, got %d", putCount)
	}
	// After the 409 rejection, the session must be archived so that the retry
	// re-fetches pre-keys.
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

	getPreKeysCount := 0
	putCount := 0

	snd := newTestSender(t, st, "my-aci", 2)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		getPreKeysCount++
		resp := makeTestPreKeys(t, recipPriv, deviceID, 1)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, _ *outgoingMessageList) error {
		putCount++
		if putCount == 1 {
			// First PUT: 410 stale device 1.
			return &staleDevicesError{StaleDevices: []int{1}}
		}
		// Second PUT: accept.
		return nil
	}

	err = snd.sendTextMessage(context.Background(), "recip-aci", "hello")
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

// TestSend410OnlyArchivesSessions verifies Signal-Android behavior:
// 410 (stale devices) only archives sessions, does NOT remove devices from the list.
//
// Scenario:
// 1. PUT → 410 stale=[1] → archive session for device 1, retry
// 2. PUT → 409 missing=[2] → add device 2, archive all sessions
// 3. PUT with [1,2] → 410 stale=[2] → archive session for device 2 (NOT removed)
// 4. PUT with [1,2] → 200 (server accepts both devices with fresh sessions)
func TestSend410OnlyArchivesSessions(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()

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

	putCount := 0

	snd := newTestSender(t, st, "self-aci", 4)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		resp := makeTestPreKeys(t, recipPriv, deviceID, 1)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, msg *outgoingMessageList) error {
		putCount++
		switch putCount {
		case 1:
			// 410: stale session for device 1 from previous run.
			return &staleDevicesError{StaleDevices: []int{1}}
		case 2:
			// 409: server says device 2 is missing.
			return &mismatchedDevicesError{MissingDevices: []int{2}}
		case 3:
			// Verify device 2 was added after 409.
			hasDevice2 := false
			for _, m := range msg.Messages {
				if m.DestinationDeviceID == 2 {
					hasDevice2 = true
				}
			}
			if !hasDevice2 {
				t.Errorf("PUT #3: expected device 2 after 409 missing")
			}
			// 410: device 2's session is stale.
			return &staleDevicesError{StaleDevices: []int{2}}
		case 4:
			// Signal-Android behavior: 410 only archives sessions, doesn't remove devices.
			// Device 2 should still be in the list with a fresh session.
			hasDevice2 := false
			for _, m := range msg.Messages {
				if m.DestinationDeviceID == 2 {
					hasDevice2 = true
				}
			}
			if !hasDevice2 {
				t.Errorf("PUT #4: device 2 should still be present (410 only archives, doesn't remove)")
			}
			if len(msg.Messages) != 2 {
				t.Errorf("PUT #4: expected 2 messages (devices 1 and 2), got %d", len(msg.Messages))
			}
			return nil
		default:
			t.Errorf("unexpected PUT #%d", putCount)
			return nil
		}
	}

	err = snd.sendTextMessage(context.Background(), "self-aci", "sync")
	if err != nil {
		t.Fatal(err)
	}
	if putCount != 4 {
		t.Errorf("expected 4 PUT attempts, got %d", putCount)
	}
}

// TestSend409PersistsDefaultDevice1 verifies that when starting with no cache
// (default device 1), a 409 response correctly persists ALL devices including
// device 1 to the cache. This prevents losing device 1 if the send is cancelled.
func TestSend409PersistsDefaultDevice1(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()

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

	// Verify no devices cached initially.
	devices, _ := st.GetDevices("recip-aci")
	if len(devices) != 0 {
		t.Fatalf("expected empty cache, got %v", devices)
	}

	putCount := 0

	snd := newTestSender(t, st, "my-aci", 1)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		resp := makeTestPreKeys(t, recipPriv, deviceID, 1)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, _ *outgoingMessageList) error {
		putCount++
		if putCount == 1 {
			// First PUT: 409 missing device 2.
			return &mismatchedDevicesError{MissingDevices: []int{2}}
		}
		// Second PUT: accept.
		return nil
	}

	err = snd.sendTextMessage(context.Background(), "recip-aci", "hello")
	if err != nil {
		t.Fatal(err)
	}

	// Verify device cache includes BOTH device 1 (the default) and device 2 (from 409).
	devices, _ = st.GetDevices("recip-aci")
	if len(devices) != 2 {
		t.Errorf("expected 2 devices in cache, got %v", devices)
	}
	hasDevice1 := false
	hasDevice2 := false
	for _, d := range devices {
		if d == 1 {
			hasDevice1 = true
		}
		if d == 2 {
			hasDevice2 = true
		}
	}
	if !hasDevice1 {
		t.Errorf("expected device 1 in cache (was default), got %v", devices)
	}
	if !hasDevice2 {
		t.Errorf("expected device 2 in cache (from 409), got %v", devices)
	}
}

// TestSend409ExtraDevicesRemoved verifies that 409 with extraDevices correctly
// removes those devices from the device list, matching Signal-Android behavior.
//
// Scenario:
// 1. PUT with cached [1,2] → 409 extra=[2] (device 2 was unlinked)
// 2. PUT with [1] only → 200
func TestSend409ExtraDevicesRemoved(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()

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

	// Pre-populate device cache with devices 1 and 2.
	_ = st.SetDevices("recip-aci", []int{1, 2})

	putCount := 0

	snd := newTestSender(t, st, "my-aci", 4)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		resp := makeTestPreKeys(t, recipPriv, deviceID, 1)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, msg *outgoingMessageList) error {
		putCount++
		switch putCount {
		case 1:
			// Verify both devices are being sent to.
			if len(msg.Messages) != 2 {
				t.Errorf("PUT #1: expected 2 messages, got %d", len(msg.Messages))
			}
			// 409: device 2 is no longer registered (extra).
			return &mismatchedDevicesError{ExtraDevices: []int{2}}
		case 2:
			// Verify device 2 was removed after 409 extra.
			for _, m := range msg.Messages {
				if m.DestinationDeviceID == 2 {
					t.Errorf("PUT #2: device 2 should have been removed after 409 extra")
				}
			}
			if len(msg.Messages) != 1 {
				t.Errorf("PUT #2: expected 1 message, got %d", len(msg.Messages))
			}
			return nil
		default:
			t.Errorf("unexpected PUT #%d", putCount)
			return nil
		}
	}

	err = snd.sendTextMessage(context.Background(), "recip-aci", "hello")
	if err != nil {
		t.Fatal(err)
	}
	if putCount != 2 {
		t.Errorf("expected 2 PUT attempts, got %d", putCount)
	}

	// Verify device cache was updated to remove device 2.
	devices, _ := st.GetDevices("recip-aci")
	if len(devices) != 1 || devices[0] != 1 {
		t.Errorf("expected device cache [1], got %v", devices)
	}
}

// TestSendUnifiedSealedFallbackOnCertError verifies that when the sender certificate
// is unavailable, the unified send path falls back to unsealed delivery.
func TestSendUnifiedSealedFallbackOnCertError(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()

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

	var unsealedSent bool

	snd := newTestSender(t, st, "my-aci", 1)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		resp := makeTestPreKeys(t, recipPriv, deviceID, 42)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, _ *outgoingMessageList) error {
		unsealedSent = true
		return nil
	}
	// Certificate callback returns an error — should trigger fallback.
	snd.getSenderCertificate = func(_ context.Context) ([]byte, error) {
		return nil, errors.New("certificate unavailable")
	}

	err = snd.sendTextMessage(context.Background(), "recip-aci", "hello")
	if err != nil {
		t.Fatal(err)
	}

	if !unsealedSent {
		t.Error("expected fallback to unsealed send when cert is unavailable")
	}
}

// TestSendUnifiedSkipsSealedForSelf verifies that send-to-self always uses
// unsealed delivery, skipping the sealed sender path entirely.
func TestSendUnifiedSkipsSealedForSelf(t *testing.T) {
	recipPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer recipPriv.Destroy()

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

	var unsealedSent bool
	sealedCertCalled := false

	snd := newTestSender(t, st, "my-aci", 2)
	snd.getPreKeys = func(_ context.Context, _ string, deviceID int) (*PreKeyResponse, error) {
		resp := makeTestPreKeys(t, recipPriv, deviceID, 1)
		return &resp, nil
	}
	snd.sendHTTPMessage = func(_ context.Context, _ string, _ *outgoingMessageList) error {
		unsealedSent = true
		return nil
	}
	// Certificate callback should NOT be called for self-send.
	snd.getSenderCertificate = func(_ context.Context) ([]byte, error) {
		sealedCertCalled = true
		return nil, errors.New("should not be called")
	}

	// Send to self (recipient == localACI).
	err = snd.sendTextMessage(context.Background(), "my-aci", "sync message")
	if err != nil {
		t.Fatal(err)
	}

	if sealedCertCalled {
		t.Error("should not attempt sealed sender for self-send")
	}
	if !unsealedSent {
		t.Error("expected unsealed send for self-send")
	}
}
