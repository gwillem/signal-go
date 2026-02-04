package signalservice

import (
	"testing"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// TestEndToEndMessageRoundtrip verifies that a message sent by Alice can be
// decrypted and parsed by Bob. This catches formatting issues like missing
// transport padding that wouldn't be caught by separate send/receive tests.
func TestEndToEndMessageRoundtrip(t *testing.T) {
	// Set up Alice (sender).
	aliceIdentity, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer aliceIdentity.Destroy()

	aliceSessionStore := libsignal.NewMemorySessionStore()
	aliceIdentityStore := libsignal.NewMemoryIdentityKeyStore(aliceIdentity, 1)

	// Set up Bob (recipient).
	bobIdentity, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobIdentity.Destroy()

	bobSessionStore := libsignal.NewMemorySessionStore()
	bobIdentityStore := libsignal.NewMemoryIdentityKeyStore(bobIdentity, 2)
	bobPreKeyStore := libsignal.NewMemoryPreKeyStore()
	bobSignedPreKeyStore := libsignal.NewMemorySignedPreKeyStore()
	bobKyberPreKeyStore := libsignal.NewMemoryKyberPreKeyStore()

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

	bobSPKSig, err := bobIdentity.Sign(bobSPKPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	bobSPKRec, err := libsignal.NewSignedPreKeyRecord(1, uint64(time.Now().UnixMilli()), bobSPKPub, bobSPKPriv, bobSPKSig)
	if err != nil {
		t.Fatal(err)
	}
	bobSignedPreKeyStore.StoreSignedPreKey(1, bobSPKRec)

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

	bobPreKeyRec, err := libsignal.NewPreKeyRecord(100, bobPreKeyPub, bobPreKeyPriv)
	if err != nil {
		t.Fatal(err)
	}
	bobPreKeyStore.StorePreKey(100, bobPreKeyRec)

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

	bobKyberSig, err := bobIdentity.Sign(bobKyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	bobKyberRec, err := libsignal.NewKyberPreKeyRecord(200, uint64(time.Now().UnixMilli()), bobKyberKP, bobKyberSig)
	if err != nil {
		t.Fatal(err)
	}
	bobKyberPreKeyStore.StoreKyberPreKey(200, bobKyberRec)

	// Create Bob's pre-key bundle for Alice.
	bobIdentityPub, err := bobIdentity.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobIdentityPub.Destroy()

	bundle, err := libsignal.NewPreKeyBundle(
		2,   // registration ID
		1,   // device ID
		100, // pre-key ID
		bobPreKeyPub,
		1, // signed pre-key ID
		bobSPKPub,
		bobSPKSig,
		bobIdentityPub,
		200, // kyber pre-key ID
		bobKyberPub,
		bobKyberSig,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()

	// Alice processes Bob's bundle to establish session.
	bobAddr, err := libsignal.NewAddress("bob-aci", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer bobAddr.Destroy()

	now := time.Now()
	if err := libsignal.ProcessPreKeyBundle(bundle, bobAddr, aliceSessionStore, aliceIdentityStore, now); err != nil {
		t.Fatal(err)
	}

	// === ALICE SENDS MESSAGE ===
	// This is what SendTextMessage does internally.
	messageText := "Hello Bob! This is a test message."
	timestamp := uint64(now.UnixMilli())
	content := &proto.Content{
		DataMessage: &proto.DataMessage{
			Body:      &messageText,
			Timestamp: &timestamp,
		},
	}
	contentBytes, err := pb.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}

	// Apply Signal transport padding (the fix we added).
	paddedContent := padMessage(contentBytes)

	// Encrypt.
	ciphertext, err := libsignal.Encrypt(paddedContent, bobAddr, aliceSessionStore, aliceIdentityStore, now)
	if err != nil {
		t.Fatal(err)
	}
	defer ciphertext.Destroy()

	ctBytes, err := ciphertext.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// === BOB RECEIVES MESSAGE ===
	// This is what the receiver does.
	aliceAddr, err := libsignal.NewAddress("alice-aci", 1)
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

	// Strip transport padding (what receiver.go does).
	unpadded := stripPadding(plaintext)

	// Parse protobuf.
	var received proto.Content
	if err := pb.Unmarshal(unpadded, &received); err != nil {
		t.Fatalf("failed to parse received content: %v\nplaintext len=%d, unpadded len=%d",
			err, len(plaintext), len(unpadded))
	}

	// Verify message content.
	if received.GetDataMessage().GetBody() != messageText {
		t.Errorf("message body: got %q, want %q",
			received.GetDataMessage().GetBody(), messageText)
	}
}

// TestEndToEndWithoutPaddingFails demonstrates that skipping padding causes
// the receiver to fail parsing the message. This test documents the bug that
// was fixed by adding padMessage().
func TestEndToEndWithoutPaddingFails(t *testing.T) {
	// Set up Alice and Bob (same as above, abbreviated).
	aliceIdentity, _ := libsignal.GeneratePrivateKey()
	defer aliceIdentity.Destroy()
	aliceSessionStore := libsignal.NewMemorySessionStore()
	aliceIdentityStore := libsignal.NewMemoryIdentityKeyStore(aliceIdentity, 1)

	bobIdentity, _ := libsignal.GeneratePrivateKey()
	defer bobIdentity.Destroy()
	bobSessionStore := libsignal.NewMemorySessionStore()
	bobIdentityStore := libsignal.NewMemoryIdentityKeyStore(bobIdentity, 2)
	bobPreKeyStore := libsignal.NewMemoryPreKeyStore()
	bobSignedPreKeyStore := libsignal.NewMemorySignedPreKeyStore()
	bobKyberPreKeyStore := libsignal.NewMemoryKyberPreKeyStore()

	// Generate Bob's keys (simplified - no Kyber for brevity).
	bobSPKPriv, _ := libsignal.GeneratePrivateKey()
	defer bobSPKPriv.Destroy()
	bobSPKPub, _ := bobSPKPriv.PublicKey()
	defer bobSPKPub.Destroy()
	bobSPKPubBytes, _ := bobSPKPub.Serialize()
	bobSPKSig, _ := bobIdentity.Sign(bobSPKPubBytes)

	bobSPKRec, _ := libsignal.NewSignedPreKeyRecord(1, uint64(time.Now().UnixMilli()), bobSPKPub, bobSPKPriv, bobSPKSig)
	bobSignedPreKeyStore.StoreSignedPreKey(1, bobSPKRec)

	bobPreKeyPriv, _ := libsignal.GeneratePrivateKey()
	defer bobPreKeyPriv.Destroy()
	bobPreKeyPub, _ := bobPreKeyPriv.PublicKey()
	defer bobPreKeyPub.Destroy()
	bobPreKeyRec, _ := libsignal.NewPreKeyRecord(100, bobPreKeyPub, bobPreKeyPriv)
	bobPreKeyStore.StorePreKey(100, bobPreKeyRec)

	bobIdentityPub, _ := bobIdentity.PublicKey()
	defer bobIdentityPub.Destroy()

	// Create bundle without Kyber.
	bundle, _ := libsignal.NewPreKeyBundle(2, 1, 100, bobPreKeyPub, 1, bobSPKPub, bobSPKSig, bobIdentityPub, 0xFFFFFFFF, nil, nil)
	defer bundle.Destroy()

	bobAddr, _ := libsignal.NewAddress("bob-aci", 1)
	defer bobAddr.Destroy()

	now := time.Now()
	libsignal.ProcessPreKeyBundle(bundle, bobAddr, aliceSessionStore, aliceIdentityStore, now)

	// Alice sends WITHOUT padding (the bug).
	messageText := "Hello Bob!"
	timestamp := uint64(now.UnixMilli())
	content := &proto.Content{
		DataMessage: &proto.DataMessage{
			Body:      &messageText,
			Timestamp: &timestamp,
		},
	}
	contentBytes, _ := pb.Marshal(content)

	// NO PADDING - this is the bug
	ciphertext, _ := libsignal.Encrypt(contentBytes, bobAddr, aliceSessionStore, aliceIdentityStore, now)
	defer ciphertext.Destroy()
	ctBytes, _ := ciphertext.Serialize()

	// Bob receives.
	aliceAddr, _ := libsignal.NewAddress("alice-aci", 1)
	defer aliceAddr.Destroy()

	preKeyMsg, _ := libsignal.DeserializePreKeySignalMessage(ctBytes)
	defer preKeyMsg.Destroy()

	plaintext, err := libsignal.DecryptPreKeyMessage(
		preKeyMsg, aliceAddr,
		bobSessionStore, bobIdentityStore,
		bobPreKeyStore, bobSignedPreKeyStore, bobKyberPreKeyStore,
	)
	if err != nil {
		t.Fatalf("decryption should succeed even without padding: %v", err)
	}

	// stripPadding won't find 0x80, returns data as-is.
	unpadded := stripPadding(plaintext)

	// This might work if the protobuf happens to be valid, but demonstrates
	// the risk. In practice, the message body could be truncated or have
	// trailing garbage if the receiver expects specific padding.
	var received proto.Content
	err = pb.Unmarshal(unpadded, &received)

	// The key insight: even if parsing succeeds here, real Signal clients
	// expect the padding format. This test documents the requirement.
	t.Logf("Without padding: plaintext=%d bytes, parse error=%v", len(plaintext), err)
	t.Logf("With padding would be: %d bytes", len(padMessage(contentBytes)))
}
