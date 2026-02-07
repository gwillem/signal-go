package libsignal

import (
	"bytes"
	"testing"
	"time"
)

// setupParty creates a full set of stores and keys for one party.
type party struct {
	identityKey     *PrivateKey
	identityPub     *PublicKey
	registrationID  uint32
	sessionStore    *MemorySessionStore
	identityStore   *MemoryIdentityKeyStore
	preKeyStore     *MemoryPreKeyStore
	signedPreKeyStore *MemorySignedPreKeyStore
	kyberPreKeyStore  *MemoryKyberPreKeyStore
}

func newParty(t *testing.T, regID uint32) *party {
	t.Helper()
	identityKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	identityPub, err := identityKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	return &party{
		identityKey:       identityKey,
		identityPub:       identityPub,
		registrationID:    regID,
		sessionStore:      NewMemorySessionStore(),
		identityStore:     NewMemoryIdentityKeyStore(identityKey, regID),
		preKeyStore:       NewMemoryPreKeyStore(),
		signedPreKeyStore: NewMemorySignedPreKeyStore(),
		kyberPreKeyStore:  NewMemoryKyberPreKeyStore(),
	}
}

// buildPreKeyBundle creates a pre-key bundle for this party, storing the
// corresponding private keys in the stores.
func (p *party) buildPreKeyBundle(t *testing.T) *PreKeyBundle {
	t.Helper()

	// EC pre-key
	preKeyPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey (prekey): %v", err)
	}
	preKeyPub, err := preKeyPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey (prekey): %v", err)
	}
	preKeyRec, err := NewPreKeyRecord(1, preKeyPub, preKeyPriv)
	if err != nil {
		t.Fatalf("NewPreKeyRecord: %v", err)
	}
	preKeyData, err := preKeyRec.Serialize()
	if err != nil {
		t.Fatalf("Serialize prekey: %v", err)
	}
	preKeyRec.Destroy()
	if err := p.preKeyStore.StorePreKey(1, preKeyData); err != nil {
		t.Fatalf("StorePreKey: %v", err)
	}

	// Signed pre-key
	signedPreKeyPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey (signed): %v", err)
	}
	signedPreKeyPub, err := signedPreKeyPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey (signed): %v", err)
	}
	signedPubBytes, err := signedPreKeyPub.Serialize()
	if err != nil {
		t.Fatalf("Serialize signed pub: %v", err)
	}
	signedSig, err := p.identityKey.Sign(signedPubBytes)
	if err != nil {
		t.Fatalf("Sign signed prekey: %v", err)
	}
	signedPreKeyRec, err := NewSignedPreKeyRecord(2, uint64(time.Now().UnixMilli()), signedPreKeyPub, signedPreKeyPriv, signedSig)
	if err != nil {
		t.Fatalf("NewSignedPreKeyRecord: %v", err)
	}
	signedPreKeyData, err := signedPreKeyRec.Serialize()
	if err != nil {
		t.Fatalf("Serialize signed prekey: %v", err)
	}
	signedPreKeyRec.Destroy()
	if err := p.signedPreKeyStore.StoreSignedPreKey(2, signedPreKeyData); err != nil {
		t.Fatalf("StoreSignedPreKey: %v", err)
	}

	// Kyber pre-key
	kyberKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}
	kyberPub, err := kyberKP.PublicKey()
	if err != nil {
		t.Fatalf("KyberPublicKey: %v", err)
	}
	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatalf("Serialize kyber pub: %v", err)
	}
	kyberSig, err := p.identityKey.Sign(kyberPubBytes)
	if err != nil {
		t.Fatalf("Sign kyber: %v", err)
	}
	kyberRec, err := NewKyberPreKeyRecord(3, uint64(time.Now().UnixMilli()), kyberKP, kyberSig)
	if err != nil {
		t.Fatalf("NewKyberPreKeyRecord: %v", err)
	}
	kyberData, err := kyberRec.Serialize()
	if err != nil {
		t.Fatalf("Serialize kyber prekey: %v", err)
	}
	kyberRec.Destroy()
	if err := p.kyberPreKeyStore.StoreKyberPreKey(3, kyberData); err != nil {
		t.Fatalf("StoreKyberPreKey: %v", err)
	}

	bundle, err := NewPreKeyBundle(
		p.registrationID, 1, // regID, deviceID
		1, preKeyPub,        // preKeyID, preKey
		2, signedPreKeyPub, signedSig, // signedPreKeyID, signedPreKey, sig
		p.identityPub,     // identity key
		3, kyberPub, kyberSig, // kyberPreKeyID, kyberPreKey, sig
	)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}
	return bundle
}

// E1: ProcessPreKeyBundle runs without error
func TestProcessPreKeyBundle(t *testing.T) {
	alice := newParty(t, 1)
	bob := newParty(t, 2)

	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()

	bobAddr, err := NewAddress("+31600000002", 1)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer bobAddr.Destroy()

	err = ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}
}

// E2: After processing bundle, session store contains a session for Bob
func TestProcessPreKeyBundleCreatesSession(t *testing.T) {
	alice := newParty(t, 1)
	bob := newParty(t, 2)

	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()

	bobAddr, err := NewAddress("+31600000002", 1)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer bobAddr.Destroy()

	err = ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}

	// Verify session was stored
	session, err := alice.sessionStore.LoadSession(bobAddr)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if session == nil {
		t.Fatal("expected session to be stored after ProcessPreKeyBundle")
	}
	defer session.Destroy()
}

// F1-F4: Full encryption/decryption round-trip
func TestEncryptDecryptRoundTrip(t *testing.T) {
	alice := newParty(t, 1)
	bob := newParty(t, 2)

	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatalf("NewAddress alice: %v", err)
	}
	defer aliceAddr.Destroy()

	bobAddr, err := NewAddress("+31600000002", 1)
	if err != nil {
		t.Fatalf("NewAddress bob: %v", err)
	}
	defer bobAddr.Destroy()

	// Alice processes Bob's bundle
	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()

	err = ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}

	// F1: Alice encrypts "hello" → PreKeySignalMessage
	ciphertext, err := Encrypt([]byte("hello"), bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	defer ciphertext.Destroy()

	msgType, err := ciphertext.Type()
	if err != nil {
		t.Fatalf("Type: %v", err)
	}
	if msgType != CiphertextMessageTypePreKey {
		t.Fatalf("expected PreKey message type (%d), got %d", CiphertextMessageTypePreKey, msgType)
	}

	ciphertextBytes, err := ciphertext.Serialize()
	if err != nil {
		t.Fatalf("Serialize ciphertext: %v", err)
	}

	// F2: Bob decrypts → "hello"
	preKeyMsg, err := DeserializePreKeySignalMessage(ciphertextBytes)
	if err != nil {
		t.Fatalf("DeserializePreKeySignalMessage: %v", err)
	}
	defer preKeyMsg.Destroy()

	plaintext, err := DecryptPreKeyMessage(preKeyMsg, aliceAddr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedPreKeyStore, bob.kyberPreKeyStore)
	if err != nil {
		t.Fatalf("DecryptPreKeyMessage: %v", err)
	}
	if !bytes.Equal(plaintext, []byte("hello")) {
		t.Fatalf("expected 'hello', got %q", plaintext)
	}

	// F3: Bob replies — encrypts "world" → SignalMessage (ratchet advanced)
	ciphertext2, err := Encrypt([]byte("world"), aliceAddr, bob.sessionStore, bob.identityStore, time.Now())
	if err != nil {
		t.Fatalf("Encrypt reply: %v", err)
	}
	defer ciphertext2.Destroy()

	msgType2, err := ciphertext2.Type()
	if err != nil {
		t.Fatalf("Type reply: %v", err)
	}
	if msgType2 != CiphertextMessageTypeWhisper {
		t.Fatalf("expected Whisper message type (%d), got %d", CiphertextMessageTypeWhisper, msgType2)
	}

	ciphertext2Bytes, err := ciphertext2.Serialize()
	if err != nil {
		t.Fatalf("Serialize reply: %v", err)
	}

	// F4: Alice decrypts → "world"
	signalMsg, err := DeserializeSignalMessage(ciphertext2Bytes)
	if err != nil {
		t.Fatalf("DeserializeSignalMessage: %v", err)
	}
	defer signalMsg.Destroy()

	plaintext2, err := DecryptMessage(signalMsg, bobAddr, alice.sessionStore, alice.identityStore)
	if err != nil {
		t.Fatalf("DecryptMessage: %v", err)
	}
	if !bytes.Equal(plaintext2, []byte("world")) {
		t.Fatalf("expected 'world', got %q", plaintext2)
	}
}

// F5: Full round-trip test — multi-message exchange
func TestMultiMessageExchange(t *testing.T) {
	alice := newParty(t, 1)
	bob := newParty(t, 2)

	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatalf("NewAddress alice: %v", err)
	}
	defer aliceAddr.Destroy()

	bobAddr, err := NewAddress("+31600000002", 1)
	if err != nil {
		t.Fatalf("NewAddress bob: %v", err)
	}
	defer bobAddr.Destroy()

	// Alice processes Bob's bundle
	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()

	err = ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}

	// Helper: encrypt from sender to receiver
	sendAndReceive := func(msg string, senderAddr, receiverAddr *Address,
		sender, receiver *party, isFirst bool) {
		t.Helper()

		ct, err := Encrypt([]byte(msg), receiverAddr, sender.sessionStore, sender.identityStore, time.Now())
		if err != nil {
			t.Fatalf("Encrypt %q: %v", msg, err)
		}
		defer ct.Destroy()

		ctBytes, err := ct.Serialize()
		if err != nil {
			t.Fatalf("Serialize %q: %v", msg, err)
		}

		var plaintext []byte
		if isFirst {
			preKeyMsg, err := DeserializePreKeySignalMessage(ctBytes)
			if err != nil {
				t.Fatalf("DeserializePreKeySignalMessage %q: %v", msg, err)
			}
			defer preKeyMsg.Destroy()
			plaintext, err = DecryptPreKeyMessage(preKeyMsg, senderAddr,
				receiver.sessionStore, receiver.identityStore,
				receiver.preKeyStore, receiver.signedPreKeyStore, receiver.kyberPreKeyStore)
			if err != nil {
				t.Fatalf("DecryptPreKeyMessage %q: %v", msg, err)
			}
		} else {
			signalMsg, err := DeserializeSignalMessage(ctBytes)
			if err != nil {
				t.Fatalf("DeserializeSignalMessage %q: %v", msg, err)
			}
			defer signalMsg.Destroy()
			plaintext, err = DecryptMessage(signalMsg, senderAddr,
				receiver.sessionStore, receiver.identityStore)
			if err != nil {
				t.Fatalf("DecryptMessage %q: %v", msg, err)
			}
		}

		if !bytes.Equal(plaintext, []byte(msg)) {
			t.Fatalf("expected %q, got %q", msg, plaintext)
		}
	}

	// Alice → Bob (first message, PreKey)
	sendAndReceive("message 1", aliceAddr, bobAddr, alice, bob, true)
	// Bob → Alice (Whisper)
	sendAndReceive("message 2", bobAddr, aliceAddr, bob, alice, false)
	// Alice → Bob (Whisper)
	sendAndReceive("message 3", aliceAddr, bobAddr, alice, bob, false)
	// Bob → Alice (Whisper)
	sendAndReceive("message 4", bobAddr, aliceAddr, bob, alice, false)
}
