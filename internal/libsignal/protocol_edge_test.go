package libsignal

import (
	"bytes"
	"testing"
	"time"
)

// establishSession sets up a full Alice↔Bob session with completed ratchet
// exchange so subsequent messages in both directions are Whisper type.
func establishSession(t *testing.T) (alice, bob *party, aliceAddr, bobAddr *Address) {
	t.Helper()
	alice = newParty(t, 1)
	bob = newParty(t, 2)

	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatal(err)
	}
	bobAddr, err = NewAddress("+31600000002", 1)
	if err != nil {
		t.Fatal(err)
	}

	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()

	if err := ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now()); err != nil {
		t.Fatal(err)
	}

	// Alice → Bob: PreKey message to establish Bob's session
	ct, err := Encrypt([]byte("init"), bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctBytes, err := ct.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ct.Destroy()
	preKeyMsg, err := DeserializePreKeySignalMessage(ctBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptPreKeyMessage(preKeyMsg, aliceAddr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedPreKeyStore, bob.kyberPreKeyStore)
	preKeyMsg.Destroy()
	if err != nil {
		t.Fatal(err)
	}

	// Bob → Alice: Whisper reply to advance Alice's ratchet
	ct2, err := Encrypt([]byte("ack"), aliceAddr, bob.sessionStore, bob.identityStore, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ct2Bytes, err := ct2.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ct2.Destroy()
	signalMsg, err := DeserializeSignalMessage(ct2Bytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptMessage(signalMsg, bobAddr, alice.sessionStore, alice.identityStore)
	signalMsg.Destroy()
	if err != nil {
		t.Fatal(err)
	}

	return alice, bob, aliceAddr, bobAddr
}

func TestOutOfOrderDecryption(t *testing.T) {
	alice, bob, _, bobAddr := establishSession(t)
	defer bobAddr.Destroy()

	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceAddr.Destroy()

	// Alice sends 3 messages (all Whisper now that session is fully established)
	messages := []string{"msg1", "msg2", "msg3"}
	var ciphertexts [][]byte
	for _, msg := range messages {
		ct, err := Encrypt([]byte(msg), bobAddr, alice.sessionStore, alice.identityStore, time.Now())
		if err != nil {
			t.Fatalf("Encrypt %q: %v", msg, err)
		}
		ctBytes, err := ct.Serialize()
		if err != nil {
			t.Fatalf("Serialize %q: %v", msg, err)
		}
		ct.Destroy()
		ciphertexts = append(ciphertexts, ctBytes)
	}

	// Bob decrypts in reverse order
	for i := len(ciphertexts) - 1; i >= 0; i-- {
		signalMsg, err := DeserializeSignalMessage(ciphertexts[i])
		if err != nil {
			t.Fatalf("DeserializeSignalMessage[%d]: %v", i, err)
		}
		plaintext, err := DecryptMessage(signalMsg, aliceAddr, bob.sessionStore, bob.identityStore)
		signalMsg.Destroy()
		if err != nil {
			t.Fatalf("DecryptMessage[%d]: %v", i, err)
		}
		if !bytes.Equal(plaintext, []byte(messages[i])) {
			t.Fatalf("expected %q, got %q", messages[i], plaintext)
		}
	}
}

func TestReplayProtection(t *testing.T) {
	alice, bob, _, bobAddr := establishSession(t)
	defer bobAddr.Destroy()

	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceAddr.Destroy()

	ct, err := Encrypt([]byte("replay-me"), bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctBytes, err := ct.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ct.Destroy()

	// First decrypt should succeed
	msg1, err := DeserializeSignalMessage(ctBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptMessage(msg1, aliceAddr, bob.sessionStore, bob.identityStore)
	msg1.Destroy()
	if err != nil {
		t.Fatalf("first decrypt should succeed: %v", err)
	}

	// Second decrypt of same ciphertext should fail
	msg2, err := DeserializeSignalMessage(ctBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptMessage(msg2, aliceAddr, bob.sessionStore, bob.identityStore)
	msg2.Destroy()
	if err == nil {
		t.Fatal("expected error on replay, got nil")
	}
}

func TestWrongKeyDecryption(t *testing.T) {
	alice, _, _, bobAddr := establishSession(t)
	defer bobAddr.Destroy()

	// Create an unrelated party (Charlie) with no session to Alice
	charlie := newParty(t, 3)
	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceAddr.Destroy()

	ct, err := Encrypt([]byte("secret"), bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctBytes, err := ct.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ct.Destroy()

	// Charlie tries to decrypt — should fail (no session)
	signalMsg, err := DeserializeSignalMessage(ctBytes)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptMessage(signalMsg, aliceAddr, charlie.sessionStore, charlie.identityStore)
	signalMsg.Destroy()
	if err == nil {
		t.Fatal("expected error decrypting with wrong key, got nil")
	}
}

func TestCorruptedCiphertext(t *testing.T) {
	alice, bob, _, bobAddr := establishSession(t)
	defer bobAddr.Destroy()

	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceAddr.Destroy()

	ct, err := Encrypt([]byte("corrupt-me"), bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctBytes, err := ct.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ct.Destroy()

	// Flip a byte in the middle of the ciphertext
	corrupted := make([]byte, len(ctBytes))
	copy(corrupted, ctBytes)
	corrupted[len(corrupted)/2] ^= 0xff

	signalMsg, err := DeserializeSignalMessage(corrupted)
	if err != nil {
		// Deserialization itself may fail — that's fine
		return
	}
	_, err = DecryptMessage(signalMsg, aliceAddr, bob.sessionStore, bob.identityStore)
	signalMsg.Destroy()
	if err == nil {
		t.Fatal("expected error decrypting corrupted ciphertext, got nil")
	}
}

func TestEmptyPlaintext(t *testing.T) {
	alice, bob, _, bobAddr := establishSession(t)
	defer bobAddr.Destroy()

	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceAddr.Destroy()

	for _, plaintext := range [][]byte{nil, {}} {
		ct, err := Encrypt(plaintext, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
		if err != nil {
			t.Fatalf("Encrypt(%v): %v", plaintext, err)
		}
		ctBytes, err := ct.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		ct.Destroy()

		signalMsg, err := DeserializeSignalMessage(ctBytes)
		if err != nil {
			t.Fatalf("DeserializeSignalMessage: %v", err)
		}
		decrypted, err := DecryptMessage(signalMsg, aliceAddr, bob.sessionStore, bob.identityStore)
		signalMsg.Destroy()
		if err != nil {
			t.Fatalf("DecryptMessage(%v): %v", plaintext, err)
		}
		if len(decrypted) != 0 {
			t.Fatalf("expected empty plaintext, got %q", decrypted)
		}
	}
}

func TestLargePlaintext(t *testing.T) {
	alice, bob, _, bobAddr := establishSession(t)
	defer bobAddr.Destroy()

	aliceAddr, err := NewAddress("+31600000001", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer aliceAddr.Destroy()

	// 10KB message
	large := make([]byte, 10*1024)
	for i := range large {
		large[i] = byte(i % 256)
	}

	ct, err := Encrypt(large, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("Encrypt large: %v", err)
	}
	ctBytes, err := ct.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	ct.Destroy()

	signalMsg, err := DeserializeSignalMessage(ctBytes)
	if err != nil {
		t.Fatalf("DeserializeSignalMessage: %v", err)
	}
	decrypted, err := DecryptMessage(signalMsg, aliceAddr, bob.sessionStore, bob.identityStore)
	signalMsg.Destroy()
	if err != nil {
		t.Fatalf("DecryptMessage large: %v", err)
	}
	if !bytes.Equal(decrypted, large) {
		t.Fatal("large plaintext round-trip mismatch")
	}
}
