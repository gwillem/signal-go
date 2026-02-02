package libsignal

import (
	"testing"
)

// TestSealedSenderDecryptInvalidCiphertext verifies that SealedSenderDecrypt
// returns a proper error when given invalid ciphertext (not a panic/crash).
func TestSealedSenderDecryptInvalidCiphertext(t *testing.T) {
	bob := newParty(t, 2)

	// Generate a trust root key (in production this is Signal's server key).
	trustRootPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	trustRootPub, err := trustRootPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	defer trustRootPub.Destroy()

	// Call with garbage ciphertext — should return an error, not crash.
	_, err = SealedSenderDecrypt(
		[]byte("not-valid-sealed-sender-ciphertext"),
		trustRootPub,
		1000,
		"",
		"bob-uuid",
		1,
		bob.sessionStore,
		bob.identityStore,
		bob.preKeyStore,
		bob.signedPreKeyStore,
	)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// TestSealedSenderDecryptToUSMCInvalidCiphertext verifies that the two-step
// approach also returns proper errors for invalid ciphertext.
func TestSealedSenderDecryptToUSMCInvalidCiphertext(t *testing.T) {
	bob := newParty(t, 2)

	_, err := SealedSenderDecryptToUSMC(
		[]byte("not-valid-sealed-sender-ciphertext"),
		bob.identityStore,
	)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext, got nil")
	}
	t.Logf("got expected error: %v", err)
}
