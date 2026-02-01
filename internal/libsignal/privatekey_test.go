package libsignal

import (
	"bytes"
	"testing"
)

func TestGeneratePrivateKey(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	defer key.Destroy()

	data, err := key.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(data) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(data))
	}
}

func TestPrivateKeySerializeRoundTrip(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	defer key.Destroy()

	data, err := key.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	key2, err := DeserializePrivateKey(data)
	if err != nil {
		t.Fatalf("DeserializePrivateKey: %v", err)
	}
	defer key2.Destroy()

	data2, err := key2.Serialize()
	if err != nil {
		t.Fatalf("Serialize key2: %v", err)
	}

	if len(data) != len(data2) {
		t.Fatalf("length mismatch: %d vs %d", len(data), len(data2))
	}
	if !bytes.Equal(data, data2) {
		t.Fatal("private key round-trip mismatch")
	}
}

// B5: PrivateKey.Sign produces 64-byte signature
func TestPrivateKeySign(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	defer key.Destroy()

	sig, err := key.Sign([]byte("test message"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("expected 64-byte signature, got %d", len(sig))
	}
}

// B6: PublicKey.Verify returns true for matching signature
func TestPublicKeyVerify(t *testing.T) {
	key, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	defer key.Destroy()

	msg := []byte("test message")
	sig, err := key.Sign(msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	pub, err := key.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	defer pub.Destroy()

	ok, err := pub.Verify(msg, sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !ok {
		t.Fatal("signature should verify")
	}

	// Tampered message should not verify
	ok, err = pub.Verify([]byte("wrong message"), sig)
	if err != nil {
		t.Fatalf("Verify tampered: %v", err)
	}
	if ok {
		t.Fatal("tampered message should not verify")
	}
}

// B7: PrivateKey.Agree produces 32-byte shared secret
func TestPrivateKeyAgree(t *testing.T) {
	alice, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey alice: %v", err)
	}
	defer alice.Destroy()

	bob, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey bob: %v", err)
	}
	defer bob.Destroy()

	alicePub, err := alice.PublicKey()
	if err != nil {
		t.Fatalf("alice PublicKey: %v", err)
	}
	defer alicePub.Destroy()

	bobPub, err := bob.PublicKey()
	if err != nil {
		t.Fatalf("bob PublicKey: %v", err)
	}
	defer bobPub.Destroy()

	secret1, err := alice.Agree(bobPub)
	if err != nil {
		t.Fatalf("alice.Agree: %v", err)
	}
	if len(secret1) != 32 {
		t.Fatalf("expected 32-byte secret, got %d", len(secret1))
	}

	secret2, err := bob.Agree(alicePub)
	if err != nil {
		t.Fatalf("bob.Agree: %v", err)
	}

	if !bytes.Equal(secret1, secret2) {
		t.Fatal("shared secrets should match")
	}
}
