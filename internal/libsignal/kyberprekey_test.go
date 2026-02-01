package libsignal

import (
	"bytes"
	"testing"
)

// C4: Generate Kyber key pair
func TestKyberKeyPairGenerate(t *testing.T) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}
	defer kp.Destroy()

	pub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	defer pub.Destroy()

	data, err := pub.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("Kyber public key should not be empty")
	}
}

// C5: Kyber pre-key record serialize/deserialize round-trip
func TestKyberPreKeyRecordRoundTrip(t *testing.T) {
	// Generate a Kyber key pair
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}
	defer kp.Destroy()

	// Sign the Kyber public key with an identity key
	identityKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	defer identityKey.Destroy()

	kyberPub, err := kp.PublicKey()
	if err != nil {
		t.Fatalf("KyberPublicKey: %v", err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatalf("Serialize kyber pub: %v", err)
	}

	sig, err := identityKey.Sign(kyberPubBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rec, err := NewKyberPreKeyRecord(99, 2000000, kp, sig)
	if err != nil {
		t.Fatalf("NewKyberPreKeyRecord: %v", err)
	}
	defer rec.Destroy()

	id, err := rec.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if id != 99 {
		t.Fatalf("expected ID 99, got %d", id)
	}

	data, err := rec.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	rec2, err := DeserializeKyberPreKeyRecord(data)
	if err != nil {
		t.Fatalf("DeserializeKyberPreKeyRecord: %v", err)
	}
	defer rec2.Destroy()

	data2, err := rec2.Serialize()
	if err != nil {
		t.Fatalf("Serialize rec2: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Fatal("Kyber pre-key record round-trip mismatch")
	}
}

func TestKyberPreKeyRecordSignature(t *testing.T) {
	kp, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer kp.Destroy()

	identityKey, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityKey.Destroy()

	kyberPub, err := kp.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := identityKey.Sign(kyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := NewKyberPreKeyRecord(77, 2000000, kp, sig)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Destroy()

	gotSig, err := rec.Signature()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, gotSig) {
		t.Fatal("signature mismatch")
	}

	// Verify signature is valid
	identityPub, err := identityKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityPub.Destroy()

	valid, err := identityPub.Verify(kyberPubBytes, gotSig)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("signature should be valid")
	}
}
