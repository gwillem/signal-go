package libsignal

import (
	"bytes"
	"testing"
)

// C2: Create PreKeyRecord, serialize/deserialize round-trip
func TestPreKeyRecordRoundTrip(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	defer priv.Destroy()

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	defer pub.Destroy()

	rec, err := NewPreKeyRecord(42, pub, priv)
	if err != nil {
		t.Fatalf("NewPreKeyRecord: %v", err)
	}
	defer rec.Destroy()

	id, err := rec.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if id != 42 {
		t.Fatalf("expected ID 42, got %d", id)
	}

	data, err := rec.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	rec2, err := DeserializePreKeyRecord(data)
	if err != nil {
		t.Fatalf("DeserializePreKeyRecord: %v", err)
	}
	defer rec2.Destroy()

	data2, err := rec2.Serialize()
	if err != nil {
		t.Fatalf("Serialize rec2: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Fatal("pre-key record round-trip mismatch")
	}
}

// C3: Create SignedPreKeyRecord, serialize/deserialize round-trip
func TestSignedPreKeyRecordRoundTrip(t *testing.T) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	defer priv.Destroy()

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	defer pub.Destroy()

	pubBytes, err := pub.Serialize()
	if err != nil {
		t.Fatalf("Serialize pub: %v", err)
	}

	sig, err := priv.Sign(pubBytes)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	rec, err := NewSignedPreKeyRecord(7, 1000000, pub, priv, sig)
	if err != nil {
		t.Fatalf("NewSignedPreKeyRecord: %v", err)
	}
	defer rec.Destroy()

	id, err := rec.ID()
	if err != nil {
		t.Fatalf("ID: %v", err)
	}
	if id != 7 {
		t.Fatalf("expected ID 7, got %d", id)
	}

	data, err := rec.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	rec2, err := DeserializeSignedPreKeyRecord(data)
	if err != nil {
		t.Fatalf("DeserializeSignedPreKeyRecord: %v", err)
	}
	defer rec2.Destroy()

	data2, err := rec2.Serialize()
	if err != nil {
		t.Fatalf("Serialize rec2: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Fatal("signed pre-key record round-trip mismatch")
	}
}

func TestSignedPreKeyRecordGetters(t *testing.T) {
	identityPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityPriv.Destroy()

	priv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Destroy()

	pubBytes, err := pub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := identityPriv.Sign(pubBytes)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := NewSignedPreKeyRecord(42, 1000000, pub, priv, sig)
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Destroy()

	// Test PublicKey getter
	gotPub, err := rec.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer gotPub.Destroy()

	gotPubBytes, err := gotPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pubBytes, gotPubBytes) {
		t.Fatal("public key mismatch")
	}

	// Test Signature getter
	gotSig, err := rec.Signature()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, gotSig) {
		t.Fatal("signature mismatch")
	}

	// Verify signature is valid
	identityPub, err := identityPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityPub.Destroy()

	valid, err := identityPub.Verify(pubBytes, gotSig)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("signature should be valid")
	}
}
