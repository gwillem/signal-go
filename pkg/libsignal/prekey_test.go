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
