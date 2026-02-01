package libsignal

import (
	"bytes"
	"testing"
)

// B1: Derive public from private key
func TestPublicKeyFromPrivate(t *testing.T) {
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

	data, err := pub.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// EC public keys serialize to 33 bytes (1 byte prefix + 32 bytes)
	if len(data) != 33 {
		t.Fatalf("expected 33 bytes, got %d", len(data))
	}
}

// B2: Public key serialize/deserialize round-trip
func TestPublicKeySerializeRoundTrip(t *testing.T) {
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

	data, err := pub.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	pub2, err := DeserializePublicKey(data)
	if err != nil {
		t.Fatalf("DeserializePublicKey: %v", err)
	}
	defer pub2.Destroy()

	data2, err := pub2.Serialize()
	if err != nil {
		t.Fatalf("Serialize pub2: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Fatal("public key round-trip mismatch")
	}
}

// B3: Two different private keys produce different public keys
func TestDifferentKeysProduceDifferentPublicKeys(t *testing.T) {
	priv1, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey 1: %v", err)
	}
	defer priv1.Destroy()

	priv2, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey 2: %v", err)
	}
	defer priv2.Destroy()

	pub1, err := priv1.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey 1: %v", err)
	}
	defer pub1.Destroy()

	pub2, err := priv2.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey 2: %v", err)
	}
	defer pub2.Destroy()

	cmp, err := pub1.Compare(pub2)
	if err != nil {
		t.Fatalf("Compare: %v", err)
	}
	if cmp == 0 {
		t.Fatal("two independently generated keys should not be equal")
	}
}
