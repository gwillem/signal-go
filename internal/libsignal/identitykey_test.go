package libsignal

import (
	"bytes"
	"testing"
)

// B4: Serialize identity key pair, deserialize back
func TestIdentityKeyPairSerializeRoundTrip(t *testing.T) {
	kp, err := GenerateIdentityKeyPair()
	if err != nil {
		t.Fatalf("GenerateIdentityKeyPair: %v", err)
	}
	defer kp.Destroy()

	data, err := kp.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized identity key pair should not be empty")
	}

	kp2, err := DeserializeIdentityKeyPair(data)
	if err != nil {
		t.Fatalf("DeserializeIdentityKeyPair: %v", err)
	}
	defer kp2.Destroy()

	// Compare public keys
	pubData1, err := kp.PublicKey.Serialize()
	if err != nil {
		t.Fatalf("Serialize pub1: %v", err)
	}
	pubData2, err := kp2.PublicKey.Serialize()
	if err != nil {
		t.Fatalf("Serialize pub2: %v", err)
	}
	if !bytes.Equal(pubData1, pubData2) {
		t.Fatal("public key mismatch after round-trip")
	}

	// Compare private keys
	privData1, err := kp.PrivateKey.Serialize()
	if err != nil {
		t.Fatalf("Serialize priv1: %v", err)
	}
	privData2, err := kp2.PrivateKey.Serialize()
	if err != nil {
		t.Fatalf("Serialize priv2: %v", err)
	}
	if !bytes.Equal(privData1, privData2) {
		t.Fatal("private key mismatch after round-trip")
	}
}
