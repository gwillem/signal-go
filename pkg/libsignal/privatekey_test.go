package libsignal

import (
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
	for i := range data {
		if data[i] != data2[i] {
			t.Fatalf("byte %d differs: %x vs %x", i, data[i], data2[i])
		}
	}
}
