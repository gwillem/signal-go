package provisioncrypto

import (
	"testing"

	"github.com/gwillem/signal-go/internal/libsignal"
)

func TestEncryptDecryptDeviceName(t *testing.T) {
	identity, err := libsignal.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Destroy()

	name := "signal-go test device"

	encrypted, err := EncryptDeviceName(name, identity)
	if err != nil {
		t.Fatal(err)
	}

	if len(encrypted) == 0 {
		t.Fatal("encrypted device name should not be empty")
	}

	// Decrypt and verify round-trip.
	got, err := DecryptDeviceName(encrypted, identity)
	if err != nil {
		t.Fatal(err)
	}

	if got != name {
		t.Fatalf("device name mismatch: got %q, want %q", got, name)
	}
}

func TestEncryptDeviceNameDifferentEachTime(t *testing.T) {
	identity, err := libsignal.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Destroy()

	a, err := EncryptDeviceName("test", identity)
	if err != nil {
		t.Fatal(err)
	}

	b, err := EncryptDeviceName("test", identity)
	if err != nil {
		t.Fatal(err)
	}

	// Different ephemeral keys → different ciphertext.
	if string(a) == string(b) {
		t.Fatal("two encryptions of same name should produce different ciphertext")
	}
}
