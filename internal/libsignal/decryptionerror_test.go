package libsignal

import (
	"testing"
	"time"
)

// encryptTestMessage sets up a session between Alice and Bob and encrypts a
// message, returning the serialized ciphertext and its type.
func encryptTestMessage(t *testing.T) ([]byte, uint8) {
	t.Helper()
	alice := newParty(t, 1)
	bob := newParty(t, 2)

	bobAddr, err := NewAddress("+31600000002", 1)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer bobAddr.Destroy()

	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()

	if err := ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now()); err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}

	ct, err := Encrypt([]byte("hello"), bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	defer ct.Destroy()

	msgType, err := ct.Type()
	if err != nil {
		t.Fatalf("Type: %v", err)
	}

	ctBytes, err := ct.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	return ctBytes, msgType
}

func TestDecryptionErrorMessageRoundTrip(t *testing.T) {
	ctBytes, msgType := encryptTestMessage(t)

	var timestamp uint64 = 1700000000000
	var senderDeviceID uint32 = 1

	dem, err := NewDecryptionErrorMessage(ctBytes, msgType, timestamp, senderDeviceID)
	if err != nil {
		t.Fatalf("NewDecryptionErrorMessage: %v", err)
	}
	defer dem.Destroy()

	// Verify fields.
	gotTimestamp, err := dem.Timestamp()
	if err != nil {
		t.Fatalf("Timestamp: %v", err)
	}
	if gotTimestamp != timestamp {
		t.Errorf("timestamp = %d, want %d", gotTimestamp, timestamp)
	}

	gotDevice, err := dem.DeviceID()
	if err != nil {
		t.Fatalf("DeviceID: %v", err)
	}
	if gotDevice != senderDeviceID {
		t.Errorf("deviceID = %d, want %d", gotDevice, senderDeviceID)
	}

	// RatchetKey should be present for a real PreKey message.
	rk, err := dem.RatchetKey()
	if err != nil {
		t.Fatalf("RatchetKey: %v", err)
	}
	if rk == nil {
		t.Fatal("expected ratchet key to be non-nil for real ciphertext")
	}
	defer rk.Destroy()

	// Serialize → Deserialize round-trip.
	data, err := dem.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized data is empty")
	}

	dem2, err := DeserializeDecryptionErrorMessage(data)
	if err != nil {
		t.Fatalf("DeserializeDecryptionErrorMessage: %v", err)
	}
	defer dem2.Destroy()

	gotTimestamp2, err := dem2.Timestamp()
	if err != nil {
		t.Fatalf("Timestamp after round-trip: %v", err)
	}
	if gotTimestamp2 != timestamp {
		t.Errorf("round-trip timestamp = %d, want %d", gotTimestamp2, timestamp)
	}

	gotDevice2, err := dem2.DeviceID()
	if err != nil {
		t.Fatalf("DeviceID after round-trip: %v", err)
	}
	if gotDevice2 != senderDeviceID {
		t.Errorf("round-trip deviceID = %d, want %d", gotDevice2, senderDeviceID)
	}
}
