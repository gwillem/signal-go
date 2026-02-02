package libsignal

import (
	"testing"
)

func TestPlaintextContentFromDecryptionError(t *testing.T) {
	ctBytes, msgType := encryptTestMessage(t)

	dem, err := NewDecryptionErrorMessage(ctBytes, msgType, 1700000000000, 1)
	if err != nil {
		t.Fatalf("NewDecryptionErrorMessage: %v", err)
	}
	defer dem.Destroy()

	// Wrap in PlaintextContent.
	pc, err := NewPlaintextContentFromDecryptionError(dem)
	if err != nil {
		t.Fatalf("NewPlaintextContentFromDecryptionError: %v", err)
	}
	defer pc.Destroy()

	// Serialize → Deserialize round-trip.
	data, err := pc.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(data) == 0 {
		t.Fatal("serialized data is empty")
	}

	pc2, err := DeserializePlaintextContent(data)
	if err != nil {
		t.Fatalf("DeserializePlaintextContent: %v", err)
	}
	defer pc2.Destroy()

	// Verify body is non-empty.
	body, err := pc2.Body()
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if len(body) == 0 {
		t.Fatal("body is empty after round-trip")
	}
}

func TestCiphertextMessageFromPlaintextContent(t *testing.T) {
	ctBytes, msgType := encryptTestMessage(t)

	dem, err := NewDecryptionErrorMessage(ctBytes, msgType, 1700000000000, 1)
	if err != nil {
		t.Fatalf("NewDecryptionErrorMessage: %v", err)
	}
	defer dem.Destroy()

	pc, err := NewPlaintextContentFromDecryptionError(dem)
	if err != nil {
		t.Fatalf("NewPlaintextContentFromDecryptionError: %v", err)
	}
	defer pc.Destroy()

	cm, err := CiphertextMessageFromPlaintextContent(pc)
	if err != nil {
		t.Fatalf("CiphertextMessageFromPlaintextContent: %v", err)
	}
	defer cm.Destroy()

	gotType, err := cm.Type()
	if err != nil {
		t.Fatalf("Type: %v", err)
	}
	if gotType != CiphertextMessageTypePlaintext {
		t.Errorf("type = %d, want %d (Plaintext)", gotType, CiphertextMessageTypePlaintext)
	}

	ser, err := cm.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(ser) == 0 {
		t.Fatal("serialized CiphertextMessage is empty")
	}
}
