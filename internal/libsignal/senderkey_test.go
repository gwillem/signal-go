package libsignal

import (
	"testing"
)

func TestSenderKeyRecordSerializeDeserialize(t *testing.T) {
	// Create a sender key store and a distribution message to populate it
	store := NewMemorySenderKeyStore()

	// Create sender address
	addr, err := NewAddress("test-uuid", 1)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer addr.Destroy()

	// Create a distribution ID (UUID)
	distributionID := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// Initially no key should exist
	rec, err := store.LoadSenderKey(addr, distributionID)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil record, got %v", rec)
	}
}

func TestMemorySenderKeyStore(t *testing.T) {
	store := NewMemorySenderKeyStore()

	// Create sender address
	addr, err := NewAddress("sender-uuid", 2)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer addr.Destroy()

	distributionID := [16]byte{0xaa, 0xbb, 0xcc, 0xdd}

	// Load from empty store should return nil
	rec, err := store.LoadSenderKey(addr, distributionID)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil, got record")
	}
}
