package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/gwillem/signal-go/internal/libsignal"
)

func TestSenderKeyStore(t *testing.T) {
	// Create temp database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	defer os.Remove(dbPath)

	// Create sender address
	addr, err := libsignal.NewAddress("sender-uuid-123", 2)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer addr.Destroy()

	distributionID := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	// Load from empty store should return nil
	rec, err := st.LoadSenderKey(addr, distributionID)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	if rec != nil {
		t.Errorf("expected nil, got record")
	}
}

func TestSenderKeyStoreWithDifferentDistributionIDs(t *testing.T) {
	// Create temp database
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	defer os.Remove(dbPath)

	// Create sender address
	addr, err := libsignal.NewAddress("sender-uuid-456", 1)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer addr.Destroy()

	distributionID1 := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	distributionID2 := [16]byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20}

	// Both should return nil initially
	rec1, err := st.LoadSenderKey(addr, distributionID1)
	if err != nil {
		t.Fatalf("LoadSenderKey 1: %v", err)
	}
	if rec1 != nil {
		t.Errorf("expected nil for dist1, got record")
	}

	rec2, err := st.LoadSenderKey(addr, distributionID2)
	if err != nil {
		t.Fatalf("LoadSenderKey 2: %v", err)
	}
	if rec2 != nil {
		t.Errorf("expected nil for dist2, got record")
	}
}
