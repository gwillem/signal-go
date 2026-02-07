package store

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeviceCaching(t *testing.T) {
	// Create temp database
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	st, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer st.Close()
	defer os.Remove(dbPath)

	aci := "550e8400-e29b-41d4-a716-446655440000"

	t.Run("GetDevices returns empty for unknown recipient", func(t *testing.T) {
		devices, err := st.GetDevices(aci)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 0 {
			t.Errorf("expected empty, got %v", devices)
		}
	})

	t.Run("SetDevices stores device list", func(t *testing.T) {
		err := st.SetDevices(aci, []int{1, 2, 3})
		if err != nil {
			t.Fatalf("SetDevices: %v", err)
		}

		devices, err := st.GetDevices(aci)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 3 || devices[0] != 1 || devices[1] != 2 || devices[2] != 3 {
			t.Errorf("expected [1 2 3], got %v", devices)
		}
	})

	t.Run("SetDevices replaces existing list", func(t *testing.T) {
		err := st.SetDevices(aci, []int{1, 4})
		if err != nil {
			t.Fatalf("SetDevices: %v", err)
		}

		devices, err := st.GetDevices(aci)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 2 || devices[0] != 1 || devices[1] != 4 {
			t.Errorf("expected [1 4], got %v", devices)
		}
	})

	t.Run("GetDevices returns sorted by device_id", func(t *testing.T) {
		testACI := "770e8400-e29b-41d4-a716-446655440000"
		// Insert in non-sorted order
		err := st.SetDevices(testACI, []int{3, 1, 2})
		if err != nil {
			t.Fatalf("SetDevices: %v", err)
		}

		devices, err := st.GetDevices(testACI)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 3 || devices[0] != 1 || devices[1] != 2 || devices[2] != 3 {
			t.Errorf("expected sorted [1 2 3], got %v", devices)
		}
	})
}
