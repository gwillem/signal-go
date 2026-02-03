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

	t.Run("AddDevice adds to existing list", func(t *testing.T) {
		err := st.AddDevice(aci, 5)
		if err != nil {
			t.Fatalf("AddDevice: %v", err)
		}

		devices, err := st.GetDevices(aci)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 3 || devices[0] != 1 || devices[1] != 4 || devices[2] != 5 {
			t.Errorf("expected [1 4 5], got %v", devices)
		}
	})

	t.Run("AddDevice is idempotent", func(t *testing.T) {
		err := st.AddDevice(aci, 5) // already exists
		if err != nil {
			t.Fatalf("AddDevice: %v", err)
		}

		devices, err := st.GetDevices(aci)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 3 {
			t.Errorf("expected 3 devices, got %v", devices)
		}
	})

	t.Run("AddDevice to unknown recipient creates entry", func(t *testing.T) {
		newACI := "660e8400-e29b-41d4-a716-446655440000"
		err := st.AddDevice(newACI, 2)
		if err != nil {
			t.Fatalf("AddDevice: %v", err)
		}

		devices, err := st.GetDevices(newACI)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 1 || devices[0] != 2 {
			t.Errorf("expected [2], got %v", devices)
		}
	})

	t.Run("RemoveDevice removes from list", func(t *testing.T) {
		err := st.RemoveDevice(aci, 4)
		if err != nil {
			t.Fatalf("RemoveDevice: %v", err)
		}

		devices, err := st.GetDevices(aci)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 2 || devices[0] != 1 || devices[1] != 5 {
			t.Errorf("expected [1 5], got %v", devices)
		}
	})

	t.Run("RemoveDevice is idempotent", func(t *testing.T) {
		err := st.RemoveDevice(aci, 4) // already removed
		if err != nil {
			t.Fatalf("RemoveDevice: %v", err)
		}

		devices, err := st.GetDevices(aci)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 2 {
			t.Errorf("expected 2 devices, got %v", devices)
		}
	})

	t.Run("RemoveDevice from unknown recipient is no-op", func(t *testing.T) {
		err := st.RemoveDevice("unknown-aci", 1)
		if err != nil {
			t.Fatalf("RemoveDevice: %v", err)
		}
	})

	t.Run("GetDevices returns sorted by device_id", func(t *testing.T) {
		testACI := "770e8400-e29b-41d4-a716-446655440000"
		// Add in non-sorted order
		_ = st.AddDevice(testACI, 3)
		_ = st.AddDevice(testACI, 1)
		_ = st.AddDevice(testACI, 2)

		devices, err := st.GetDevices(testACI)
		if err != nil {
			t.Fatalf("GetDevices: %v", err)
		}
		if len(devices) != 3 || devices[0] != 1 || devices[1] != 2 || devices[2] != 3 {
			t.Errorf("expected sorted [1 2 3], got %v", devices)
		}
	})
}
