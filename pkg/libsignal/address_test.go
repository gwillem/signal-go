package libsignal

import "testing"

// C1: NewAddress → get name, get device ID
func TestAddress(t *testing.T) {
	addr, err := NewAddress("+31612345678", 1)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer addr.Destroy()

	name, err := addr.Name()
	if err != nil {
		t.Fatalf("Name: %v", err)
	}
	if name != "+31612345678" {
		t.Fatalf("expected +31612345678, got %s", name)
	}

	devID, err := addr.DeviceID()
	if err != nil {
		t.Fatalf("DeviceID: %v", err)
	}
	if devID != 1 {
		t.Fatalf("expected device ID 1, got %d", devID)
	}
}
