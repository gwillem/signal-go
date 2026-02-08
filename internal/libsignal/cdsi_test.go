package libsignal_test

import (
	"testing"

	"github.com/gwillem/signal-go/internal/libsignal"
)

func TestLookupRequestLifecycle(t *testing.T) {
	req, err := libsignal.NewLookupRequest()
	if err != nil {
		t.Fatalf("NewLookupRequest: %v", err)
	}
	defer req.Destroy()

	// Adding E.164 numbers should not error.
	if err := req.AddE164("+31612345678"); err != nil {
		t.Fatalf("AddE164: %v", err)
	}
	if err := req.AddE164("+14155551234"); err != nil {
		t.Fatalf("AddE164 second: %v", err)
	}
}

func TestLookupRequestDoubleDestroy(t *testing.T) {
	req, err := libsignal.NewLookupRequest()
	if err != nil {
		t.Fatalf("NewLookupRequest: %v", err)
	}
	req.Destroy()
	// Double destroy should be safe.
	req.Destroy()
}
