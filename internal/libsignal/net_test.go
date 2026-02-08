package libsignal_test

import (
	"testing"

	"github.com/gwillem/signal-go/internal/libsignal"
)

func TestTokioAsyncContextLifecycle(t *testing.T) {
	ctx, err := libsignal.NewTokioAsyncContext()
	if err != nil {
		t.Fatalf("NewTokioAsyncContext: %v", err)
	}
	ctx.Destroy()
	// Double destroy should be safe.
	ctx.Destroy()
}

func TestConnectionManagerLifecycle(t *testing.T) {
	cm, err := libsignal.NewConnectionManager(libsignal.EnvironmentProduction, "signal-go-test/0.1")
	if err != nil {
		t.Fatalf("NewConnectionManager: %v", err)
	}
	cm.Destroy()
	// Double destroy should be safe.
	cm.Destroy()
}
