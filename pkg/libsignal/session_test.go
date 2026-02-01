package libsignal

import (
	"bytes"
	"testing"
	"time"
)

// C7: SessionRecord serialize/deserialize (via protocol operation)
func TestSessionRecordSerializeRoundTrip(t *testing.T) {
	alice := newParty(t, 1)
	bob := newParty(t, 2)

	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()

	bobAddr, err := NewAddress("+31600000002", 1)
	if err != nil {
		t.Fatalf("NewAddress: %v", err)
	}
	defer bobAddr.Destroy()

	err = ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}

	session, err := alice.sessionStore.LoadSession(bobAddr)
	if err != nil {
		t.Fatalf("LoadSession: %v", err)
	}
	if session == nil {
		t.Fatal("expected session")
	}
	defer session.Destroy()

	data, err := session.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	session2, err := DeserializeSessionRecord(data)
	if err != nil {
		t.Fatalf("DeserializeSessionRecord: %v", err)
	}
	defer session2.Destroy()

	data2, err := session2.Serialize()
	if err != nil {
		t.Fatalf("Serialize session2: %v", err)
	}

	if !bytes.Equal(data, data2) {
		t.Fatal("session record round-trip mismatch")
	}
}
