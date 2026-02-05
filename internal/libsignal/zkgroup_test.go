package libsignal

import (
	"testing"
)

func TestGroupSecretParamsDerivation(t *testing.T) {
	// Create a test master key (32 bytes)
	var masterKey GroupMasterKey
	for i := range 32 {
		masterKey[i] = byte(i)
	}

	// Derive secret params
	secretParams, err := DeriveGroupSecretParams(masterKey)
	if err != nil {
		t.Fatalf("DeriveGroupSecretParams: %v", err)
	}

	// Verify we can get back the master key
	recoveredKey, err := secretParams.GetMasterKey()
	if err != nil {
		t.Fatalf("GetMasterKey: %v", err)
	}
	if recoveredKey != masterKey {
		t.Errorf("master key mismatch: got %x, want %x", recoveredKey, masterKey)
	}
}

func TestGroupPublicParams(t *testing.T) {
	var masterKey GroupMasterKey
	for i := range 32 {
		masterKey[i] = byte(i + 100)
	}

	secretParams, err := DeriveGroupSecretParams(masterKey)
	if err != nil {
		t.Fatalf("DeriveGroupSecretParams: %v", err)
	}

	publicParams, err := secretParams.GetPublicParams()
	if err != nil {
		t.Fatalf("GetPublicParams: %v", err)
	}

	// Public params should be non-zero
	allZero := true
	for _, b := range publicParams {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("public params are all zeros")
	}
}

func TestGroupIdentifier(t *testing.T) {
	var masterKey GroupMasterKey
	for i := range 32 {
		masterKey[i] = byte(i * 2)
	}

	secretParams, err := DeriveGroupSecretParams(masterKey)
	if err != nil {
		t.Fatalf("DeriveGroupSecretParams: %v", err)
	}

	publicParams, err := secretParams.GetPublicParams()
	if err != nil {
		t.Fatalf("GetPublicParams: %v", err)
	}

	groupID, err := publicParams.GetGroupIdentifier()
	if err != nil {
		t.Fatalf("GetGroupIdentifier: %v", err)
	}

	// Group ID should be non-zero
	allZero := true
	for _, b := range groupID {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("group identifier is all zeros")
	}

	// Test the convenience function
	groupID2, err := GroupIdentifierFromMasterKey(masterKey)
	if err != nil {
		t.Fatalf("GroupIdentifierFromMasterKey: %v", err)
	}
	if groupID != groupID2 {
		t.Error("group identifiers don't match")
	}
}

func TestGroupIdentifierDeterministic(t *testing.T) {
	// Same master key should always produce same group identifier
	var masterKey GroupMasterKey
	for i := range 32 {
		masterKey[i] = byte(42)
	}

	id1, err := GroupIdentifierFromMasterKey(masterKey)
	if err != nil {
		t.Fatalf("GroupIdentifierFromMasterKey 1: %v", err)
	}

	id2, err := GroupIdentifierFromMasterKey(masterKey)
	if err != nil {
		t.Fatalf("GroupIdentifierFromMasterKey 2: %v", err)
	}

	if id1 != id2 {
		t.Errorf("group identifiers not deterministic: %x vs %x", id1, id2)
	}
}
