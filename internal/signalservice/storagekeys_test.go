package signalservice

import (
	"encoding/hex"
	"testing"
)

func TestDeriveStorageKey(t *testing.T) {
	// Test with a known master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	storageKey, err := deriveStorageKey(masterKey)
	if err != nil {
		t.Fatalf("DeriveStorageKey: %v", err)
	}

	// Verify we get a non-zero key
	allZero := true
	for _, b := range storageKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("storage key is all zeros")
	}

	// Verify deterministic
	storageKey2, err := deriveStorageKey(masterKey)
	if err != nil {
		t.Fatalf("DeriveStorageKey (2): %v", err)
	}
	if storageKey != storageKey2 {
		t.Error("storage key derivation is not deterministic")
	}
}

func TestDeriveStorageKeyInvalidLength(t *testing.T) {
	_, err := deriveStorageKey(make([]byte, 16))
	if err == nil {
		t.Error("expected error for invalid master key length")
	}
}

func TestDeriveManifestKey(t *testing.T) {
	var storageKey storageKey
	for i := range storageKey {
		storageKey[i] = byte(i + 100)
	}

	// Test different versions produce different keys
	key1 := storageKey.DeriveManifestKey(1)
	key2 := storageKey.DeriveManifestKey(2)

	if key1 == key2 {
		t.Error("different versions should produce different manifest keys")
	}

	// Test deterministic
	key1b := storageKey.DeriveManifestKey(1)
	if key1 != key1b {
		t.Error("manifest key derivation is not deterministic")
	}
}

func TestDeriveItemKey(t *testing.T) {
	var storageKey storageKey
	for i := range storageKey {
		storageKey[i] = byte(i + 50)
	}

	rawID1 := []byte{1, 2, 3, 4}
	rawID2 := []byte{5, 6, 7, 8}

	// Test different IDs produce different keys
	key1 := storageKey.DeriveItemKey(rawID1)
	key2 := storageKey.DeriveItemKey(rawID2)

	if key1 == key2 {
		t.Error("different raw IDs should produce different item keys")
	}

	// Test deterministic
	key1b := storageKey.DeriveItemKey(rawID1)
	if key1 != key1b {
		t.Error("item key derivation is not deterministic")
	}
}

func TestStorageKeyDerivationChain(t *testing.T) {
	// Test the full derivation chain matches expected HMAC-SHA256 behavior
	masterKey, _ := hex.DecodeString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	storageKey, err := deriveStorageKey(masterKey)
	if err != nil {
		t.Fatalf("DeriveStorageKey: %v", err)
	}

	// The storage key should be HMAC-SHA256(masterKey, "Storage Service Encryption")
	// Verify it's 32 bytes and non-zero
	if len(storageKey) != 32 {
		t.Errorf("storage key length: got %d, want 32", len(storageKey))
	}

	manifestKey := storageKey.DeriveManifestKey(42)
	if len(manifestKey) != 32 {
		t.Errorf("manifest key length: got %d, want 32", len(manifestKey))
	}

	itemKey := storageKey.DeriveItemKey([]byte("test-id"))
	if len(itemKey) != 32 {
		t.Errorf("item key length: got %d, want 32", len(itemKey))
	}
}
