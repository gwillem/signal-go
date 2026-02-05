package signalservice

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// StorageKey is the key used to encrypt data on the storage service.
// Derived from MasterKey via HMAC-SHA256(masterKey, "Storage Service Encryption").
type StorageKey [32]byte

// StorageManifestKey is used to decrypt the storage manifest.
// Derived via HMAC-SHA256(storageKey, "Manifest_{version}").
type StorageManifestKey [32]byte

// StorageItemKey is used to decrypt individual storage items.
// Derived via HMAC-SHA256(storageKey, "Item_{base64(rawId)}").
type StorageItemKey [32]byte

// DeriveStorageKey derives a StorageKey from a 32-byte master key.
// This matches Signal-Android's MasterKey.deriveStorageServiceKey().
func DeriveStorageKey(masterKey []byte) (StorageKey, error) {
	if len(masterKey) != 32 {
		return StorageKey{}, fmt.Errorf("master key must be 32 bytes, got %d", len(masterKey))
	}

	h := hmac.New(sha256.New, masterKey)
	h.Write([]byte("Storage Service Encryption"))
	var key StorageKey
	copy(key[:], h.Sum(nil))
	return key, nil
}

// DeriveManifestKey derives a key for decrypting the manifest at the given version.
// This matches Signal-Android's StorageKey.deriveManifestKey(version).
func (k StorageKey) DeriveManifestKey(version int64) StorageManifestKey {
	h := hmac.New(sha256.New, k[:])
	h.Write([]byte(fmt.Sprintf("Manifest_%d", version)))
	var key StorageManifestKey
	copy(key[:], h.Sum(nil))
	return key
}

// DeriveItemKey derives a key for decrypting a storage item with the given raw ID.
// This matches Signal-Android's StorageKey.deriveItemKey(rawId).
func (k StorageKey) DeriveItemKey(rawID []byte) StorageItemKey {
	h := hmac.New(sha256.New, k[:])
	h.Write([]byte("Item_" + base64.StdEncoding.EncodeToString(rawID)))
	var key StorageItemKey
	copy(key[:], h.Sum(nil))
	return key
}
