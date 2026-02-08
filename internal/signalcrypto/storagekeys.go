package signalcrypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/hkdf"
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
// Note: This is the legacy method. Use RecordIkm.DeriveItemKey when recordIkm is present.
func (k StorageKey) DeriveItemKey(rawID []byte) StorageItemKey {
	h := hmac.New(sha256.New, k[:])
	h.Write([]byte("Item_" + base64.StdEncoding.EncodeToString(rawID)))
	var key StorageItemKey
	copy(key[:], h.Sum(nil))
	return key
}

// RecordIkm is the Item Key Material from the storage manifest.
// When present, it should be used to derive item keys instead of StorageKey.DeriveItemKey.
type RecordIkm []byte

// DeriveItemKey derives a StorageItemKey from RecordIkm using HKDF.
// This matches Signal-Android's RecordIkm.deriveStorageItemKey(rawId).
func (ikm RecordIkm) DeriveItemKey(rawID []byte) (StorageItemKey, error) {
	if len(ikm) == 0 {
		return StorageItemKey{}, fmt.Errorf("recordIkm is empty")
	}

	// Info is "20240801_SIGNAL_STORAGE_SERVICE_ITEM_" + rawId
	info := append([]byte("20240801_SIGNAL_STORAGE_SERVICE_ITEM_"), rawID...)

	reader := hkdf.New(sha256.New, ikm, nil, info)
	var key StorageItemKey
	if _, err := reader.Read(key[:]); err != nil {
		return StorageItemKey{}, fmt.Errorf("hkdf read: %w", err)
	}
	return key, nil
}
