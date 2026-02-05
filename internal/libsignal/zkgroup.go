package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"
import (
	"encoding/hex"
	"fmt"
	"unsafe"
)

// GroupMasterKey is a 32-byte key that identifies a group.
// It's the root key from which all other group keys are derived.
type GroupMasterKey [32]byte

// GroupSecretParams are derived from the master key and used for group crypto operations.
type GroupSecretParams [289]byte // SignalGROUP_SECRET_PARAMS_LEN

// GroupPublicParams are the public portion of group params, used in server requests.
type GroupPublicParams [97]byte // SignalGROUP_PUBLIC_PARAMS_LEN

// GroupIdentifier is a 32-byte hash derived from public params, used to identify groups.
type GroupIdentifier [32]byte

// String returns hex encoding of the group identifier.
func (g GroupIdentifier) String() string {
	return hex.EncodeToString(g[:])
}

// DeriveGroupSecretParams derives GroupSecretParams from a GroupMasterKey.
func DeriveGroupSecretParams(masterKey GroupMasterKey) (GroupSecretParams, error) {
	var out [289]C.uchar
	masterKeyPtr := (*[32]C.uchar)(unsafe.Pointer(&masterKey[0]))

	if err := wrapError(C.signal_group_secret_params_derive_from_master_key(&out, masterKeyPtr)); err != nil {
		return GroupSecretParams{}, fmt.Errorf("derive group secret params: %w", err)
	}

	var params GroupSecretParams
	for i := range 289 {
		params[i] = byte(out[i])
	}
	return params, nil
}

// GetPublicParams extracts the public params from secret params.
func (p GroupSecretParams) GetPublicParams() (GroupPublicParams, error) {
	var out [97]C.uchar
	paramsPtr := (*[289]C.uchar)(unsafe.Pointer(&p[0]))

	if err := wrapError(C.signal_group_secret_params_get_public_params(&out, paramsPtr)); err != nil {
		return GroupPublicParams{}, fmt.Errorf("get public params: %w", err)
	}

	var pub GroupPublicParams
	for i := range 97 {
		pub[i] = byte(out[i])
	}
	return pub, nil
}

// GetMasterKey extracts the master key from secret params.
func (p GroupSecretParams) GetMasterKey() (GroupMasterKey, error) {
	var out [32]C.uchar
	paramsPtr := (*[289]C.uchar)(unsafe.Pointer(&p[0]))

	if err := wrapError(C.signal_group_secret_params_get_master_key(&out, paramsPtr)); err != nil {
		return GroupMasterKey{}, fmt.Errorf("get master key: %w", err)
	}

	var key GroupMasterKey
	for i := range 32 {
		key[i] = byte(out[i])
	}
	return key, nil
}

// GetGroupIdentifier derives the group identifier from public params.
func (p GroupPublicParams) GetGroupIdentifier() (GroupIdentifier, error) {
	var out [32]C.uint8_t
	paramsPtr := (*[97]C.uchar)(unsafe.Pointer(&p[0]))

	if err := wrapError(C.signal_group_public_params_get_group_identifier(&out, paramsPtr)); err != nil {
		return GroupIdentifier{}, fmt.Errorf("get group identifier: %w", err)
	}

	var id GroupIdentifier
	for i := range 32 {
		id[i] = byte(out[i])
	}
	return id, nil
}

// DecryptBlob decrypts an encrypted blob from group state.
func (p GroupSecretParams) DecryptBlob(ciphertext []byte) ([]byte, error) {
	var out C.SignalOwnedBuffer
	paramsPtr := (*[289]C.uchar)(unsafe.Pointer(&p[0]))

	if err := wrapError(C.signal_group_secret_params_decrypt_blob_with_padding(&out, paramsPtr, borrowedBuffer(ciphertext))); err != nil {
		return nil, fmt.Errorf("decrypt blob: %w", err)
	}

	return freeOwnedBuffer(out), nil
}

// DecryptServiceID decrypts an encrypted service ID (ACI/PNI) from group state.
// Returns a 17-byte service ID (1 byte type prefix + 16 byte UUID).
func (p GroupSecretParams) DecryptServiceID(ciphertext [65]byte) ([17]byte, error) {
	var out [17]byte
	paramsPtr := (*[289]C.uchar)(unsafe.Pointer(&p[0]))
	ciphertextPtr := (*[65]C.uchar)(unsafe.Pointer(&ciphertext[0]))
	outPtr := (*C.SignalServiceIdFixedWidthBinaryBytes)(unsafe.Pointer(&out[0]))

	if err := wrapError(C.signal_group_secret_params_decrypt_service_id(outPtr, paramsPtr, ciphertextPtr)); err != nil {
		return [17]byte{}, fmt.Errorf("decrypt service id: %w", err)
	}

	return out, nil
}

// DecryptProfileKey decrypts an encrypted profile key from group state.
// The ciphertext is 65 bytes (SignalPROFILE_KEY_CIPHERTEXT_LEN).
// The serviceID is the 17-byte decrypted service ID of the member.
// Returns the 32-byte profile key.
func (p GroupSecretParams) DecryptProfileKey(ciphertext [65]byte, serviceID [17]byte) ([32]byte, error) {
	var out [32]C.uchar
	paramsPtr := (*[289]C.uchar)(unsafe.Pointer(&p[0]))
	ciphertextPtr := (*[65]C.uchar)(unsafe.Pointer(&ciphertext[0]))
	serviceIDPtr := (*C.SignalServiceIdFixedWidthBinaryBytes)(unsafe.Pointer(&serviceID[0]))

	if err := wrapError(C.signal_group_secret_params_decrypt_profile_key(&out, paramsPtr, ciphertextPtr, serviceIDPtr)); err != nil {
		return [32]byte{}, fmt.Errorf("decrypt profile key: %w", err)
	}

	var key [32]byte
	for i := range 32 {
		key[i] = byte(out[i])
	}
	return key, nil
}

// GroupIdentifierFromMasterKey derives a GroupIdentifier directly from a master key.
// This is a convenience function that combines DeriveGroupSecretParams, GetPublicParams,
// and GetGroupIdentifier.
func GroupIdentifierFromMasterKey(masterKey GroupMasterKey) (GroupIdentifier, error) {
	secretParams, err := DeriveGroupSecretParams(masterKey)
	if err != nil {
		return GroupIdentifier{}, err
	}

	publicParams, err := secretParams.GetPublicParams()
	if err != nil {
		return GroupIdentifier{}, err
	}

	return publicParams.GetGroupIdentifier()
}
