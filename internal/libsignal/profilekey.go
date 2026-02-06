package libsignal

/*
#include "libsignal-ffi.h"
#include "bridge.h"
*/
import "C"
import (
	"fmt"
	"unsafe"

	"github.com/google/uuid"
)

const (
	ProfileKeyLen           = 32
	ProfileKeyVersionLen    = 64 // Encoded as hex
	ProfileKeyCommitmentLen = 97
)

// ProfileKeyGetVersion derives the profile key version from a profile key and ACI.
// The version is a 64-byte hex-encoded string used in profile endpoints.
func ProfileKeyGetVersion(profileKey []byte, aci string) (string, error) {
	if len(profileKey) != ProfileKeyLen {
		return "", fmt.Errorf("profile key must be %d bytes, got %d", ProfileKeyLen, len(profileKey))
	}

	// Parse ACI UUID
	aciUUID, err := uuid.Parse(aci)
	if err != nil {
		return "", fmt.Errorf("parse ACI: %w", err)
	}

	// Convert to fixed-width binary format for libsignal
	// SignalServiceIdFixedWidthBinaryBytes is a [17]uint8_t
	// ACI is encoded as 0x00 prefix + 16 UUID bytes
	var serviceID [17]byte
	serviceID[0] = 0x00
	copy(serviceID[1:], aciUUID[:])

	var pkArray [ProfileKeyLen]C.uchar
	for i := range ProfileKeyLen {
		pkArray[i] = C.uchar(profileKey[i])
	}

	var versionOut [ProfileKeyVersionLen]C.uint8_t

	err = wrapError(C.signal_profile_key_get_profile_key_version(
		&versionOut,
		&pkArray,
		C.as_service_id(unsafe.Pointer(&serviceID[0])),
	))
	if err != nil {
		return "", fmt.Errorf("get profile key version: %w", err)
	}

	// Convert to string (it's hex-encoded)
	result := make([]byte, ProfileKeyVersionLen)
	for i := range ProfileKeyVersionLen {
		result[i] = byte(versionOut[i])
	}
	return string(result), nil
}

// ProfileKeyGetCommitment derives the profile key commitment from a profile key and ACI.
// Returns a 97-byte commitment used in profile write requests.
func ProfileKeyGetCommitment(profileKey []byte, aci string) ([]byte, error) {
	if len(profileKey) != ProfileKeyLen {
		return nil, fmt.Errorf("profile key must be %d bytes, got %d", ProfileKeyLen, len(profileKey))
	}

	// Parse ACI UUID
	aciUUID, err := uuid.Parse(aci)
	if err != nil {
		return nil, fmt.Errorf("parse ACI: %w", err)
	}

	// Convert to fixed-width binary format for libsignal
	var serviceID [17]byte
	serviceID[0] = 0x00
	copy(serviceID[1:], aciUUID[:])

	var pkArray [ProfileKeyLen]C.uchar
	for i := range ProfileKeyLen {
		pkArray[i] = C.uchar(profileKey[i])
	}

	var commitmentOut [ProfileKeyCommitmentLen]C.uchar

	err = wrapError(C.signal_profile_key_get_commitment(
		&commitmentOut,
		&pkArray,
		C.as_service_id(unsafe.Pointer(&serviceID[0])),
	))
	if err != nil {
		return nil, fmt.Errorf("get profile key commitment: %w", err)
	}

	result := make([]byte, ProfileKeyCommitmentLen)
	for i := range ProfileKeyCommitmentLen {
		result[i] = byte(commitmentOut[i])
	}
	return result, nil
}
