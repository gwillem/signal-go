package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// EndorsementExpiration returns the expiration timestamp (seconds since epoch)
// from a raw GroupSendEndorsementsResponse.
func EndorsementExpiration(responseBytes []byte) (uint64, error) {
	var out C.uint64_t
	if err := wrapError(C.signal_group_send_endorsements_response_get_expiration(
		&out,
		borrowedBuffer(responseBytes),
	)); err != nil {
		return 0, err
	}
	return uint64(out), nil
}

// ReceiveEndorsements validates a GroupSendEndorsementsResponse from the server
// and returns per-member endorsement blobs (one per group member, excluding localUser).
//
// groupMembers is a concatenation of 17-byte ServiceIdFixedWidthBinaryBytes for ALL members.
// localUser is the 17-byte service ID of the local user.
// now is the current time in seconds since epoch.
func ReceiveEndorsements(
	responseBytes []byte,
	groupMembers []byte,
	localUser [17]byte,
	now uint64,
	groupSecretParams GroupSecretParams,
	serverPublicParams *ServerPublicParams,
) ([][]byte, error) {
	var out C.SignalBytestringArray

	localUserPtr := (*C.SignalServiceIdFixedWidthBinaryBytes)(unsafe.Pointer(&localUser[0]))
	paramsPtr := (*[289]C.uchar)(unsafe.Pointer(&groupSecretParams[0]))

	if err := wrapError(C.signal_group_send_endorsements_response_receive_and_combine_with_service_ids(
		&out,
		borrowedBuffer(responseBytes),
		borrowedBuffer(groupMembers),
		localUserPtr,
		C.uint64_t(now),
		paramsPtr,
		C.SignalConstPointerServerPublicParams(serverPublicParams.ptr),
	)); err != nil {
		return nil, err
	}
	defer C.signal_free_bytestring_array(out)

	return splitBytestringArray(out), nil
}

// CombineEndorsements combines multiple per-member endorsements into a single
// combined endorsement suitable for creating a Group-Send-Token.
func CombineEndorsements(endorsements [][]byte) ([]byte, error) {
	if len(endorsements) == 0 {
		return nil, &Error{Message: "endorsements must not be empty"}
	}

	// Pin all Go byte slices so CGO doesn't complain about Go pointers
	// to unpinned Go memory inside the cBuffers array.
	var pinner runtime.Pinner
	defer pinner.Unpin()

	cBuffers := make([]C.SignalBorrowedBuffer, len(endorsements))
	for i, e := range endorsements {
		if len(e) > 0 {
			pinner.Pin(&e[0])
		}
		cBuffers[i] = borrowedBuffer(e)
	}
	pinner.Pin(&cBuffers[0])

	cSlice := C.SignalBorrowedSliceOfBuffers{
		base:   &cBuffers[0],
		length: C.size_t(len(cBuffers)),
	}

	var out C.SignalOwnedBuffer
	if err := wrapError(C.signal_group_send_endorsement_combine(&out, cSlice)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(out), nil
}

// EndorsementToFullToken converts a combined endorsement to a full Group-Send-Token
// that can be used as the Group-Send-Token HTTP header.
func EndorsementToFullToken(endorsement []byte, groupSecretParams GroupSecretParams, expiration uint64) ([]byte, error) {
	// Step 1: endorsement → token
	var tokenBuf C.SignalOwnedBuffer
	paramsPtr := (*[289]C.uchar)(unsafe.Pointer(&groupSecretParams[0]))
	if err := wrapError(C.signal_group_send_endorsement_to_token(
		&tokenBuf,
		borrowedBuffer(endorsement),
		paramsPtr,
	)); err != nil {
		return nil, err
	}
	token := freeOwnedBuffer(tokenBuf)

	// Step 2: token → full token (includes expiration)
	var fullTokenBuf C.SignalOwnedBuffer
	if err := wrapError(C.signal_group_send_token_to_full_token(
		&fullTokenBuf,
		borrowedBuffer(token),
		C.uint64_t(expiration),
	)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(fullTokenBuf), nil
}

// splitBytestringArray converts a SignalBytestringArray into a Go [][]byte.
func splitBytestringArray(arr C.SignalBytestringArray) [][]byte {
	nItems := int(arr.lengths.length)
	if nItems == 0 {
		return nil
	}

	// Read the lengths array
	lengths := unsafe.Slice(arr.lengths.base, nItems)

	// Read all bytes as a contiguous buffer
	totalBytes := int(arr.bytes.length)
	allBytes := C.GoBytes(unsafe.Pointer(arr.bytes.base), C.int(totalBytes))

	// Split into individual endorsements using the lengths
	result := make([][]byte, nItems)
	offset := 0
	for i := range nItems {
		l := int(lengths[i])
		result[i] = make([]byte, l)
		copy(result[i], allBytes[offset:offset+l])
		offset += l
	}
	return result
}
