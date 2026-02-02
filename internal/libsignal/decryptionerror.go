package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// DecryptionErrorMessage wraps a libsignal DecryptionErrorMessage.
// It is used to notify a sender that we could not decrypt their message.
type DecryptionErrorMessage struct {
	ptr *C.SignalDecryptionErrorMessage
}

// NewDecryptionErrorMessage creates a DecryptionErrorMessage for a failed
// original message. originalBytes is the raw ciphertext content, originalType
// is the CiphertextMessage type constant, timestamp is the envelope timestamp,
// and senderDeviceID is the sender's device ID.
func NewDecryptionErrorMessage(originalBytes []byte, originalType uint8, timestamp uint64, senderDeviceID uint32) (*DecryptionErrorMessage, error) {
	var out C.SignalMutPointerDecryptionErrorMessage
	if err := wrapError(C.signal_decryption_error_message_for_original_message(
		&out,
		borrowedBuffer(originalBytes),
		C.uint8_t(originalType),
		C.uint64_t(timestamp),
		C.uint32_t(senderDeviceID),
	)); err != nil {
		return nil, err
	}
	return &DecryptionErrorMessage{ptr: out.raw}, nil
}

// DeserializeDecryptionErrorMessage reconstructs from serialized form.
func DeserializeDecryptionErrorMessage(data []byte) (*DecryptionErrorMessage, error) {
	var out C.SignalMutPointerDecryptionErrorMessage
	if err := wrapError(C.signal_decryption_error_message_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &DecryptionErrorMessage{ptr: out.raw}, nil
}

// ExtractDecryptionErrorFromContent extracts a DecryptionErrorMessage from
// serialized Content bytes (as received in a PLAINTEXT_CONTENT envelope body).
func ExtractDecryptionErrorFromContent(data []byte) (*DecryptionErrorMessage, error) {
	var out C.SignalMutPointerDecryptionErrorMessage
	if err := wrapError(C.signal_decryption_error_message_extract_from_serialized_content(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &DecryptionErrorMessage{ptr: out.raw}, nil
}

// Serialize returns the serialized form of the DecryptionErrorMessage.
func (d *DecryptionErrorMessage) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerDecryptionErrorMessage{raw: d.ptr}
	if err := wrapError(C.signal_decryption_error_message_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Timestamp returns the original message timestamp.
func (d *DecryptionErrorMessage) Timestamp() (uint64, error) {
	var out C.uint64_t
	cPtr := C.SignalConstPointerDecryptionErrorMessage{raw: d.ptr}
	if err := wrapError(C.signal_decryption_error_message_get_timestamp(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint64(out), nil
}

// DeviceID returns the original sender's device ID.
func (d *DecryptionErrorMessage) DeviceID() (uint32, error) {
	var out C.uint32_t
	cPtr := C.SignalConstPointerDecryptionErrorMessage{raw: d.ptr}
	if err := wrapError(C.signal_decryption_error_message_get_device_id(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint32(out), nil
}

// RatchetKey returns the ratchet key from the failed message, if available.
// Returns nil, nil if no ratchet key is present.
func (d *DecryptionErrorMessage) RatchetKey() (*PublicKey, error) {
	var out C.SignalMutPointerPublicKey
	cPtr := C.SignalConstPointerDecryptionErrorMessage{raw: d.ptr}
	if err := wrapError(C.signal_decryption_error_message_get_ratchet_key(&out, cPtr)); err != nil {
		return nil, err
	}
	if out.raw == nil {
		return nil, nil
	}
	return &PublicKey{ptr: out.raw}, nil
}

// Destroy frees the underlying C resource.
func (d *DecryptionErrorMessage) Destroy() {
	if d.ptr != nil {
		C.signal_decryption_error_message_destroy(C.SignalMutPointerDecryptionErrorMessage{raw: d.ptr})
		d.ptr = nil
	}
}
