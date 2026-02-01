package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// CiphertextMessage type constants.
const (
	CiphertextMessageTypeWhisper   = 2
	CiphertextMessageTypePreKey    = 3
	CiphertextMessageTypeSenderKey = 7
	CiphertextMessageTypePlaintext = 8
)

// CiphertextMessage wraps a libsignal ciphertext message.
type CiphertextMessage struct {
	ptr *C.SignalCiphertextMessage
}

// Type returns the message type (PreKey, Whisper, etc).
func (m *CiphertextMessage) Type() (uint8, error) {
	var out C.uint8_t
	cPtr := C.SignalConstPointerCiphertextMessage{raw: m.ptr}
	if err := wrapError(C.signal_ciphertext_message_type(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint8(out), nil
}

// Serialize returns the serialized form of the ciphertext message.
func (m *CiphertextMessage) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerCiphertextMessage{raw: m.ptr}
	if err := wrapError(C.signal_ciphertext_message_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Destroy frees the underlying C resource.
func (m *CiphertextMessage) Destroy() {
	if m.ptr != nil {
		C.signal_ciphertext_message_destroy(C.SignalMutPointerCiphertextMessage{raw: m.ptr})
		m.ptr = nil
	}
}

// PreKeySignalMessage wraps a pre-key signal message (first message in a session).
type PreKeySignalMessage struct {
	ptr *C.SignalPreKeySignalMessage
}

// DeserializePreKeySignalMessage reconstructs from serialized form.
func DeserializePreKeySignalMessage(data []byte) (*PreKeySignalMessage, error) {
	var out C.SignalMutPointerPreKeySignalMessage
	if err := wrapError(C.signal_pre_key_signal_message_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &PreKeySignalMessage{ptr: out.raw}, nil
}

// Serialize returns the serialized form.
func (m *PreKeySignalMessage) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerPreKeySignalMessage{raw: m.ptr}
	if err := wrapError(C.signal_pre_key_signal_message_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Destroy frees the underlying C resource.
func (m *PreKeySignalMessage) Destroy() {
	if m.ptr != nil {
		C.signal_pre_key_signal_message_destroy(C.SignalMutPointerPreKeySignalMessage{raw: m.ptr})
		m.ptr = nil
	}
}

// SignalMessage wraps a regular signal message (after session is established).
type SignalMessage struct {
	ptr *C.SignalMessage
}

// DeserializeSignalMessage reconstructs from serialized form.
func DeserializeSignalMessage(data []byte) (*SignalMessage, error) {
	var out C.SignalMutPointerSignalMessage
	if err := wrapError(C.signal_message_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &SignalMessage{ptr: out.raw}, nil
}

// Destroy frees the underlying C resource.
func (m *SignalMessage) Destroy() {
	if m.ptr != nil {
		C.signal_message_destroy(C.SignalMutPointerSignalMessage{raw: m.ptr})
		m.ptr = nil
	}
}
