package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// PlaintextContent wraps a libsignal PlaintextContent message.
// PlaintextContent is used to send DecryptionErrorMessage (retry receipts)
// without encryption — it is sent as-is in a PLAINTEXT_CONTENT envelope.
type PlaintextContent struct {
	ptr *C.SignalPlaintextContent
}

// NewPlaintextContentFromDecryptionError creates a PlaintextContent wrapping
// a DecryptionErrorMessage.
func NewPlaintextContentFromDecryptionError(dem *DecryptionErrorMessage) (*PlaintextContent, error) {
	var out C.SignalMutPointerPlaintextContent
	cDem := C.SignalConstPointerDecryptionErrorMessage{raw: dem.ptr}
	if err := wrapError(C.signal_plaintext_content_from_decryption_error_message(&out, cDem)); err != nil {
		return nil, err
	}
	return &PlaintextContent{ptr: out.raw}, nil
}

// DeserializePlaintextContent reconstructs from serialized form.
func DeserializePlaintextContent(data []byte) (*PlaintextContent, error) {
	var out C.SignalMutPointerPlaintextContent
	if err := wrapError(C.signal_plaintext_content_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &PlaintextContent{ptr: out.raw}, nil
}

// Serialize returns the serialized form of the PlaintextContent.
func (p *PlaintextContent) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerPlaintextContent{raw: p.ptr}
	if err := wrapError(C.signal_plaintext_content_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Body returns the inner body of the PlaintextContent (a serialized Content protobuf).
func (p *PlaintextContent) Body() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerPlaintextContent{raw: p.ptr}
	if err := wrapError(C.signal_plaintext_content_get_body(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Destroy frees the underlying C resource.
func (p *PlaintextContent) Destroy() {
	if p.ptr != nil {
		C.signal_plaintext_content_destroy(C.SignalMutPointerPlaintextContent{raw: p.ptr})
		p.ptr = nil
	}
}

// CiphertextMessageFromPlaintextContent converts a PlaintextContent into a
// CiphertextMessage (type=PLAINTEXT) for use with the message sending path.
func CiphertextMessageFromPlaintextContent(p *PlaintextContent) (*CiphertextMessage, error) {
	var out C.SignalMutPointerCiphertextMessage
	cPtr := C.SignalConstPointerPlaintextContent{raw: p.ptr}
	if err := wrapError(C.signal_ciphertext_message_from_plaintext_content(&out, cPtr)); err != nil {
		return nil, err
	}
	return &CiphertextMessage{ptr: out.raw}, nil
}
