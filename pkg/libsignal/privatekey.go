package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"
import "unsafe"

// PrivateKey wraps a libsignal EC private key.
type PrivateKey struct {
	ptr *C.SignalPrivateKey
}

// GeneratePrivateKey generates a new random EC private key.
func GeneratePrivateKey() (*PrivateKey, error) {
	var out C.SignalMutPointerPrivateKey
	if err := wrapError(C.signal_privatekey_generate(&out)); err != nil {
		return nil, err
	}
	return &PrivateKey{ptr: out.raw}, nil
}

// DeserializePrivateKey reconstructs a private key from its serialized form.
func DeserializePrivateKey(data []byte) (*PrivateKey, error) {
	var out C.SignalMutPointerPrivateKey
	borrowed := borrowedBuffer(data)
	if err := wrapError(C.signal_privatekey_deserialize(&out, borrowed)); err != nil {
		return nil, err
	}
	return &PrivateKey{ptr: out.raw}, nil
}

// Serialize returns the 32-byte serialized form of the private key.
func (k *PrivateKey) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerPrivateKey{raw: k.ptr}
	if err := wrapError(C.signal_privatekey_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Sign produces an Ed25519-compatible signature of message.
func (k *PrivateKey) Sign(message []byte) ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerPrivateKey{raw: k.ptr}
	if err := wrapError(C.signal_privatekey_sign(&buf, cPtr, borrowedBuffer(message))); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Agree performs X25519 key agreement with the given public key.
func (k *PrivateKey) Agree(pub *PublicKey) ([]byte, error) {
	var buf C.SignalOwnedBuffer
	privPtr := C.SignalConstPointerPrivateKey{raw: k.ptr}
	pubPtr := C.SignalConstPointerPublicKey{raw: pub.ptr}
	if err := wrapError(C.signal_privatekey_agree(&buf, privPtr, pubPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Destroy frees the underlying C resource.
func (k *PrivateKey) Destroy() {
	if k.ptr != nil {
		C.signal_privatekey_destroy(C.SignalMutPointerPrivateKey{raw: k.ptr})
		k.ptr = nil
	}
}

// borrowedBuffer creates a SignalBorrowedBuffer pointing into a Go byte slice.
// The slice must remain valid for the duration of the C call.
func borrowedBuffer(data []byte) C.SignalBorrowedBuffer {
	if len(data) == 0 {
		return C.SignalBorrowedBuffer{base: nil, length: 0}
	}
	return C.SignalBorrowedBuffer{
		base:   (*C.uchar)(unsafe.Pointer(&data[0])),
		length: C.size_t(len(data)),
	}
}
