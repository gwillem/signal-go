package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// PublicKey wraps a libsignal EC public key.
type PublicKey struct {
	ptr *C.SignalPublicKey
}

// PublicKey derives the public key from this private key.
func (k *PrivateKey) PublicKey() (*PublicKey, error) {
	var out C.SignalMutPointerPublicKey
	cPtr := C.SignalConstPointerPrivateKey{raw: k.ptr}
	if err := wrapError(C.signal_privatekey_get_public_key(&out, cPtr)); err != nil {
		return nil, err
	}
	return &PublicKey{ptr: out.raw}, nil
}

// Serialize returns the 33-byte serialized form of the public key.
func (k *PublicKey) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerPublicKey{raw: k.ptr}
	if err := wrapError(C.signal_publickey_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// DeserializePublicKey reconstructs a public key from its serialized form.
func DeserializePublicKey(data []byte) (*PublicKey, error) {
	var out C.SignalMutPointerPublicKey
	borrowed := borrowedBuffer(data)
	if err := wrapError(C.signal_publickey_deserialize(&out, borrowed)); err != nil {
		return nil, err
	}
	return &PublicKey{ptr: out.raw}, nil
}

// Compare compares two public keys. Returns 0 if equal, negative if k < other, positive if k > other.
func (k *PublicKey) Compare(other *PublicKey) (int, error) {
	var out C.int32_t
	k1 := C.SignalConstPointerPublicKey{raw: k.ptr}
	k2 := C.SignalConstPointerPublicKey{raw: other.ptr}
	if err := wrapError(C.signal_publickey_compare(&out, k1, k2)); err != nil {
		return 0, err
	}
	return int(out), nil
}

// Verify checks that signature is valid for message under this public key.
func (k *PublicKey) Verify(message, signature []byte) (bool, error) {
	var out C.bool
	cPtr := C.SignalConstPointerPublicKey{raw: k.ptr}
	if err := wrapError(C.signal_publickey_verify(&out, cPtr, borrowedBuffer(message), borrowedBuffer(signature))); err != nil {
		return false, err
	}
	return bool(out), nil
}

// Destroy frees the underlying C resource.
func (k *PublicKey) Destroy() {
	if k.ptr != nil {
		C.signal_publickey_destroy(C.SignalMutPointerPublicKey{raw: k.ptr})
		k.ptr = nil
	}
}
