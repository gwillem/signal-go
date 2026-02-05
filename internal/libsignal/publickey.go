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

// Equals checks if two public keys are equal.
func (k *PublicKey) Equals(other *PublicKey) (bool, error) {
	var out C.bool
	k1 := C.SignalConstPointerPublicKey{raw: k.ptr}
	k2 := C.SignalConstPointerPublicKey{raw: other.ptr}
	if err := wrapError(C.signal_publickey_equals(&out, k1, k2)); err != nil {
		return false, err
	}
	return bool(out), nil
}

// Compare compares two public keys. Returns 0 if equal, non-zero otherwise.
// Note: v0.87.0 removed ordering comparison; this only tests equality.
func (k *PublicKey) Compare(other *PublicKey) (int, error) {
	eq, err := k.Equals(other)
	if err != nil {
		return 0, err
	}
	if eq {
		return 0, nil
	}
	return 1, nil
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
