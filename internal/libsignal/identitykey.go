package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// IdentityKeyPair holds a public/private key pair used as a long-term identity.
type IdentityKeyPair struct {
	PublicKey  *PublicKey
	PrivateKey *PrivateKey
}

// GenerateIdentityKeyPair creates a new random identity key pair.
func GenerateIdentityKeyPair() (*IdentityKeyPair, error) {
	priv, err := GeneratePrivateKey()
	if err != nil {
		return nil, err
	}
	pub, err := priv.PublicKey()
	if err != nil {
		priv.Destroy()
		return nil, err
	}
	return &IdentityKeyPair{PublicKey: pub, PrivateKey: priv}, nil
}

// SerializeIdentityKeyPair serializes the identity key pair to bytes.
func SerializeIdentityKeyPair(pub *PublicKey, priv *PrivateKey) ([]byte, error) {
	var buf C.SignalOwnedBuffer
	pubPtr := C.SignalConstPointerPublicKey{raw: pub.ptr}
	privPtr := C.SignalConstPointerPrivateKey{raw: priv.ptr}
	if err := wrapError(C.signal_identitykeypair_serialize(&buf, pubPtr, privPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Serialize serializes this identity key pair to bytes.
func (kp *IdentityKeyPair) Serialize() ([]byte, error) {
	return SerializeIdentityKeyPair(kp.PublicKey, kp.PrivateKey)
}

// DeserializeIdentityKeyPair reconstructs an identity key pair from serialized form.
func DeserializeIdentityKeyPair(data []byte) (*IdentityKeyPair, error) {
	var privOut C.SignalMutPointerPrivateKey
	var pubOut C.SignalMutPointerPublicKey
	borrowed := borrowedBuffer(data)
	if err := wrapError(C.signal_identitykeypair_deserialize(&privOut, &pubOut, borrowed)); err != nil {
		return nil, err
	}
	return &IdentityKeyPair{
		PublicKey:  &PublicKey{ptr: pubOut.raw},
		PrivateKey: &PrivateKey{ptr: privOut.raw},
	}, nil
}

// Destroy frees both keys.
func (kp *IdentityKeyPair) Destroy() {
	if kp.PublicKey != nil {
		kp.PublicKey.Destroy()
	}
	if kp.PrivateKey != nil {
		kp.PrivateKey.Destroy()
	}
}
