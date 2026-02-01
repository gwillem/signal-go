package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// PreKeyBundle contains all the pre-key material needed to establish a session.
type PreKeyBundle struct {
	ptr *C.SignalPreKeyBundle
}

// NewPreKeyBundle creates a new pre-key bundle with all components (including Kyber).
func NewPreKeyBundle(
	registrationID uint32,
	deviceID uint32,
	preKeyID uint32,
	preKey *PublicKey,
	signedPreKeyID uint32,
	signedPreKey *PublicKey,
	signedPreKeySignature []byte,
	identityKey *PublicKey,
	kyberPreKeyID uint32,
	kyberPreKey *KyberPublicKey,
	kyberPreKeySignature []byte,
) (*PreKeyBundle, error) {
	var out C.SignalMutPointerPreKeyBundle
	if err := wrapError(C.signal_pre_key_bundle_new(
		&out,
		C.uint32_t(registrationID),
		C.uint32_t(deviceID),
		C.uint32_t(preKeyID),
		C.SignalConstPointerPublicKey{raw: preKey.ptr},
		C.uint32_t(signedPreKeyID),
		C.SignalConstPointerPublicKey{raw: signedPreKey.ptr},
		borrowedBuffer(signedPreKeySignature),
		C.SignalConstPointerPublicKey{raw: identityKey.ptr},
		C.uint32_t(kyberPreKeyID),
		C.SignalConstPointerKyberPublicKey{raw: kyberPreKey.ptr},
		borrowedBuffer(kyberPreKeySignature),
	)); err != nil {
		return nil, err
	}
	return &PreKeyBundle{ptr: out.raw}, nil
}

// Destroy frees the underlying C resource.
func (b *PreKeyBundle) Destroy() {
	if b.ptr != nil {
		C.signal_pre_key_bundle_destroy(C.SignalMutPointerPreKeyBundle{raw: b.ptr})
		b.ptr = nil
	}
}
