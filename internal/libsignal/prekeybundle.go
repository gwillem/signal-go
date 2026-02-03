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
// preKey and kyberPreKey are optional and may be nil. When nil, the corresponding
// ID parameter is ignored (the FFI uses u32::MAX as the None sentinel internally).
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

	// Handle optional pre-key. The C FFI uses u32::MAX to represent None for
	// Option<u32>. Pass MaxUint32 + null pointer when there's no pre-key.
	var cPreKey C.SignalConstPointerPublicKey
	cPreKeyID := uint32(0xFFFFFFFF) // u32::MAX = None
	if preKey != nil {
		cPreKey.raw = preKey.ptr
		cPreKeyID = preKeyID
	}

	// Handle optional Kyber pre-key. Same sentinel logic.
	var cKyberPreKey C.SignalConstPointerKyberPublicKey
	cKyberPreKeyID := uint32(0xFFFFFFFF) // u32::MAX = None
	if kyberPreKey != nil {
		cKyberPreKey.raw = kyberPreKey.ptr
		cKyberPreKeyID = kyberPreKeyID
	}

	// Debug
	println("DEBUG NewPreKeyBundle: preKeyID=", preKeyID, "preKey=", preKey != nil, "cPreKeyID=", cPreKeyID, "cPreKey.raw=", cPreKey.raw != nil)
	println("DEBUG NewPreKeyBundle: kyberID=", kyberPreKeyID, "kyber=", kyberPreKey != nil, "cKyberID=", cKyberPreKeyID, "cKyber.raw=", cKyberPreKey.raw != nil)

	if err := wrapError(C.signal_pre_key_bundle_new(
		&out,
		C.uint32_t(registrationID),
		C.uint32_t(deviceID),
		C.uint32_t(cPreKeyID),
		cPreKey,
		C.uint32_t(signedPreKeyID),
		C.SignalConstPointerPublicKey{raw: signedPreKey.ptr},
		borrowedBuffer(signedPreKeySignature),
		C.SignalConstPointerPublicKey{raw: identityKey.ptr},
		C.uint32_t(cKyberPreKeyID),
		cKyberPreKey,
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
