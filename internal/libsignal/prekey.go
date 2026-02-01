package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// PreKeyRecord wraps a libsignal pre-key record.
type PreKeyRecord struct {
	ptr *C.SignalPreKeyRecord
}

// NewPreKeyRecord creates a new pre-key record from an ID and key pair.
func NewPreKeyRecord(id uint32, pub *PublicKey, priv *PrivateKey) (*PreKeyRecord, error) {
	var out C.SignalMutPointerPreKeyRecord
	pubPtr := C.SignalConstPointerPublicKey{raw: pub.ptr}
	privPtr := C.SignalConstPointerPrivateKey{raw: priv.ptr}
	if err := wrapError(C.signal_pre_key_record_new(&out, C.uint32_t(id), pubPtr, privPtr)); err != nil {
		return nil, err
	}
	return &PreKeyRecord{ptr: out.raw}, nil
}

// DeserializePreKeyRecord reconstructs a pre-key record from serialized form.
func DeserializePreKeyRecord(data []byte) (*PreKeyRecord, error) {
	var out C.SignalMutPointerPreKeyRecord
	if err := wrapError(C.signal_pre_key_record_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &PreKeyRecord{ptr: out.raw}, nil
}

// ID returns the pre-key ID.
func (r *PreKeyRecord) ID() (uint32, error) {
	var out C.uint32_t
	cPtr := C.SignalConstPointerPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_pre_key_record_get_id(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint32(out), nil
}

// PublicKey returns the public key from this record.
func (r *PreKeyRecord) PublicKey() (*PublicKey, error) {
	var out C.SignalMutPointerPublicKey
	cPtr := C.SignalConstPointerPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_pre_key_record_get_public_key(&out, cPtr)); err != nil {
		return nil, err
	}
	return &PublicKey{ptr: out.raw}, nil
}

// PrivateKey returns the private key from this record.
func (r *PreKeyRecord) PrivateKey() (*PrivateKey, error) {
	var out C.SignalMutPointerPrivateKey
	cPtr := C.SignalConstPointerPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_pre_key_record_get_private_key(&out, cPtr)); err != nil {
		return nil, err
	}
	return &PrivateKey{ptr: out.raw}, nil
}

// Serialize returns the serialized form of this pre-key record.
func (r *PreKeyRecord) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_pre_key_record_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Destroy frees the underlying C resource.
func (r *PreKeyRecord) Destroy() {
	if r.ptr != nil {
		C.signal_pre_key_record_destroy(C.SignalMutPointerPreKeyRecord{raw: r.ptr})
		r.ptr = nil
	}
}

// SignedPreKeyRecord wraps a libsignal signed pre-key record.
type SignedPreKeyRecord struct {
	ptr *C.SignalSignedPreKeyRecord
}

// NewSignedPreKeyRecord creates a new signed pre-key record.
func NewSignedPreKeyRecord(id uint32, timestamp uint64, pub *PublicKey, priv *PrivateKey, signature []byte) (*SignedPreKeyRecord, error) {
	var out C.SignalMutPointerSignedPreKeyRecord
	pubPtr := C.SignalConstPointerPublicKey{raw: pub.ptr}
	privPtr := C.SignalConstPointerPrivateKey{raw: priv.ptr}
	if err := wrapError(C.signal_signed_pre_key_record_new(&out, C.uint32_t(id), C.uint64_t(timestamp), pubPtr, privPtr, borrowedBuffer(signature))); err != nil {
		return nil, err
	}
	return &SignedPreKeyRecord{ptr: out.raw}, nil
}

// DeserializeSignedPreKeyRecord reconstructs from serialized form.
func DeserializeSignedPreKeyRecord(data []byte) (*SignedPreKeyRecord, error) {
	var out C.SignalMutPointerSignedPreKeyRecord
	if err := wrapError(C.signal_signed_pre_key_record_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &SignedPreKeyRecord{ptr: out.raw}, nil
}

// ID returns the signed pre-key ID.
func (r *SignedPreKeyRecord) ID() (uint32, error) {
	var out C.uint32_t
	cPtr := C.SignalConstPointerSignedPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_signed_pre_key_record_get_id(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint32(out), nil
}

// PublicKey returns the public key from this signed pre-key record.
func (r *SignedPreKeyRecord) PublicKey() (*PublicKey, error) {
	var out C.SignalMutPointerPublicKey
	cPtr := C.SignalConstPointerSignedPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_signed_pre_key_record_get_public_key(&out, cPtr)); err != nil {
		return nil, err
	}
	return &PublicKey{ptr: out.raw}, nil
}

// Signature returns the signature from this signed pre-key record.
func (r *SignedPreKeyRecord) Signature() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerSignedPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_signed_pre_key_record_get_signature(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Serialize returns the serialized form.
func (r *SignedPreKeyRecord) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerSignedPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_signed_pre_key_record_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Destroy frees the underlying C resource.
func (r *SignedPreKeyRecord) Destroy() {
	if r.ptr != nil {
		C.signal_signed_pre_key_record_destroy(C.SignalMutPointerSignedPreKeyRecord{raw: r.ptr})
		r.ptr = nil
	}
}
