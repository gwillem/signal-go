package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// KyberKeyPair wraps a libsignal Kyber key pair.
type KyberKeyPair struct {
	ptr *C.SignalKyberKeyPair
}

// GenerateKyberKeyPair generates a new Kyber key pair.
func GenerateKyberKeyPair() (*KyberKeyPair, error) {
	var out C.SignalMutPointerKyberKeyPair
	if err := wrapError(C.signal_kyber_key_pair_generate(&out)); err != nil {
		return nil, err
	}
	return &KyberKeyPair{ptr: out.raw}, nil
}

// PublicKey returns the public key from this Kyber key pair.
func (kp *KyberKeyPair) PublicKey() (*KyberPublicKey, error) {
	var out C.SignalMutPointerKyberPublicKey
	cPtr := C.SignalConstPointerKyberKeyPair{raw: kp.ptr}
	if err := wrapError(C.signal_kyber_key_pair_get_public_key(&out, cPtr)); err != nil {
		return nil, err
	}
	return &KyberPublicKey{ptr: out.raw}, nil
}

// Destroy frees the underlying C resource.
func (kp *KyberKeyPair) Destroy() {
	if kp.ptr != nil {
		C.signal_kyber_key_pair_destroy(C.SignalMutPointerKyberKeyPair{raw: kp.ptr})
		kp.ptr = nil
	}
}

// KyberPublicKey wraps a libsignal Kyber public key.
type KyberPublicKey struct {
	ptr *C.SignalKyberPublicKey
}

// DeserializeKyberPublicKey reconstructs a Kyber public key from serialized form.
func DeserializeKyberPublicKey(data []byte) (*KyberPublicKey, error) {
	var out C.SignalMutPointerKyberPublicKey
	if err := wrapError(C.signal_kyber_public_key_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &KyberPublicKey{ptr: out.raw}, nil
}

// Serialize returns the serialized form of the Kyber public key.
func (k *KyberPublicKey) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerKyberPublicKey{raw: k.ptr}
	if err := wrapError(C.signal_kyber_public_key_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Destroy frees the underlying C resource.
func (k *KyberPublicKey) Destroy() {
	if k.ptr != nil {
		C.signal_kyber_public_key_destroy(C.SignalMutPointerKyberPublicKey{raw: k.ptr})
		k.ptr = nil
	}
}

// KyberPreKeyRecord wraps a libsignal Kyber pre-key record.
type KyberPreKeyRecord struct {
	ptr *C.SignalKyberPreKeyRecord
}

// NewKyberPreKeyRecord creates a new Kyber pre-key record.
func NewKyberPreKeyRecord(id uint32, timestamp uint64, keyPair *KyberKeyPair, signature []byte) (*KyberPreKeyRecord, error) {
	var out C.SignalMutPointerKyberPreKeyRecord
	kpPtr := C.SignalConstPointerKyberKeyPair{raw: keyPair.ptr}
	if err := wrapError(C.signal_kyber_pre_key_record_new(&out, C.uint32_t(id), C.uint64_t(timestamp), kpPtr, borrowedBuffer(signature))); err != nil {
		return nil, err
	}
	return &KyberPreKeyRecord{ptr: out.raw}, nil
}

// DeserializeKyberPreKeyRecord reconstructs from serialized form.
func DeserializeKyberPreKeyRecord(data []byte) (*KyberPreKeyRecord, error) {
	var out C.SignalMutPointerKyberPreKeyRecord
	if err := wrapError(C.signal_kyber_pre_key_record_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &KyberPreKeyRecord{ptr: out.raw}, nil
}

// ID returns the Kyber pre-key ID.
func (r *KyberPreKeyRecord) ID() (uint32, error) {
	var out C.uint32_t
	cPtr := C.SignalConstPointerKyberPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_kyber_pre_key_record_get_id(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint32(out), nil
}

// PublicKey returns the Kyber public key from this record.
func (r *KyberPreKeyRecord) PublicKey() (*KyberPublicKey, error) {
	var out C.SignalMutPointerKyberPublicKey
	cPtr := C.SignalConstPointerKyberPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_kyber_pre_key_record_get_public_key(&out, cPtr)); err != nil {
		return nil, err
	}
	return &KyberPublicKey{ptr: out.raw}, nil
}

// Signature returns the signature from this Kyber pre-key record.
func (r *KyberPreKeyRecord) Signature() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerKyberPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_kyber_pre_key_record_get_signature(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Serialize returns the serialized form.
func (r *KyberPreKeyRecord) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerKyberPreKeyRecord{raw: r.ptr}
	if err := wrapError(C.signal_kyber_pre_key_record_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// Destroy frees the underlying C resource.
func (r *KyberPreKeyRecord) Destroy() {
	if r.ptr != nil {
		C.signal_kyber_pre_key_record_destroy(C.SignalMutPointerKyberPreKeyRecord{raw: r.ptr})
		r.ptr = nil
	}
}
