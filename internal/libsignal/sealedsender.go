package libsignal

/*
#include "libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

// SealedSenderResult holds the decrypted plaintext and sender information
// from a sealed sender (UNIDENTIFIED_SENDER) envelope.
type SealedSenderResult struct {
	Plaintext    []byte
	SenderUUID   string
	SenderE164   string // may be empty
	SenderDevice uint32
}

// UnidentifiedSenderMessageContent wraps the decrypted outer layer of a
// sealed sender message. Contains the sender certificate and the inner
// encrypted message.
type UnidentifiedSenderMessageContent struct {
	ptr *C.SignalUnidentifiedSenderMessageContent
}

// Destroy frees the underlying C resource.
func (u *UnidentifiedSenderMessageContent) Destroy() {
	if u.ptr != nil {
		C.signal_unidentified_sender_message_content_destroy(C.SignalMutPointerUnidentifiedSenderMessageContent{raw: u.ptr})
		u.ptr = nil
	}
}

// MsgType returns the inner message type (CiphertextMessageTypeWhisper, CiphertextMessageTypePreKey, etc).
func (u *UnidentifiedSenderMessageContent) MsgType() (uint8, error) {
	var out C.uint8_t
	cPtr := C.SignalConstPointerUnidentifiedSenderMessageContent{raw: u.ptr}
	if err := wrapError(C.signal_unidentified_sender_message_content_get_msg_type(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint8(out), nil
}

// Contents returns the inner encrypted message bytes.
func (u *UnidentifiedSenderMessageContent) Contents() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerUnidentifiedSenderMessageContent{raw: u.ptr}
	if err := wrapError(C.signal_unidentified_sender_message_content_get_contents(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// SenderCertificate wraps a Signal sender certificate from a sealed sender message.
type SenderCertificate struct {
	ptr *C.SignalSenderCertificate
}

// Destroy frees the underlying C resource.
func (sc *SenderCertificate) Destroy() {
	if sc.ptr != nil {
		C.signal_sender_certificate_destroy(C.SignalMutPointerSenderCertificate{raw: sc.ptr})
		sc.ptr = nil
	}
}

// SenderUUID returns the sender's UUID from the certificate.
func (sc *SenderCertificate) SenderUUID() (string, error) {
	var out *C.char
	cPtr := C.SignalConstPointerSenderCertificate{raw: sc.ptr}
	if err := wrapError(C.signal_sender_certificate_get_sender_uuid(&out, cPtr)); err != nil {
		return "", err
	}
	if out == nil {
		return "", nil
	}
	s := C.GoString(out)
	C.signal_free_string(out)
	return s, nil
}

// SenderE164 returns the sender's phone number from the certificate (may be empty).
func (sc *SenderCertificate) SenderE164() (string, error) {
	var out *C.char
	cPtr := C.SignalConstPointerSenderCertificate{raw: sc.ptr}
	if err := wrapError(C.signal_sender_certificate_get_sender_e164(&out, cPtr)); err != nil {
		return "", err
	}
	if out == nil {
		return "", nil
	}
	s := C.GoString(out)
	C.signal_free_string(out)
	return s, nil
}

// DeviceID returns the sender's device ID from the certificate.
func (sc *SenderCertificate) DeviceID() (uint32, error) {
	var out C.uint32_t
	cPtr := C.SignalConstPointerSenderCertificate{raw: sc.ptr}
	if err := wrapError(C.signal_sender_certificate_get_device_id(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint32(out), nil
}

// Validate checks the certificate against a trust root and timestamp.
func (sc *SenderCertificate) Validate(trustRoot *PublicKey, timestamp uint64) (bool, error) {
	var out C.bool
	cCert := C.SignalConstPointerSenderCertificate{raw: sc.ptr}
	cKey := C.SignalConstPointerPublicKey{raw: trustRoot.ptr}
	if err := wrapError(C.signal_sender_certificate_validate(&out, cCert, cKey, C.uint64_t(timestamp))); err != nil {
		return false, err
	}
	return bool(out), nil
}

// GetSenderCert extracts the sender certificate from the USMC.
func (u *UnidentifiedSenderMessageContent) GetSenderCert() (*SenderCertificate, error) {
	var out C.SignalMutPointerSenderCertificate
	cPtr := C.SignalConstPointerUnidentifiedSenderMessageContent{raw: u.ptr}
	if err := wrapError(C.signal_unidentified_sender_message_content_get_sender_cert(&out, cPtr)); err != nil {
		return nil, err
	}
	return &SenderCertificate{ptr: out.raw}, nil
}

// SealedSenderDecryptToUSMC decrypts the outer layer of a sealed sender message,
// returning the UnidentifiedSenderMessageContent. This uses only the identity
// key store (for ECDH) and does not decrypt the inner message.
func SealedSenderDecryptToUSMC(
	ctext []byte,
	identityStore IdentityKeyStore,
) (*UnidentifiedSenderMessageContent, error) {
	var out C.SignalMutPointerUnidentifiedSenderMessageContent
	cIdentityStore, cleanupIdentity := wrapIdentityKeyStore(identityStore)
	defer cleanupIdentity()
	cIdentity := C.SignalConstPointerFfiIdentityKeyStoreStruct{raw: cIdentityStore}

	if err := wrapError(C.signal_sealed_session_cipher_decrypt_to_usmc(&out, borrowedBuffer(ctext), cIdentity)); err != nil {
		return nil, err
	}
	return &UnidentifiedSenderMessageContent{ptr: out.raw}, nil
}

// SealedSenderDecrypt decrypts a sealed sender ciphertext using
// signal_sealed_session_cipher_decrypt. Note: this function does NOT
// support Kyber/PQXDH pre-keys. For modern messages, use the two-step
// approach: SealedSenderDecryptToUSMC + manual inner decrypt.
func SealedSenderDecrypt(
	ctext []byte,
	trustRoot *PublicKey,
	timestamp uint64,
	localE164 string,
	localUUID string,
	localDeviceID uint32,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
	preKeyStore PreKeyStore,
	signedPreKeyStore SignedPreKeyStore,
) (*SealedSenderResult, error) {
	var out C.SignalOwnedBuffer
	var senderE164 *C.char
	var senderUUID *C.char
	var senderDeviceID C.uint32_t

	cTrustRoot := C.SignalConstPointerPublicKey{raw: trustRoot.ptr}

	// local_e164 can be NULL
	var cLocalE164 *C.char
	if localE164 != "" {
		cLocalE164 = C.CString(localE164)
		defer C.free(unsafe.Pointer(cLocalE164))
	}

	cLocalUUID := C.CString(localUUID)
	defer C.free(unsafe.Pointer(cLocalUUID))

	cSessionStore, cleanupSession := wrapSessionStore(sessionStore)
	defer cleanupSession()
	cIdentityStore, cleanupIdentity := wrapIdentityKeyStore(identityStore)
	defer cleanupIdentity()
	cPreKeyStore, cleanupPreKey := wrapPreKeyStore(preKeyStore)
	defer cleanupPreKey()
	cSignedStore, cleanupSigned := wrapSignedPreKeyStore(signedPreKeyStore)
	defer cleanupSigned()

	cSession := C.SignalConstPointerFfiSessionStoreStruct{raw: cSessionStore}
	cIdentity := C.SignalConstPointerFfiIdentityKeyStoreStruct{raw: cIdentityStore}
	cPreKey := C.SignalConstPointerFfiPreKeyStoreStruct{raw: cPreKeyStore}
	cSigned := C.SignalConstPointerFfiSignedPreKeyStoreStruct{raw: cSignedStore}

	err := wrapError(C.signal_sealed_session_cipher_decrypt(
		&out,
		&senderE164,
		&senderUUID,
		&senderDeviceID,
		borrowedBuffer(ctext),
		cTrustRoot,
		C.uint64_t(timestamp),
		cLocalE164,
		cLocalUUID,
		C.uint(localDeviceID),
		cSession,
		cIdentity,
		cPreKey,
		cSigned,
	))
	if err != nil {
		return nil, err
	}

	result := &SealedSenderResult{
		Plaintext:    freeOwnedBuffer(out),
		SenderDevice: uint32(senderDeviceID),
	}

	if senderUUID != nil {
		result.SenderUUID = C.GoString(senderUUID)
		C.signal_free_string(senderUUID)
	}
	if senderE164 != nil {
		result.SenderE164 = C.GoString(senderE164)
		C.signal_free_string(senderE164)
	}

	return result, nil
}
