package libsignal

/*
#include "libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

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
	// v0.87.0 changed to take a slice of trust roots
	cKey := C.SignalConstPointerPublicKey{raw: trustRoot.ptr}
	cTrustRoots := C.SignalBorrowedSliceOfConstPointerPublicKey{
		base:   &cKey,
		length: 1,
	}
	if err := wrapError(C.signal_sender_certificate_validate(&out, cCert, cTrustRoots, C.uint64_t(timestamp))); err != nil {
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

// ContentHint constants for UnidentifiedSenderMessageContent.
const (
	ContentHintDefault    uint32 = 0
	ContentHintResendable uint32 = 1
	ContentHintImplicit   uint32 = 2
)

// ServerCertificate wraps a Signal server certificate for sealed sender.
type ServerCertificate struct {
	ptr *C.SignalServerCertificate
}

// NewServerCertificate creates a new server certificate signed by the trust root.
func NewServerCertificate(keyID uint32, serverKey *PublicKey, trustRoot *PrivateKey) (*ServerCertificate, error) {
	var out C.SignalMutPointerServerCertificate
	cServerKey := C.SignalConstPointerPublicKey{raw: serverKey.ptr}
	cTrustRoot := C.SignalConstPointerPrivateKey{raw: trustRoot.ptr}

	if err := wrapError(C.signal_server_certificate_new(&out, C.uint32_t(keyID), cServerKey, cTrustRoot)); err != nil {
		return nil, err
	}
	return &ServerCertificate{ptr: out.raw}, nil
}

// Destroy frees the underlying C resource.
func (sc *ServerCertificate) Destroy() {
	if sc.ptr != nil {
		C.signal_server_certificate_destroy(C.SignalMutPointerServerCertificate{raw: sc.ptr})
		sc.ptr = nil
	}
}

// DeserializeSenderCertificate deserializes a sender certificate from bytes.
// This is used to parse sender certificates received from the Signal server.
func DeserializeSenderCertificate(data []byte) (*SenderCertificate, error) {
	var out C.SignalMutPointerSenderCertificate
	if err := wrapError(C.signal_sender_certificate_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &SenderCertificate{ptr: out.raw}, nil
}

// NewSenderCertificate creates a new sender certificate.
func NewSenderCertificate(
	senderUUID string,
	senderE164 string, // may be empty
	senderKey *PublicKey,
	senderDeviceID uint32,
	expiration uint64,
	signerCert *ServerCertificate,
	signerKey *PrivateKey,
) (*SenderCertificate, error) {
	var out C.SignalMutPointerSenderCertificate

	cSenderUUID := C.CString(senderUUID)
	defer C.free(unsafe.Pointer(cSenderUUID))

	var cSenderE164 *C.char
	if senderE164 != "" {
		cSenderE164 = C.CString(senderE164)
		defer C.free(unsafe.Pointer(cSenderE164))
	}

	cSenderKey := C.SignalConstPointerPublicKey{raw: senderKey.ptr}
	cSignerCert := C.SignalConstPointerServerCertificate{raw: signerCert.ptr}
	cSignerKey := C.SignalConstPointerPrivateKey{raw: signerKey.ptr}

	if err := wrapError(C.signal_sender_certificate_new(
		&out,
		cSenderUUID,
		cSenderE164,
		C.uint32_t(senderDeviceID),
		cSenderKey,
		C.uint64_t(expiration),
		cSignerCert,
		cSignerKey,
	)); err != nil {
		return nil, err
	}
	return &SenderCertificate{ptr: out.raw}, nil
}

// NewUnidentifiedSenderMessageContent creates a new USMC wrapping an encrypted message.
func NewUnidentifiedSenderMessageContent(
	message *CiphertextMessage,
	senderCert *SenderCertificate,
	contentHint uint32,
	groupID []byte, // may be nil for non-group messages
) (*UnidentifiedSenderMessageContent, error) {
	var out C.SignalMutPointerUnidentifiedSenderMessageContent

	cMessage := C.SignalConstPointerCiphertextMessage{raw: message.ptr}
	cSenderCert := C.SignalConstPointerSenderCertificate{raw: senderCert.ptr}

	var cGroupID C.SignalBorrowedBuffer
	if len(groupID) > 0 {
		cGroupID = borrowedBuffer(groupID)
	} else {
		cGroupID = borrowedBuffer(nil)
	}

	if err := wrapError(C.signal_unidentified_sender_message_content_new(
		&out,
		cMessage,
		cSenderCert,
		C.uint32_t(contentHint),
		cGroupID,
	)); err != nil {
		return nil, err
	}
	return &UnidentifiedSenderMessageContent{ptr: out.raw}, nil
}

// SealedSenderEncrypt encrypts a USMC using sealed sender (SSv1).
// Uses the recipient's identity key for ECDH.
func SealedSenderEncrypt(
	destination *Address,
	content *UnidentifiedSenderMessageContent,
	identityStore IdentityKeyStore,
) ([]byte, error) {
	var out C.SignalOwnedBuffer

	cDest := C.SignalConstPointerProtocolAddress{raw: destination.ptr}
	cContent := C.SignalConstPointerUnidentifiedSenderMessageContent{raw: content.ptr}

	cIdentityStore, cleanupIdentity := wrapIdentityKeyStore(identityStore)
	defer cleanupIdentity()
	cIdentity := C.SignalConstPointerFfiIdentityKeyStoreStruct{raw: cIdentityStore}

	if err := wrapError(C.signal_sealed_session_cipher_encrypt(&out, cDest, cContent, cIdentity)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(out), nil
}
