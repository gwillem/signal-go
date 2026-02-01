package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"
import "time"

// ProcessPreKeyBundle establishes a session using a pre-key bundle.
func ProcessPreKeyBundle(
	bundle *PreKeyBundle,
	address *Address,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
	now time.Time,
) error {
	cBundle := C.SignalConstPointerPreKeyBundle{raw: bundle.ptr}
	cAddr := C.SignalConstPointerProtocolAddress{raw: address.ptr}
	cSessionStore, cleanupSession := wrapSessionStore(sessionStore)
	defer cleanupSession()
	cIdentityStore, cleanupIdentity := wrapIdentityKeyStore(identityStore)
	defer cleanupIdentity()
	cSession := C.SignalConstPointerFfiSessionStoreStruct{raw: cSessionStore}
	cIdentity := C.SignalConstPointerFfiIdentityKeyStoreStruct{raw: cIdentityStore}
	nowMs := C.uint64_t(now.UnixMilli())

	return wrapError(C.signal_process_prekey_bundle(cBundle, cAddr, cSession, cIdentity, nowMs))
}

// Encrypt encrypts plaintext for the given address.
func Encrypt(
	plaintext []byte,
	address *Address,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
	now time.Time,
) (*CiphertextMessage, error) {
	var out C.SignalMutPointerCiphertextMessage
	cAddr := C.SignalConstPointerProtocolAddress{raw: address.ptr}
	cSessionStore, cleanupSession := wrapSessionStore(sessionStore)
	defer cleanupSession()
	cIdentityStore, cleanupIdentity := wrapIdentityKeyStore(identityStore)
	defer cleanupIdentity()
	cSession := C.SignalConstPointerFfiSessionStoreStruct{raw: cSessionStore}
	cIdentity := C.SignalConstPointerFfiIdentityKeyStoreStruct{raw: cIdentityStore}
	nowMs := C.uint64_t(now.UnixMilli())

	if err := wrapError(C.signal_encrypt_message(&out, borrowedBuffer(plaintext), cAddr, cSession, cIdentity, nowMs)); err != nil {
		return nil, err
	}
	return &CiphertextMessage{ptr: out.raw}, nil
}

// DecryptPreKeyMessage decrypts a pre-key signal message (first message in a session).
func DecryptPreKeyMessage(
	message *PreKeySignalMessage,
	address *Address,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
	preKeyStore PreKeyStore,
	signedPreKeyStore SignedPreKeyStore,
	kyberPreKeyStore KyberPreKeyStore,
) ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cMsg := C.SignalConstPointerPreKeySignalMessage{raw: message.ptr}
	cAddr := C.SignalConstPointerProtocolAddress{raw: address.ptr}
	cSessionStore, cleanupSession := wrapSessionStore(sessionStore)
	defer cleanupSession()
	cIdentityStore, cleanupIdentity := wrapIdentityKeyStore(identityStore)
	defer cleanupIdentity()
	cPreKeyStore, cleanupPreKey := wrapPreKeyStore(preKeyStore)
	defer cleanupPreKey()
	cSignedStore, cleanupSigned := wrapSignedPreKeyStore(signedPreKeyStore)
	defer cleanupSigned()
	cKyberStore, cleanupKyber := wrapKyberPreKeyStore(kyberPreKeyStore)
	defer cleanupKyber()
	cSession := C.SignalConstPointerFfiSessionStoreStruct{raw: cSessionStore}
	cIdentity := C.SignalConstPointerFfiIdentityKeyStoreStruct{raw: cIdentityStore}
	cPreKey := C.SignalConstPointerFfiPreKeyStoreStruct{raw: cPreKeyStore}
	cSigned := C.SignalConstPointerFfiSignedPreKeyStoreStruct{raw: cSignedStore}
	cKyber := C.SignalConstPointerFfiKyberPreKeyStoreStruct{raw: cKyberStore}

	if err := wrapError(C.signal_decrypt_pre_key_message(&buf, cMsg, cAddr, cSession, cIdentity, cPreKey, cSigned, cKyber)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// DecryptMessage decrypts a regular signal message (after session is established).
func DecryptMessage(
	message *SignalMessage,
	address *Address,
	sessionStore SessionStore,
	identityStore IdentityKeyStore,
) ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cMsg := C.SignalConstPointerSignalMessage{raw: message.ptr}
	cAddr := C.SignalConstPointerProtocolAddress{raw: address.ptr}
	cSessionStore, cleanupSession := wrapSessionStore(sessionStore)
	defer cleanupSession()
	cIdentityStore, cleanupIdentity := wrapIdentityKeyStore(identityStore)
	defer cleanupIdentity()
	cSession := C.SignalConstPointerFfiSessionStoreStruct{raw: cSessionStore}
	cIdentity := C.SignalConstPointerFfiIdentityKeyStoreStruct{raw: cIdentityStore}

	if err := wrapError(C.signal_decrypt_message(&buf, cMsg, cAddr, cSession, cIdentity)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}
