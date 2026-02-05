package libsignal

/*
#include "libsignal-ffi.h"

// Bridge functions defined in bridge.c — each wraps a Go //export function,
// converting by-value wrapper structs to raw pointers.
extern int bridge_load_session(void *ctx, SignalMutPointerSessionRecord *recordp, SignalMutPointerProtocolAddress address);
extern int bridge_store_session(void *ctx, SignalMutPointerProtocolAddress address, SignalMutPointerSessionRecord record);
extern int bridge_get_identity_key_pair(void *ctx, SignalMutPointerPrivateKey *keyp);
extern int bridge_get_local_registration_id(void *ctx, uint32_t *idp);
extern int bridge_save_identity_key(void *ctx, uint8_t *out, SignalMutPointerProtocolAddress address, SignalMutPointerPublicKey key);
extern int bridge_get_identity_key(void *ctx, SignalMutPointerPublicKey *keyp, SignalMutPointerProtocolAddress address);
extern int bridge_is_trusted_identity(void *ctx, bool *out, SignalMutPointerProtocolAddress address, SignalMutPointerPublicKey key, uint32_t direction);
extern int bridge_load_pre_key(void *ctx, SignalMutPointerPreKeyRecord *recordp, uint32_t id);
extern int bridge_store_pre_key(void *ctx, uint32_t id, SignalMutPointerPreKeyRecord record);
extern int bridge_remove_pre_key(void *ctx, uint32_t id);
extern int bridge_load_signed_pre_key(void *ctx, SignalMutPointerSignedPreKeyRecord *recordp, uint32_t id);
extern int bridge_store_signed_pre_key(void *ctx, uint32_t id, SignalMutPointerSignedPreKeyRecord record);
extern int bridge_load_kyber_pre_key(void *ctx, SignalMutPointerKyberPreKeyRecord *recordp, uint32_t id);
extern int bridge_store_kyber_pre_key(void *ctx, uint32_t id, SignalMutPointerKyberPreKeyRecord record);
extern int bridge_mark_kyber_pre_key_used(void *ctx, uint32_t id, uint32_t ec_prekey_id, SignalMutPointerPublicKey base_key);
// No-op destroy function - Go handles actual cleanup via deferred cleanup functions.
extern void bridge_noop_destroy(void *ctx);
*/
import "C"
import (
	"runtime"
	"unsafe"
)

// --- Session Store callbacks ---

//export goLoadSession
func goLoadSession(ctx unsafe.Pointer, recordp *C.SignalMutPointerSessionRecord, address *C.SignalProtocolAddress) C.int {
	store := restorePointer(ctx).(SessionStore)
	addr := &Address{ptr: address}
	rec, err := store.LoadSession(addr)
	addr.ptr = nil // prevent Destroy of borrowed pointer
	if err != nil {
		return -1
	}
	if rec != nil {
		recordp.raw = rec.ptr
	}
	return 0
}

//export goStoreSession
func goStoreSession(ctx unsafe.Pointer, address *C.SignalProtocolAddress, record *C.SignalSessionRecord) C.int {
	store := restorePointer(ctx).(SessionStore)
	addr := &Address{ptr: address}

	// Clone the session record since we're borrowing the C pointer
	var clonedBuf C.SignalOwnedBuffer
	if err := wrapError(C.signal_session_record_serialize(&clonedBuf, C.SignalConstPointerSessionRecord{raw: record})); err != nil {
		return -1
	}
	data := freeOwnedBuffer(clonedBuf)
	rec, err := DeserializeSessionRecord(data)
	if err != nil {
		return -1
	}

	err = store.StoreSession(addr, rec)
	addr.ptr = nil
	if err != nil {
		return -1
	}
	return 0
}

// --- Identity Key Store callbacks ---

//export goGetIdentityKeyPair
func goGetIdentityKeyPair(ctx unsafe.Pointer, keyp *C.SignalMutPointerPrivateKey) C.int {
	store := restorePointer(ctx).(IdentityKeyStore)
	key, err := store.GetIdentityKeyPair()
	if err != nil {
		return -1
	}
	if key != nil {
		keyp.raw = key.ptr
	}
	return 0
}

//export goGetLocalRegistrationId
func goGetLocalRegistrationId(ctx unsafe.Pointer, idp *C.uint32_t) C.int {
	store := restorePointer(ctx).(IdentityKeyStore)
	id, err := store.GetLocalRegistrationID()
	if err != nil {
		return -1
	}
	*idp = C.uint32_t(id)
	return 0
}

//export goSaveIdentityKey
func goSaveIdentityKey(ctx unsafe.Pointer, out *C.uint8_t, address *C.SignalProtocolAddress, key *C.SignalPublicKey) C.int {
	store := restorePointer(ctx).(IdentityKeyStore)
	addr := &Address{ptr: address}

	// Clone the public key since we're borrowing the C pointer
	var buf C.SignalOwnedBuffer
	if err := wrapError(C.signal_publickey_serialize(&buf, C.SignalConstPointerPublicKey{raw: key})); err != nil {
		return -1
	}
	data := freeOwnedBuffer(buf)
	pubKey, err := DeserializePublicKey(data)
	if err != nil {
		return -1
	}

	replaced, err := store.SaveIdentityKey(addr, pubKey)
	addr.ptr = nil
	if err != nil {
		return -1
	}

	// Return IdentityChange enum: 0 = NewOrUnchanged, 1 = ReplacedExisting
	if replaced {
		*out = 1
	} else {
		*out = 0
	}
	return 0
}

//export goGetIdentityKey
func goGetIdentityKey(ctx unsafe.Pointer, keyp *C.SignalMutPointerPublicKey, address *C.SignalProtocolAddress) C.int {
	store := restorePointer(ctx).(IdentityKeyStore)
	addr := &Address{ptr: address}
	key, err := store.GetIdentityKey(addr)
	addr.ptr = nil
	if err != nil {
		return -1
	}
	if key != nil {
		keyp.raw = key.ptr
	}
	return 0
}

//export goIsTrustedIdentity
func goIsTrustedIdentity(ctx unsafe.Pointer, out *C.bool, address *C.SignalProtocolAddress, key *C.SignalPublicKey, direction C.uint32_t) C.int {
	store := restorePointer(ctx).(IdentityKeyStore)
	addr := &Address{ptr: address}
	pub := &PublicKey{ptr: key}
	trusted, err := store.IsTrustedIdentity(addr, pub, uint(direction))
	addr.ptr = nil
	pub.ptr = nil // prevent Destroy of borrowed pointer
	if err != nil {
		return -1
	}
	*out = C.bool(trusted)
	return 0
}

// --- PreKey Store callbacks ---

//export goLoadPreKey
func goLoadPreKey(ctx unsafe.Pointer, recordp *C.SignalMutPointerPreKeyRecord, id C.uint32_t) C.int {
	store := restorePointer(ctx).(PreKeyStore)
	rec, err := store.LoadPreKey(uint32(id))
	if err != nil {
		return -1
	}
	if rec != nil {
		recordp.raw = rec.ptr
	}
	return 0
}

//export goStorePreKey
func goStorePreKey(ctx unsafe.Pointer, id C.uint32_t, record *C.SignalPreKeyRecord) C.int {
	store := restorePointer(ctx).(PreKeyStore)

	// Clone via serialize/deserialize
	var buf C.SignalOwnedBuffer
	if err := wrapError(C.signal_pre_key_record_serialize(&buf, C.SignalConstPointerPreKeyRecord{raw: record})); err != nil {
		return -1
	}
	data := freeOwnedBuffer(buf)
	rec, err := DeserializePreKeyRecord(data)
	if err != nil {
		return -1
	}

	if err := store.StorePreKey(uint32(id), rec); err != nil {
		return -1
	}
	return 0
}

//export goRemovePreKey
func goRemovePreKey(ctx unsafe.Pointer, id C.uint32_t) C.int {
	store := restorePointer(ctx).(PreKeyStore)
	if err := store.RemovePreKey(uint32(id)); err != nil {
		return -1
	}
	return 0
}

// --- Signed PreKey Store callbacks ---

//export goLoadSignedPreKey
func goLoadSignedPreKey(ctx unsafe.Pointer, recordp *C.SignalMutPointerSignedPreKeyRecord, id C.uint32_t) C.int {
	store := restorePointer(ctx).(SignedPreKeyStore)
	rec, err := store.LoadSignedPreKey(uint32(id))
	if err != nil {
		return -1
	}
	if rec != nil {
		recordp.raw = rec.ptr
	}
	return 0
}

//export goStoreSignedPreKey
func goStoreSignedPreKey(ctx unsafe.Pointer, id C.uint32_t, record *C.SignalSignedPreKeyRecord) C.int {
	store := restorePointer(ctx).(SignedPreKeyStore)

	var buf C.SignalOwnedBuffer
	if err := wrapError(C.signal_signed_pre_key_record_serialize(&buf, C.SignalConstPointerSignedPreKeyRecord{raw: record})); err != nil {
		return -1
	}
	data := freeOwnedBuffer(buf)
	rec, err := DeserializeSignedPreKeyRecord(data)
	if err != nil {
		return -1
	}

	if err := store.StoreSignedPreKey(uint32(id), rec); err != nil {
		return -1
	}
	return 0
}

// --- Kyber PreKey Store callbacks ---

//export goLoadKyberPreKey
func goLoadKyberPreKey(ctx unsafe.Pointer, recordp *C.SignalMutPointerKyberPreKeyRecord, id C.uint32_t) C.int {
	store := restorePointer(ctx).(KyberPreKeyStore)
	rec, err := store.LoadKyberPreKey(uint32(id))
	if err != nil {
		return -1
	}
	if rec != nil {
		recordp.raw = rec.ptr
	}
	return 0
}

//export goStoreKyberPreKey
func goStoreKyberPreKey(ctx unsafe.Pointer, id C.uint32_t, record *C.SignalKyberPreKeyRecord) C.int {
	store := restorePointer(ctx).(KyberPreKeyStore)

	var buf C.SignalOwnedBuffer
	if err := wrapError(C.signal_kyber_pre_key_record_serialize(&buf, C.SignalConstPointerKyberPreKeyRecord{raw: record})); err != nil {
		return -1
	}
	data := freeOwnedBuffer(buf)
	rec, err := DeserializeKyberPreKeyRecord(data)
	if err != nil {
		return -1
	}

	if err := store.StoreKyberPreKey(uint32(id), rec); err != nil {
		return -1
	}
	return 0
}

//export goMarkKyberPreKeyUsed
func goMarkKyberPreKeyUsed(ctx unsafe.Pointer, id C.uint32_t, ecPreKeyID C.uint32_t, baseKey *C.SignalPublicKey) C.int {
	store := restorePointer(ctx).(KyberPreKeyStore)

	// Clone the base key if provided (may be NULL)
	var pubKey *PublicKey
	if baseKey != nil {
		var buf C.SignalOwnedBuffer
		if err := wrapError(C.signal_publickey_serialize(&buf, C.SignalConstPointerPublicKey{raw: baseKey})); err != nil {
			return -1
		}
		data := freeOwnedBuffer(buf)
		var err error
		pubKey, err = DeserializePublicKey(data)
		if err != nil {
			return -1
		}
	}

	if err := store.MarkKyberPreKeyUsed(uint32(id), uint32(ecPreKeyID), pubKey); err != nil {
		return -1
	}
	return 0
}

// --- Store wrapper constructors ---

func wrapSessionStore(store SessionStore) (*C.SignalSessionStore, func()) {
	ctx := savePointer(store)
	cStore := &C.SignalSessionStore{
		ctx:           ctx,
		load_session:  C.SignalFfiBridgeSessionStoreLoadSession(C.bridge_load_session),
		store_session: C.SignalFfiBridgeSessionStoreStoreSession(C.bridge_store_session),
		destroy:       C.SignalFfiBridgeSessionStoreDestroy(C.bridge_noop_destroy),
	}
	// Pin the C struct so GC doesn't move it during Rust callbacks
	var pinner runtime.Pinner
	pinner.Pin(cStore)
	return cStore, func() {
		pinner.Unpin()
		deletePointer(ctx)
	}
}

func wrapIdentityKeyStore(store IdentityKeyStore) (*C.SignalIdentityKeyStore, func()) {
	ctx := savePointer(store)
	cStore := &C.SignalIdentityKeyStore{
		ctx:                            ctx,
		get_local_identity_private_key: C.SignalFfiBridgeIdentityKeyStoreGetLocalIdentityPrivateKey(C.bridge_get_identity_key_pair),
		get_local_registration_id:      C.SignalFfiBridgeIdentityKeyStoreGetLocalRegistrationId(C.bridge_get_local_registration_id),
		get_identity_key:               C.SignalFfiBridgeIdentityKeyStoreGetIdentityKey(C.bridge_get_identity_key),
		save_identity_key:              C.SignalFfiBridgeIdentityKeyStoreSaveIdentityKey(C.bridge_save_identity_key),
		is_trusted_identity:            C.SignalFfiBridgeIdentityKeyStoreIsTrustedIdentity(C.bridge_is_trusted_identity),
		destroy:                        C.SignalFfiBridgeIdentityKeyStoreDestroy(C.bridge_noop_destroy),
	}
	// Pin the C struct so GC doesn't move it during Rust callbacks
	var pinner runtime.Pinner
	pinner.Pin(cStore)
	return cStore, func() {
		pinner.Unpin()
		deletePointer(ctx)
	}
}

func wrapPreKeyStore(store PreKeyStore) (*C.SignalPreKeyStore, func()) {
	ctx := savePointer(store)
	cStore := &C.SignalPreKeyStore{
		ctx:            ctx,
		load_pre_key:   C.SignalFfiBridgePreKeyStoreLoadPreKey(C.bridge_load_pre_key),
		store_pre_key:  C.SignalFfiBridgePreKeyStoreStorePreKey(C.bridge_store_pre_key),
		remove_pre_key: C.SignalFfiBridgePreKeyStoreRemovePreKey(C.bridge_remove_pre_key),
		destroy:        C.SignalFfiBridgePreKeyStoreDestroy(C.bridge_noop_destroy),
	}
	// Pin the C struct so GC doesn't move it during Rust callbacks
	var pinner runtime.Pinner
	pinner.Pin(cStore)
	return cStore, func() {
		pinner.Unpin()
		deletePointer(ctx)
	}
}

func wrapSignedPreKeyStore(store SignedPreKeyStore) (*C.SignalSignedPreKeyStore, func()) {
	ctx := savePointer(store)
	cStore := &C.SignalSignedPreKeyStore{
		ctx:                  ctx,
		load_signed_pre_key:  C.SignalFfiBridgeSignedPreKeyStoreLoadSignedPreKey(C.bridge_load_signed_pre_key),
		store_signed_pre_key: C.SignalFfiBridgeSignedPreKeyStoreStoreSignedPreKey(C.bridge_store_signed_pre_key),
		destroy:              C.SignalFfiBridgeSignedPreKeyStoreDestroy(C.bridge_noop_destroy),
	}
	// Pin the C struct so GC doesn't move it during Rust callbacks
	var pinner runtime.Pinner
	pinner.Pin(cStore)
	return cStore, func() {
		pinner.Unpin()
		deletePointer(ctx)
	}
}

func wrapKyberPreKeyStore(store KyberPreKeyStore) (*C.SignalKyberPreKeyStore, func()) {
	ctx := savePointer(store)
	cStore := &C.SignalKyberPreKeyStore{
		ctx:                     ctx,
		load_kyber_pre_key:      C.SignalFfiBridgeKyberPreKeyStoreLoadKyberPreKey(C.bridge_load_kyber_pre_key),
		store_kyber_pre_key:     C.SignalFfiBridgeKyberPreKeyStoreStoreKyberPreKey(C.bridge_store_kyber_pre_key),
		mark_kyber_pre_key_used: C.SignalFfiBridgeKyberPreKeyStoreMarkKyberPreKeyUsed(C.bridge_mark_kyber_pre_key_used),
		destroy:                 C.SignalFfiBridgeKyberPreKeyStoreDestroy(C.bridge_noop_destroy),
	}
	// Pin the C struct so GC doesn't move it during Rust callbacks
	var pinner runtime.Pinner
	pinner.Pin(cStore)
	return cStore, func() {
		pinner.Unpin()
		deletePointer(ctx)
	}
}
