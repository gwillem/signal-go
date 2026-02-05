#include "libsignal-ffi.h"
#include "_cgo_export.h"

// Bridge functions: all callbacks go through here so that Go //export functions
// can use simple pointer types instead of by-value wrapper structs.

// No-op destroy function - Go handles cleanup via deletePointer in deferred cleanup functions.
// Rust clones callback structs and calls destroy when dropping the clone, so we need a valid
// function pointer but actual cleanup happens in Go.
void bridge_noop_destroy(void *ctx) {
    (void)ctx;  // suppress unused parameter warning
}

// Session store
int bridge_load_session(void *ctx, SignalMutPointerSessionRecord *recordp, SignalMutPointerProtocolAddress address) {
    return goLoadSession(ctx, recordp, (SignalProtocolAddress*)address.raw);
}
int bridge_store_session(void *ctx, SignalMutPointerProtocolAddress address, SignalMutPointerSessionRecord record) {
    return goStoreSession(ctx, (SignalProtocolAddress*)address.raw, (SignalSessionRecord*)record.raw);
}

// Identity key store
int bridge_get_identity_key_pair(void *ctx, SignalMutPointerPrivateKey *keyp) {
    return goGetIdentityKeyPair(ctx, keyp);
}
int bridge_get_local_registration_id(void *ctx, uint32_t *idp) {
    return goGetLocalRegistrationId(ctx, idp);
}
int bridge_save_identity_key(void *ctx, uint8_t *out, SignalMutPointerProtocolAddress address, SignalMutPointerPublicKey key) {
    return goSaveIdentityKey(ctx, out, (SignalProtocolAddress*)address.raw, (SignalPublicKey*)key.raw);
}
int bridge_get_identity_key(void *ctx, SignalMutPointerPublicKey *keyp, SignalMutPointerProtocolAddress address) {
    return goGetIdentityKey(ctx, keyp, (SignalProtocolAddress*)address.raw);
}
int bridge_is_trusted_identity(void *ctx, bool *out, SignalMutPointerProtocolAddress address, SignalMutPointerPublicKey key, uint32_t direction) {
    return goIsTrustedIdentity(ctx, out, (SignalProtocolAddress*)address.raw, (SignalPublicKey*)key.raw, direction);
}

// Pre-key store
int bridge_load_pre_key(void *ctx, SignalMutPointerPreKeyRecord *recordp, uint32_t id) {
    return goLoadPreKey(ctx, recordp, id);
}
int bridge_store_pre_key(void *ctx, uint32_t id, SignalMutPointerPreKeyRecord record) {
    return goStorePreKey(ctx, id, (SignalPreKeyRecord*)record.raw);
}
int bridge_remove_pre_key(void *ctx, uint32_t id) {
    return goRemovePreKey(ctx, id);
}

// Signed pre-key store
int bridge_load_signed_pre_key(void *ctx, SignalMutPointerSignedPreKeyRecord *recordp, uint32_t id) {
    return goLoadSignedPreKey(ctx, recordp, id);
}
int bridge_store_signed_pre_key(void *ctx, uint32_t id, SignalMutPointerSignedPreKeyRecord record) {
    return goStoreSignedPreKey(ctx, id, (SignalSignedPreKeyRecord*)record.raw);
}

// Kyber pre-key store
int bridge_load_kyber_pre_key(void *ctx, SignalMutPointerKyberPreKeyRecord *recordp, uint32_t id) {
    return goLoadKyberPreKey(ctx, recordp, id);
}
int bridge_store_kyber_pre_key(void *ctx, uint32_t id, SignalMutPointerKyberPreKeyRecord record) {
    return goStoreKyberPreKey(ctx, id, (SignalKyberPreKeyRecord*)record.raw);
}
int bridge_mark_kyber_pre_key_used(void *ctx, uint32_t id, uint32_t ec_prekey_id, SignalMutPointerPublicKey base_key) {
    return goMarkKyberPreKeyUsed(ctx, id, ec_prekey_id, (SignalPublicKey*)base_key.raw);
}
