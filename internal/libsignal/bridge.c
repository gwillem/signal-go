#include "libsignal-ffi.h"
#include "_cgo_export.h"

// Bridge functions: all callbacks go through here so that Go //export functions
// can use simple pointer types instead of by-value wrapper structs.

// Session store
int bridge_load_session(void *ctx, SignalMutPointerSessionRecord *recordp, SignalConstPointerProtocolAddress address) {
    return goLoadSession(ctx, recordp, (SignalProtocolAddress*)address.raw);
}
int bridge_store_session(void *ctx, SignalConstPointerProtocolAddress address, SignalConstPointerSessionRecord record) {
    return goStoreSession(ctx, (SignalProtocolAddress*)address.raw, (SignalSessionRecord*)record.raw);
}

// Identity key store
int bridge_get_identity_key_pair(void *ctx, SignalMutPointerPrivateKey *keyp) {
    return goGetIdentityKeyPair(ctx, keyp);
}
int bridge_get_local_registration_id(void *ctx, uint32_t *idp) {
    return goGetLocalRegistrationId(ctx, idp);
}
int bridge_save_identity_key(void *ctx, SignalConstPointerProtocolAddress address, SignalConstPointerPublicKey key) {
    return goSaveIdentityKey(ctx, (SignalProtocolAddress*)address.raw, (SignalPublicKey*)key.raw);
}
int bridge_get_identity_key(void *ctx, SignalMutPointerPublicKey *keyp, SignalConstPointerProtocolAddress address) {
    return goGetIdentityKey(ctx, keyp, (SignalProtocolAddress*)address.raw);
}
int bridge_is_trusted_identity(void *ctx, SignalConstPointerProtocolAddress address, SignalConstPointerPublicKey key, unsigned int direction) {
    return goIsTrustedIdentity(ctx, (SignalProtocolAddress*)address.raw, (SignalPublicKey*)key.raw, direction);
}

// Pre-key store
int bridge_load_pre_key(void *ctx, SignalMutPointerPreKeyRecord *recordp, uint32_t id) {
    return goLoadPreKey(ctx, recordp, id);
}
int bridge_store_pre_key(void *ctx, uint32_t id, SignalConstPointerPreKeyRecord record) {
    return goStorePreKey(ctx, id, (SignalPreKeyRecord*)record.raw);
}
int bridge_remove_pre_key(void *ctx, uint32_t id) {
    return goRemovePreKey(ctx, id);
}

// Signed pre-key store
int bridge_load_signed_pre_key(void *ctx, SignalMutPointerSignedPreKeyRecord *recordp, uint32_t id) {
    return goLoadSignedPreKey(ctx, recordp, id);
}
int bridge_store_signed_pre_key(void *ctx, uint32_t id, SignalConstPointerSignedPreKeyRecord record) {
    return goStoreSignedPreKey(ctx, id, (SignalSignedPreKeyRecord*)record.raw);
}

// Kyber pre-key store
int bridge_load_kyber_pre_key(void *ctx, SignalMutPointerKyberPreKeyRecord *recordp, uint32_t id) {
    return goLoadKyberPreKey(ctx, recordp, id);
}
int bridge_store_kyber_pre_key(void *ctx, uint32_t id, SignalConstPointerKyberPreKeyRecord record) {
    return goStoreKyberPreKey(ctx, id, (SignalKyberPreKeyRecord*)record.raw);
}
int bridge_mark_kyber_pre_key_used(void *ctx, uint32_t id) {
    return goMarkKyberPreKeyUsed(ctx, id);
}
