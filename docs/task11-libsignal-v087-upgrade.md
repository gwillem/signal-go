# Phase 11: Upgrade to libsignal v0.87.0

## Status: Complete ✅

## Background

We discovered that signal-go was built against an outdated version of libsignal (approximately v0.68.0, from early 2024). The current libsignal is v0.87.0 with significant FFI API changes. This explains several issues we've encountered:

1. **Sender certificate parsing failures** - The server now returns certificates using a new compact format (uuidBytes field 7, signerId field 8) that our proto definitions didn't include
2. **Potential protocol incompatibilities** - The old libsignal may not properly handle current Signal protocol features
3. **Missing security fixes** - ~19 versions of security and stability improvements

## Scope of Changes

### 1. FFI Callback Type Renames

All callback function pointer types have been renamed from `SignalXxx` to `SignalFfiBridgeXxxStoreYyy`:

| Old Type | New Type |
|----------|----------|
| `SignalLoadSession` | `SignalFfiBridgeSessionStoreLoadSession` |
| `SignalStoreSession` | `SignalFfiBridgeSessionStoreStoreSession` |
| `SignalGetIdentityKeyPair` | `SignalFfiBridgeIdentityKeyStoreGetLocalIdentityPrivateKey` |
| `SignalGetLocalRegistrationId` | `SignalFfiBridgeIdentityKeyStoreGetLocalRegistrationId` |
| `SignalSaveIdentityKey` | `SignalFfiBridgeIdentityKeyStoreSaveIdentityKey` |
| `SignalGetIdentityKey` | `SignalFfiBridgeIdentityKeyStoreGetIdentityKey` |
| `SignalIsTrustedIdentity` | `SignalFfiBridgeIdentityKeyStoreIsTrustedIdentity` |
| `SignalLoadPreKey` | `SignalFfiBridgePreKeyStoreLoadPreKey` |
| `SignalStorePreKey` | `SignalFfiBridgePreKeyStoreStorePreKey` |
| `SignalRemovePreKey` | `SignalFfiBridgePreKeyStoreRemovePreKey` |
| `SignalLoadSignedPreKey` | `SignalFfiBridgeSignedPreKeyStoreLoadSignedPreKey` |
| `SignalStoreSignedPreKey` | `SignalFfiBridgeSignedPreKeyStoreStoreSignedPreKey` |
| `SignalLoadKyberPreKey` | `SignalFfiBridgeKyberPreKeyStoreLoadKyberPreKey` |
| `SignalStoreKyberPreKey` | `SignalFfiBridgeKyberPreKeyStoreStoreKyberPreKey` |
| `SignalMarkKyberPreKeyUsed` | `SignalFfiBridgeKyberPreKeyStoreMarkKyberPreKeyUsed` |

### 2. Breaking Signature Changes

#### 2.1 IdentityKeyStore.SaveIdentityKey

**Old signature:**
```c
int (*save_identity)(void *ctx, SignalConstPointerProtocolAddress address, SignalConstPointerPublicKey key)
```

**New signature:**
```c
int (*save_identity_key)(void *ctx, uint8_t *out, SignalMutPointerProtocolAddress address, SignalMutPointerPublicKey public_key)
```

**Changes:**
- Added `uint8_t *out` parameter to return `IdentityChange` enum (0 = NewOrUnchanged, 1 = ReplacedExisting)
- Changed from `Const` to `Mut` pointer wrappers
- Field renamed from `save_identity` to `save_identity_key`

**Impact:** The Go interface `IdentityKeyStore.SaveIdentityKey()` must now return whether the identity was replaced, enabling proper identity change notifications.

#### 2.2 KyberPreKeyStore.MarkKyberPreKeyUsed

**Old signature:**
```c
int (*mark_kyber_pre_key_used)(void *ctx, uint32_t id)
```

**New signature:**
```c
int (*mark_kyber_pre_key_used)(void *ctx, uint32_t id, uint32_t ec_prekey_id, SignalMutPointerPublicKey base_key)
```

**Changes:**
- Added `uint32_t ec_prekey_id` parameter
- Added `SignalMutPointerPublicKey base_key` parameter

**Impact:** The Go interface `KyberPreKeyStore.MarkKyberPreKeyUsed()` must accept additional parameters to properly track which EC pre-key was used alongside the Kyber key.

### 3. New Required Fields: Destroy Callbacks

All store structs now include a `destroy` callback field:

```c
typedef struct {
  void *ctx;
  SignalFfiBridgeSessionStoreLoadSession load_session;
  SignalFfiBridgeSessionStoreStoreSession store_session;
  SignalFfiBridgeSessionStoreDestroy destroy;  // NEW
} SignalFfiBridgeSessionStoreStruct;
```

Affected stores:
- `SignalSessionStore`
- `SignalIdentityKeyStore`
- `SignalPreKeyStore`
- `SignalSignedPreKeyStore`
- `SignalKyberPreKeyStore`

**Impact:** All store wrappers must initialize destroy callbacks. **CRITICAL: Cannot be NULL** - see section 3.1 below.

### 3.1 Critical CGO Pattern: Destroy Callbacks and Pinning

**Root cause of SIGSEGV crashes:** Rust clones the callback struct via `store.clone()` and wraps it in `OwnedCallbackStruct`. When dropped, it calls `(self.destroy)(self.ctx)`. Setting `destroy: nil` causes a crash when Rust tries to call the null function pointer.

**Two requirements for correct CGO callback struct handling:**

1. **Pin the C struct**: The C callback struct must be pinned using `runtime.Pinner` because Rust clones it and may access the original during callbacks while Go's GC could run.

2. **Provide non-nil destroy function**: Use a no-op function instead of nil.

**Correct implementation:**

```go
// bridge.c
void bridge_noop_destroy(void *ctx) {
    (void)ctx;  // suppress unused parameter warning
}
```

```go
// callbacks.go
func wrapSessionStore(store SessionStore) (*C.SignalSessionStore, func()) {
    ctx := savePointer(store)
    cStore := &C.SignalSessionStore{
        ctx:           ctx,
        load_session:  C.SignalFfiBridgeSessionStoreLoadSession(C.bridge_load_session),
        store_session: C.SignalFfiBridgeSessionStoreStoreSession(C.bridge_store_session),
        destroy:       C.SignalFfiBridgeSessionStoreDestroy(C.bridge_noop_destroy), // NOT nil!
    }
    // Pin the C struct so GC doesn't move it during Rust callbacks
    var pinner runtime.Pinner
    pinner.Pin(cStore)
    return cStore, func() {
        pinner.Unpin()
        deletePointer(ctx)
    }
}
```

**Debugging symptoms:**
- SIGSEGV with garbage PC address (e.g., `PC=0xd100c3ff17fff81c`)
- Error memory dump shows Go heap addresses (0x14000...) instead of Rust heap (0x6000...)
- Crash occurs in `signal_error_get_type` when processing callback errors
- Callbacks may not execute at all before crash

### 4. Proto Format Changes

#### Protobuf Syntax: No Migration Required

| Component | Our Syntax | libsignal Syntax | Compatible |
|-----------|------------|------------------|------------|
| SealedSender.proto | proto2 | proto2 | ✅ Yes |
| Wire messages | proto2 | proto2 | ✅ Yes |
| Session storage | N/A (opaque) | proto3 | ✅ Yes (we store bytes) |

**Note:** libsignal uses proto3 for internal `storage.proto` (SessionRecord serialization), but we don't parse those bytes - we just store them opaquely in SQLite. The wire protocol protos remain proto2.

#### SenderCertificate (sealed_sender.proto)

**Old format:**
```protobuf
message SenderCertificate {
    message Certificate {
        optional string            senderE164    = 1;
        optional string            senderUuid    = 6;
        optional uint32            senderDevice  = 2;
        optional fixed64           expires       = 3;
        optional bytes             identityKey   = 4;
        optional ServerCertificate signer        = 5;
    }
}
```

**New format:**
```protobuf
message SenderCertificate {
    message Certificate {
        optional string            senderE164    = 1;
        oneof senderUuid {
            string                 uuidString    = 6;
            bytes                  uuidBytes     = 7;  // NEW - compact binary UUID
        }
        optional uint32            senderDevice  = 2;
        optional fixed64           expires       = 3;
        optional bytes             identityKey   = 4;
        oneof signer {
            bytes /*ServerCertificate*/ certificate = 5;
            uint32                      id          = 8;  // NEW - server cert ID reference
        }
    }
}
```

**Impact:** Already updated in our proto. The server now sends compact certificates with `uuidBytes` (field 7) and `signerId` (field 8) instead of full embedded certificates.

## Files Requiring Changes

### internal/libsignal/callbacks.go

Update all store wrapper functions with new type names:

```go
// OLD
func wrapSessionStore(store SessionStore) (*C.SignalSessionStore, func()) {
    ctx := savePointer(store)
    return &C.SignalSessionStore{
        ctx:           ctx,
        load_session:  C.SignalLoadSession(C.bridge_load_session),
        store_session: C.SignalStoreSession(C.bridge_store_session),
    }, func() { deletePointer(ctx) }
}

// NEW
func wrapSessionStore(store SessionStore) (*C.SignalSessionStore, func()) {
    ctx := savePointer(store)
    return &C.SignalSessionStore{
        ctx:           ctx,
        load_session:  C.SignalFfiBridgeSessionStoreLoadSession(C.bridge_load_session),
        store_session: C.SignalFfiBridgeSessionStoreStoreSession(C.bridge_store_session),
        destroy:       nil, // Go handles cleanup via deletePointer
    }, func() { deletePointer(ctx) }
}
```

### internal/libsignal/bridge.c

Update signatures for changed callbacks:

```c
// OLD
int bridge_save_identity_key(void *ctx, SignalConstPointerProtocolAddress address, SignalConstPointerPublicKey key) {
    return goSaveIdentityKey(ctx, (SignalProtocolAddress*)address.raw, (SignalPublicKey*)key.raw);
}

// NEW
int bridge_save_identity_key(void *ctx, uint8_t *out, SignalMutPointerProtocolAddress address, SignalMutPointerPublicKey key) {
    return goSaveIdentityKey(ctx, out, (SignalProtocolAddress*)address.raw, (SignalPublicKey*)key.raw);
}
```

```c
// OLD
int bridge_mark_kyber_pre_key_used(void *ctx, uint32_t id) {
    return goMarkKyberPreKeyUsed(ctx, id);
}

// NEW
int bridge_mark_kyber_pre_key_used(void *ctx, uint32_t id, uint32_t ec_prekey_id, SignalMutPointerPublicKey base_key) {
    return goMarkKyberPreKeyUsed(ctx, id, ec_prekey_id, (SignalPublicKey*)base_key.raw);
}
```

### internal/libsignal/store.go

Update Go interfaces:

```go
// OLD
type IdentityKeyStore interface {
    SaveIdentityKey(address *ProtocolAddress, identityKey *PublicKey) error
    // ...
}

// NEW
type IdentityKeyStore interface {
    // SaveIdentityKey returns true if this replaced an existing different identity
    SaveIdentityKey(address *ProtocolAddress, identityKey *PublicKey) (replaced bool, err error)
    // ...
}
```

```go
// OLD
type KyberPreKeyStore interface {
    MarkKyberPreKeyUsed(id uint32) error
    // ...
}

// NEW
type KyberPreKeyStore interface {
    MarkKyberPreKeyUsed(id uint32, ecPreKeyID uint32, baseKey *PublicKey) error
    // ...
}
```

### internal/store/*.go

Update SQLite store implementations to match new interfaces.

### internal/libsignal/memstore.go

Update in-memory store implementations for testing.

## Implementation Plan

### Step 1: Update bridge.c signatures ✅
- [x] Update `bridge_save_identity_key` signature and implementation
- [x] Update `bridge_mark_kyber_pre_key_used` signature and implementation
- [x] Add `bridge_noop_destroy` function for destroy callbacks

### Step 2: Update Go interfaces (store.go) ✅
- [x] Update `IdentityKeyStore.SaveIdentityKey` return type
- [x] Update `KyberPreKeyStore.MarkKyberPreKeyUsed` parameters
- [x] Add Destroy methods to store interfaces (optional)

### Step 3: Update callbacks.go ✅
- [x] Replace all old callback type names with new FFI bridge type names
- [x] Update `goSaveIdentityKey` export signature
- [x] Update `goMarkKyberPreKeyUsed` export signature
- [x] Initialize destroy fields in all wrapper structs (use `bridge_noop_destroy`, NOT nil)
- [x] Pin C callback structs with `runtime.Pinner`

### Step 4: Update store implementations ✅
- [x] Update `internal/store/identity.go` SaveIdentityKey to return replaced bool
- [x] Update `internal/store/kyberprekey.go` MarkKyberPreKeyUsed parameters
- [x] Update `internal/libsignal/memstore.go` for testing

### Step 5: Update proto definitions ✅
- [x] SealedSender.proto updated with oneof fields (already done)
- [x] Regenerate Go protobuf code
- [x] Test sender certificate parsing

### Step 6: Build and test ✅
- [x] Run `make build` to rebuild libsignal FFI
- [x] Run `make test` to verify all tests pass
- [x] Test sealed sender message sending
- [x] Test message receiving with updated decryption

## Testing Plan

### Unit Tests
1. **Store interface tests** - Verify all store implementations satisfy updated interfaces
2. **Callback tests** - Test that Go callbacks are correctly invoked via FFI
3. **Proto parsing tests** - Verify sender certificate parsing with new format

### Integration Tests
1. **Session establishment** - Verify pre-key bundle processing still works
2. **Message encryption/decryption** - Test regular message flow
3. **Sealed sender** - Test sealed sender encryption and decryption
4. **Identity change detection** - Verify identity replacement is properly detected

### Manual Tests
1. Send message from signal-go to Signal iOS/Android
2. Receive message from Signal iOS/Android to signal-go
3. Test sealed sender message exchange between two signal-go accounts

## Risks and Mitigations

| Risk | Impact | Mitigation |
|------|--------|------------|
| Additional undiscovered API changes | High | Comprehensive review of libsignal-ffi.h diff |
| Behavioral changes in protocol handling | Medium | Test against real Signal servers and clients |
| Performance regression | Low | Benchmark critical paths before/after |
| Breaking existing functionality | High | Maintain comprehensive test coverage |

## Timeline

- Step 1-2: Update C bridge and Go interfaces (1-2 hours)
- Step 3-4: Update callbacks and implementations (2-3 hours)
- Step 5-6: Build, test, debug (2-4 hours)

Total estimated effort: 5-9 hours

## Additional Breaking Changes (v0.68.0 → v0.87.0)

Analysis of the 820 commits between versions reveals additional breaking changes:

### 5. Kyber Pre-Keys Required in PreKeyBundles

**Change:** PreKeyBundles now require Kyber pre-keys. Attempting to create a bundle without Kyber keys returns an error.

**Old behavior (v0.68.0):**
```go
// Kyber keys optional - could pass nil
bundle, _ := libsignal.NewPreKeyBundle(regID, deviceID, preKeyID, preKeyPub,
    spkID, spkPub, spkSig, identityPub,
    0xFFFFFFFF, nil, nil)  // No Kyber - worked
```

**New behavior (v0.87.0):**
```go
// Kyber keys required
kyberKP, _ := libsignal.GenerateKyberKeyPair()
kyberPub, _ := kyberKP.PublicKey()
kyberPubBytes, _ := kyberPub.Serialize()
kyberSig, _ := identityKey.Sign(kyberPubBytes)

// Must also store the Kyber pre-key for decryption
kyberRec, _ := libsignal.NewKyberPreKeyRecord(kyberID, timestamp, kyberKP, kyberSig)
kyberPreKeyStore.StoreKyberPreKey(kyberID, kyberRec)

bundle, _ := libsignal.NewPreKeyBundle(regID, deviceID, preKeyID, preKeyPub,
    spkID, spkPub, spkSig, identityPub,
    kyberID, kyberPub, kyberSig)  // Kyber required
```

**Impact:**
- All test code creating PreKeyBundles must include Kyber keys
- Key generation (`keygen.go`) already generates Kyber keys - no change needed
- Pre-key fetch from server already includes Kyber - no change needed

### 6. Device ID Validation (1-127 range) (not yet encountered)

**Change:** Device IDs are now strictly validated to the range [1, 127].

**Impact:**
- `ProtocolAddress_New()` now returns `Result<ProtocolAddress>` instead of `ProtocolAddress`
- Device IDs outside range will fail with `InvalidProtocolAddress` error
- Must add error handling for protocol address creation

### 6. UUID Wrapper Structs

**Change:** UUIDs are now passed as wrapper structs instead of pointers to arrays.

```c
// OLD (v0.68.0)
typedef const uint8_t (*SignalUuid)[16];

// NEW (v0.87.0)
typedef struct {
    uint8_t bytes[16];
} SignalUuid;

typedef struct {
    bool present;
    uint8_t bytes[16];
} SignalOptionalUuid;
```

**Impact:** Any code passing UUIDs through FFI needs to use struct values instead of pointers.

### 7. Post-Quantum Ratchet (SPQR) Always Enabled

**Change:** The `usePqRatchet` parameter was removed; PQ ratchet is now always used.

**Impact:**
- `SignalMessage_New()` now requires `pq_ratchet: &[u8]` parameter
- New accessor: `SignalMessage_GetPqRatchet()`
- Messages are slightly larger due to PQ data

### 8. Error Module Refactoring

**Change:** Error handling moved to dedicated module with new accessor functions.

**New Functions:**
- `signal_error_get_type()` - Returns error code as u32
- `signal_error_get_invalid_protocol_address()` - Returns (name, device_id)
- `signal_error_get_retry_after_seconds()` - Rate limit info
- `signal_error_get_mismatched_device_errors()` - Structured device error list

### 9. Public Key Comparison Removed

**Change:** `ECPublicKey_Compare()` function completely removed.

**Impact:** Must use `signal_publickey_equals()` and implement any ordering comparisons in Go.

### 10. FingerprintError Split

**Change:** Fingerprint errors split into dedicated `FingerprintError` type.

**Impact:** Error handling for fingerprint operations needs updating.

### 11. Rust 2024 Edition

**Change:** FFI crate now uses Rust 2024 edition with new `#[unsafe(...)]` syntax.

**Impact:** Requires Rust 1.88+ to build libsignal.

## Data Store Impact Analysis

### Good News: No Database Migration Required

libsignal maintains **full backward compatibility** for stored data:

| Data Type | Format Change | Migration Needed | Notes |
|-----------|---------------|------------------|-------|
| SessionRecord | Added `pq_ratchet_state` field | ❌ No | Proto3 handles missing fields; PQ state added on first use |
| Identity Keys | No change | ❌ No | 32-byte X25519 format unchanged |
| PreKeyRecord | No change | ❌ No | Protobuf format unchanged |
| SignedPreKeyRecord | No change | ❌ No | Protobuf format unchanged |
| KyberPreKeyRecord | No change | ❌ No | Protobuf format unchanged |

### Existing Sessions Continue Working

When upgrading:
1. Old sessions without PQ ratchet state deserialize successfully
2. PQ ratchet state is generated automatically on first message send/receive
3. No need to re-establish sessions or re-fetch pre-keys
4. Old session data is "promoted" transparently by libsignal

### Database Schema: No Changes Required

Current schema in `internal/store/store.go` is sufficient:

```sql
-- These tables remain unchanged
CREATE TABLE session (name TEXT, device_id INTEGER, record BLOB, ...)
CREATE TABLE identity (name TEXT, public_key BLOB, ...)
CREATE TABLE pre_key (id INTEGER, record BLOB, ...)
CREATE TABLE signed_pre_key (id INTEGER, record BLOB, ...)
CREATE TABLE kyber_pre_key (id INTEGER, record BLOB, used INTEGER, ...)
```

### Optional Enhancement: Kyber Pre-Key Reuse Tracking

The new `markKyberPreKeyUsed` callback provides additional parameters for tracking which signed EC pre-key and session base key were used with each Kyber key. This enables detecting pre-key reuse attacks.

**Current schema (sufficient):**
```sql
CREATE TABLE kyber_pre_key (
    id INTEGER PRIMARY KEY,
    record BLOB NOT NULL,
    used INTEGER DEFAULT 0
)
```

**Optional enhanced schema (for reuse tracking):**
```sql
CREATE TABLE kyber_pre_key (
    id INTEGER PRIMARY KEY,
    record BLOB NOT NULL,
    used INTEGER DEFAULT 0,
    signed_pre_key_id INTEGER,      -- NEW: which signed pre-key was used
    session_base_key BLOB           -- NEW: the session's base key
)
```

**Decision:** For initial upgrade, we can ignore the extra parameters and just mark keys as used. Reuse tracking can be added later if needed.

### Data That Needs Re-fetching: None

- ✅ Existing sessions work as-is
- ✅ Stored identity keys remain valid
- ✅ Local pre-keys remain valid
- ✅ No server re-registration required
- ✅ No contact re-sync required

### Testing Recommendations

1. **Pre-upgrade backup:** Export database before upgrade (optional safety measure)
2. **Session continuity test:** Verify existing sessions can send/receive after upgrade
3. **New session test:** Verify new sessions establish correctly with PQ ratchet
4. **Deserialize test:** Load old SessionRecords and verify no errors

## Complete Migration Checklist

### Critical (Must Fix)
- [ ] Update callback type names (SignalXxx → SignalFfiBridgeXxxStoreYyy)
- [ ] Fix `bridge_save_identity_key` signature (add `uint8_t *out` parameter)
- [ ] Fix `bridge_mark_kyber_pre_key_used` signature (add ec_prekey_id, base_key)
- [ ] Add destroy callbacks to all store wrappers
- [ ] Update UUID passing from pointer to struct value
- [ ] Add error handling for `ProtocolAddress_New()`
- [ ] Validate device IDs are in range [1, 127]

### Important (Should Fix)
- [ ] Update Go interfaces for new callback signatures
- [ ] Update store implementations (identity.go, kyberprekey.go)
- [ ] Handle new error types and accessors
- [ ] Add `pq_ratchet` parameter to SignalMessage creation
- [ ] Update fingerprint error handling

### Verification
- [ ] Test sealed sender with certificate ID references
- [ ] Test message encryption/decryption with PQ ratchet
- [ ] Verify identity change detection works
- [ ] Test device ID boundary cases (1, 127, 128)
- [ ] Run full integration tests against Signal servers

## References

- libsignal repository: https://github.com/signalapp/libsignal
- Signal-Android reference: /Users/willem/git/Signal-Android
- libsignal FFI header: /Users/willem/git/signal-go/internal/libsignal/libsignal-ffi.h
- Version diff: `git diff v0.68.0 v0.87.0` (820 commits, ~110k insertions)
