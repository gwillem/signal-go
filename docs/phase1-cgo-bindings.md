# Phase 1: CGO Bindings to libsignal

Goal: prove that Go can call libsignal's Rust C FFI — generate keys, establish a session, encrypt and decrypt a message locally.

## Build system

### Prerequisites

- Rust nightly toolchain: `rustup install nightly`
- cbindgen: `cargo install cbindgen`
- Local libsignal checkout at `../libsignal`

### Makefile

```makefile
LIBSIGNAL_DIR := ../libsignal
LIBSIGNAL_FFI := $(LIBSIGNAL_DIR)/target/release/libsignal_ffi.a
HEADER         := pkg/libsignal/libsignal-ffi.h
NIGHTLY_BIN   := $(HOME)/.rustup/toolchains/nightly-aarch64-apple-darwin/bin

build: $(LIBSIGNAL_FFI) $(HEADER)

$(LIBSIGNAL_FFI): $(LIBSIGNAL_DIR)/rust/bridge/ffi/Cargo.toml
	"$(NIGHTLY_BIN)/cargo" build --release --manifest-path $(LIBSIGNAL_DIR)/rust/bridge/ffi/Cargo.toml

$(HEADER): $(LIBSIGNAL_FFI)
	PATH="$(NIGHTLY_BIN):$(HOME)/.cargo/bin:$$PATH" cbindgen --profile release \
		$(LIBSIGNAL_DIR)/rust/bridge/ffi -o $(HEADER)

test: build
	go test ./...
```

Nightly is required because cbindgen uses `rustc -Zunpretty=expanded` to expand macros, which is a nightly-only flag. The static library itself can be built with stable, but we use nightly for both to avoid toolchain mismatch.

Build output:
- `../libsignal/target/release/libsignal_ffi.a` — 48MB static library
- `pkg/libsignal/libsignal-ffi.h` — 2080 lines, 102KB

### CGO preamble (`pkg/libsignal/libsignal.go`)

```go
package libsignal

// #cgo CFLAGS: -I${SRCDIR}
// #cgo linux LDFLAGS: ${SRCDIR}/../../libsignal/target/release/libsignal_ffi.a -ldl -lm -lpthread
// #cgo darwin LDFLAGS: ${SRCDIR}/../../libsignal/target/release/libsignal_ffi.a -framework Security -framework Foundation -lm
// #include "libsignal-ffi.h"
import "C"
```

`${SRCDIR}` is a CGO variable that resolves to the package source directory.

## FFI conventions (from generated header)

The header uses several patterns consistently:

- **Pointer wrappers:** All object pointers are wrapped in single-field structs:
  ```c
  typedef struct { SignalPrivateKey *raw; } SignalMutPointerPrivateKey;
  typedef struct { const SignalPrivateKey *raw; } SignalConstPointerPrivateKey;
  ```
- **Error handling:** Every function returns `SignalFfiError*` (NULL = success).
- **Output parameters:** Results returned via pointer-to-pointer first argument.
- **Timestamps:** `signal_encrypt_message` and `signal_process_prekey_bundle` take `uint64_t now` (milliseconds since epoch).

## Types and wrappers

Each Go type wraps a C opaque pointer. Pattern:

```go
type PrivateKey struct {
    ptr *C.SignalPrivateKey
}

func GeneratePrivateKey() (*PrivateKey, error) {
    var pk C.SignalMutPointerPrivateKey
    if err := wrapError(C.signal_privatekey_generate(&pk)); err != nil {
        return nil, err
    }
    return &PrivateKey{ptr: pk.raw}, nil
}

func (k *PrivateKey) Serialize() ([]byte, error) { /* C.signal_privatekey_serialize */ }
func (k *PrivateKey) PublicKey() (*PublicKey, error) { /* C.signal_privatekey_get_public_key */ }
func (k *PrivateKey) Destroy()  { C.signal_privatekey_destroy(C.SignalMutPointerPrivateKey{raw: k.ptr}) }
```

### Types needed for MVP (verified against libsignal-ffi.h)

| Go type | C type | Key FFI functions |
|---|---|---|
| `PrivateKey` | `SignalPrivateKey` | `signal_privatekey_generate`, `_serialize`, `_deserialize`, `_get_public_key`, `_sign`, `_agree` |
| `PublicKey` | `SignalPublicKey` | `signal_publickey_serialize`, `_deserialize`, `_compare`, `_verify` |
| `IdentityKeyPair` | composite | `signal_identitykeypair_serialize`, `_deserialize` (returns separate pub+priv) |
| `Address` | `SignalProtocolAddress` | `signal_address_new`, `_get_name`, `_get_device_id` |
| `PreKeyRecord` | `SignalPreKeyRecord` | `signal_pre_key_record_new(id, pub, priv)`, `_serialize`, `_deserialize` |
| `SignedPreKeyRecord` | `SignalSignedPreKeyRecord` | `signal_signed_pre_key_record_new(id, ts, pub, priv, sig)`, `_serialize`, `_deserialize` |
| `KyberPreKeyRecord` | `SignalKyberPreKeyRecord` | `signal_kyber_pre_key_record_new(id, ts, keypair, sig)`, `_serialize`, `_deserialize` |
| `PreKeyBundle` | `SignalPreKeyBundle` | `signal_pre_key_bundle_new(regId, devId, prekeyId, prekey, signedId, signed, signedSig, identity, kyberId, kyber, kyberSig)` |
| `SessionRecord` | `SignalSessionRecord` | `signal_session_record_serialize`, `_deserialize`, `_archive_current_state` |
| `CiphertextMessage` | `SignalCiphertextMessage` | `signal_ciphertext_message_serialize`, `_type` |
| `PreKeySignalMessage` | `SignalPreKeySignalMessage` | `signal_pre_key_signal_message_deserialize`, `_serialize` |
| `SignalMessage` | `SignalMessage` | `signal_message_deserialize`, `_serialize` (note: `SignalMessage` not `Signal_SignalMessage`) |

## Store interfaces

Five stores required (verified against header). The FFI uses C structs with function pointers and a `void *ctx`.

### C store structs from header

```c
// SessionStore
typedef int (*SignalLoadSession)(void *store_ctx, SignalMutPointerSessionRecord *recordp, SignalConstPointerProtocolAddress address);
typedef int (*SignalStoreSession)(void *store_ctx, SignalConstPointerProtocolAddress address, SignalConstPointerSessionRecord record);
typedef struct { void *ctx; SignalLoadSession load_session; SignalStoreSession store_session; } SignalSessionStore;

// IdentityKeyStore
typedef int (*SignalGetIdentityKeyPair)(void *store_ctx, SignalMutPointerPrivateKey *keyp);
typedef int (*SignalGetLocalRegistrationId)(void *store_ctx, uint32_t *idp);
typedef int (*SignalSaveIdentityKey)(void *store_ctx, SignalConstPointerProtocolAddress address, SignalConstPointerPublicKey public_key);
typedef int (*SignalGetIdentityKey)(void *store_ctx, SignalMutPointerPublicKey *public_keyp, SignalConstPointerProtocolAddress address);
typedef int (*SignalIsTrustedIdentity)(void *store_ctx, SignalConstPointerProtocolAddress address, SignalConstPointerPublicKey public_key, unsigned int direction);
// struct has ctx + all 5 function pointers

// PreKeyStore
typedef int (*SignalLoadPreKey)(void *store_ctx, SignalMutPointerPreKeyRecord *recordp, uint32_t id);
typedef int (*SignalStorePreKey)(void *store_ctx, uint32_t id, SignalConstPointerPreKeyRecord record);
typedef int (*SignalRemovePreKey)(void *store_ctx, uint32_t id);

// SignedPreKeyStore
typedef int (*SignalLoadSignedPreKey)(void *store_ctx, SignalMutPointerSignedPreKeyRecord *recordp, uint32_t id);
typedef int (*SignalStoreSignedPreKey)(void *store_ctx, uint32_t id, SignalConstPointerSignedPreKeyRecord record);

// KyberPreKeyStore (required for signal_decrypt_pre_key_message)
typedef int (*SignalLoadKyberPreKey)(void *store_ctx, SignalMutPointerKyberPreKeyRecord *recordp, uint32_t id);
typedef int (*SignalStoreKyberPreKey)(void *store_ctx, uint32_t id, SignalConstPointerKyberPreKeyRecord record);
typedef int (*SignalMarkKyberPreKeyUsed)(void *store_ctx, uint32_t id);
```

### Go interfaces

```go
type SessionStore interface {
    LoadSession(address *Address) (*SessionRecord, error)
    StoreSession(address *Address, record *SessionRecord) error
}

type IdentityKeyStore interface {
    GetIdentityKeyPair() (*PrivateKey, error)     // returns private key (not pair)
    GetLocalRegistrationID() (uint32, error)
    SaveIdentityKey(address *Address, key *PublicKey) error
    GetIdentityKey(address *Address) (*PublicKey, error)
    IsTrustedIdentity(address *Address, key *PublicKey, direction uint) (bool, error)
}

type PreKeyStore interface {
    LoadPreKey(id uint32) (*PreKeyRecord, error)
    StorePreKey(id uint32, record *PreKeyRecord) error
    RemovePreKey(id uint32) error
}

type SignedPreKeyStore interface {
    LoadSignedPreKey(id uint32) (*SignedPreKeyRecord, error)
    StoreSignedPreKey(id uint32, record *SignedPreKeyRecord) error
}

type KyberPreKeyStore interface {
    LoadKyberPreKey(id uint32) (*KyberPreKeyRecord, error)
    StoreKyberPreKey(id uint32, record *KyberPreKeyRecord) error
    MarkKyberPreKeyUsed(id uint32) error
}
```

Note: `GetIdentityKeyPair` returns `*PrivateKey` (not a pair) — the C callback signature is `SignalGetIdentityKeyPair(void*, SignalMutPointerPrivateKey*)`.

### CGO callback pattern

Each store interface method becomes an `//export` function:

```go
//export goSessionStoreLoadSession
func goSessionStoreLoadSession(
    storeCtx unsafe.Pointer,
    recordOut *C.SignalMutPointerSessionRecord,
    address C.SignalConstPointerProtocolAddress,
) C.int {
    store := pointer.Restore(storeCtx).(SessionStore)
    addr := wrapAddress(address.raw)
    rec, err := store.LoadSession(addr)
    if err != nil {
        return -1
    }
    if rec != nil {
        recordOut.raw = rec.ptr
    }
    return 0
}
```

Key details:
- `github.com/mattn/go-pointer` saves/restores Go interfaces through C `void*`
- Callbacks return `C.int` (0 = success, -1 = error)
- `wrapSessionStore()` builds the C `SignalSessionStore` struct with function pointers + saved context

## Protocol operations (verified signatures)

```go
func ProcessPreKeyBundle(
    bundle *PreKeyBundle,
    address *Address,
    sessionStore SessionStore,
    identityStore IdentityKeyStore,
    now time.Time,
) error
// C: signal_process_prekey_bundle(bundle, address, session_store, identity_store, now_ms)

func Encrypt(
    plaintext []byte,
    address *Address,
    sessionStore SessionStore,
    identityStore IdentityKeyStore,
    now time.Time,
) (*CiphertextMessage, error)
// C: signal_encrypt_message(&out, ptext, address, session_store, identity_store, now_ms)

func DecryptPreKeyMessage(
    message *PreKeySignalMessage,
    address *Address,
    sessionStore SessionStore,
    identityStore IdentityKeyStore,
    preKeyStore PreKeyStore,
    signedPreKeyStore SignedPreKeyStore,
    kyberPreKeyStore KyberPreKeyStore,
) ([]byte, error)
// C: signal_decrypt_pre_key_message(&out, msg, addr, session, identity, prekey, signed, kyber)

func DecryptMessage(
    message *SignalMessage,
    address *Address,
    sessionStore SessionStore,
    identityStore IdentityKeyStore,
) ([]byte, error)
// C: signal_decrypt_message(&out, msg, addr, session, identity)
```

## MVP test

`pkg/libsignal/protocol_test.go` — the test that proves everything works:

```
1. Generate identity key pairs for Alice and Bob
2. Create in-memory stores for both (all 5 store types)
3. Generate pre-keys for Bob: EC pre-key, signed pre-key, Kyber pre-key
4. Build PreKeyBundle (includes Kyber key — required by current protocol)
5. Alice processes Bob's bundle → session established
6. Alice encrypts "hello" → PreKeySignalMessage
7. Bob decrypts → "hello" (uses all 5 stores)
8. Bob encrypts "world" → SignalMessage (ratchet advanced)
9. Alice decrypts → "world"
```

## Implementation order (TDD — test first)

| Step | Files | Test proves |
|---|---|---|
| 1 | `Makefile` | `libsignal_ffi.a` + `.h` exist (done) |
| 2 | `libsignal.go`, `error.go`, `buffer.go` | CGO links, trivial FFI call works |
| 3 | `privatekey.go` | Generate key, serialize round-trip |
| 4 | `publickey.go` | Derive from private, serialize round-trip |
| 5 | `identitykey.go` | Generate identity key pair |
| 6 | `address.go` | Create address, get name/device |
| 7 | `prekey.go` | Generate pre-key and signed pre-key |
| 8 | `kyberprekey.go` | Generate Kyber pre-key |
| 9 | `prekeybundle.go` | Create bundle from all components (incl Kyber) |
| 10 | `session.go`, `message.go` | Serialize/deserialize |
| 11 | `store.go`, `memstore.go` | Store callbacks work across FFI (all 5 stores) |
| 12 | `protocol.go` | **Full encrypt/decrypt round-trip** |

## Reference

- `pkg/libsignal/libsignal-ffi.h` — the actual generated header (source of truth for signatures)
- `../libsignal/rust/bridge/ffi/` — Rust FFI source and cbindgen config
- `../libsignalgo/` — archived CGO bindings (pattern reference only)
- `../libsignalgo/identitykeystore.go` — callback pattern
- `../libsignalgo/storeutil.go` — generic callback wrapper
- `../libsignalgo/session_test.go` — integration test example
