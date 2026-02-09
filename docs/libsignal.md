# libsignal Architecture Reference

Reference for Go FFI consumers of `libsignal` v0.87.0. All paths are relative to the libsignal repository root.

## Crate Structure

The workspace (`Cargo.toml`) contains these crates relevant to FFI consumers:

| Crate | Path | Purpose |
|-------|------|---------|
| `libsignal-protocol` | `rust/protocol/` | Core Signal Protocol: X3DH/PQXDH, Double Ratchet, session management, sealed sender |
| `signal-crypto` | `rust/crypto/` | Low-level crypto primitives (AES, HMAC, etc.) |
| `zkgroup` | `rust/zkgroup/` | Zero-knowledge group operations, auth credentials, profile keys |
| `libsignal-net` | `rust/net/` | Network layer: CDSI, WebSocket, attestation |
| `libsignal-net-chat` | `rust/net/chat/` | Chat service: message sending, registration, device management |
| `libsignal-core` | `rust/core/` | Shared types: `ServiceId`, `Aci`, `Pni`, `E164`, `ProtocolAddress`, `DeviceId`, key types |
| `libsignal-account-keys` | `rust/account-keys/` | PIN, account entropy pool |
| `libsignal-ffi` | `rust/bridge/ffi/` | C FFI static library (`signal_ffi`) |
| `libsignal-bridge` | `rust/bridge/shared/` | Shared bridge logic, `bridge_fn` implementations |
| `libsignal-bridge-macros` | `rust/bridge/shared/macros/` | Proc macros: `bridge_fn`, `bridge_io`, `bridge_callbacks` |
| `libsignal-bridge-types` | `rust/bridge/shared/types/` | FFI type conversions, store callback structs, error types |

### Dependency flow

```
libsignal-ffi (static lib)
  -> libsignal-bridge (bridge_fn implementations)
     -> libsignal-bridge-types (FFI type conversion, store traits)
     -> libsignal-bridge-macros (code generation)
  -> libsignal-protocol (core protocol)
  -> libsignal-net / libsignal-net-chat (network)
  -> zkgroup (zero-knowledge proofs)
```

## C FFI Layer

### How FFI functions are generated

The `bridge_fn` proc macro (`rust/bridge/shared/macros/src/ffi.rs`) transforms Rust functions into C-compatible exports. The naming convention is:

1. The Rust function name (e.g., `SessionCipher_EncryptMessage`) is converted to `lower_snake_case`
2. The prefix `signal_` is prepended (set in `rust/bridge/ffi/build.rs` via `LIBSIGNAL_BRIDGE_FN_PREFIX_FFI`)

**Example transformation:**
```
Rust:   SessionCipher_EncryptMessage(...)
C FFI:  signal_session_cipher_encrypt_message(...)
```

Custom FFI names can be specified: `#[bridge_fn(ffi = "encrypt_message")]` produces `signal_encrypt_message`.

### Generated function signature pattern

Every generated FFI function follows this pattern:

```c
SignalFfiError* signal_<name>(
    <output_type>* out,    // output parameter (if function returns a value)
    <arg1_type> arg1,      // input parameters
    <arg2_type> arg2,
    ...
);
```

- Returns `NULL` on success, or a heap-allocated `SignalFfiError*` on failure
- Output values are written through pointer parameters
- Slices become `(const unsigned char* data, size_t data_len)` pairs
- Opaque handles are `const Signal<Type>*` pointers

### Key source files

| File | Purpose |
|------|---------|
| `rust/bridge/ffi/src/lib.rs` | FFI entry point, free functions (`signal_free_string`, `signal_free_buffer`, `signal_error_free`) |
| `rust/bridge/ffi/src/error.rs` | Error accessors: `signal_error_get_type`, `Error_GetMessage`, `Error_GetAddress`, etc. |
| `rust/bridge/ffi/cbindgen.toml` | cbindgen config: type renaming, prefix rules, export list |
| `rust/bridge/shared/src/protocol.rs` | Bridge implementations for all protocol types |
| `rust/bridge/shared/src/zkgroup.rs` | Bridge implementations for zkgroup types |
| `rust/bridge/shared/src/net/cdsi.rs` | Bridge implementations for CDSI lookup |
| `rust/bridge/shared/types/src/ffi/mod.rs` | Core FFI types: `BorrowedSliceOf`, `OwnedBufferOf`, `run_ffi_safe`, handle management |
| `rust/bridge/shared/types/src/ffi/convert.rs` | `ArgTypeInfo`, `SimpleArgTypeInfo`, `ResultTypeInfo` trait implementations |
| `rust/bridge/shared/types/src/ffi/storage.rs` | Store callback struct definitions and bridge trait implementations |
| `rust/bridge/shared/types/src/ffi/futures.rs` | `CPromise`, `PromiseCompleter`, async FFI support |
| `rust/bridge/shared/types/src/ffi/error.rs` | `SignalFfiError`, `SignalErrorCode`, error conversion for all error types |

### cbindgen type renaming

The `cbindgen.toml` maps Rust types to C names with a `Signal` prefix:

| Rust type | C type |
|-----------|--------|
| `FfiSessionStoreStruct` | `SignalSessionStore` |
| `FfiIdentityKeyStoreStruct` | `SignalIdentityKeyStore` |
| `FfiPreKeyStoreStruct` | `SignalPreKeyStore` |
| `FfiSignedPreKeyStoreStruct` | `SignalSignedPreKeyStore` |
| `FfiKyberPreKeyStoreStruct` | `SignalKyberPreKeyStore` |
| `FfiSenderKeyStoreStruct` | `SignalSenderKeyStore` |
| `FfiDirection` | `SignalDirection` |
| `FfiCiphertextMessageType` | `SignalCiphertextMessageType` |
| `FfiContentHint` | `SignalContentHint` |
| `SignalFfiError` | `SignalFfiError` (no double prefix) |
| `SignalMessage` | `SignalMessage` (no double prefix) |

### Handle lifecycle pattern

Opaque types are managed through handle functions generated by the `bridge_handle_fns!` macro. For each type `Foo`:

- `signal_foo_clone(existing, *out)` -- clone the handle
- `signal_foo_destroy(handle)` -- free the Rust allocation

Declared in `rust/bridge/shared/src/protocol.rs`:
```rust
bridge_handle_fns!(CiphertextMessage, clone = false, jni = false);
bridge_handle_fns!(PreKeyBundle);
bridge_handle_fns!(PrivateKey, ffi = privatekey);
bridge_handle_fns!(PublicKey, ffi = publickey);
bridge_handle_fns!(ProtocolAddress, ffi = address);
bridge_handle_fns!(SessionRecord);
bridge_handle_fns!(SignalMessage, ffi = message);
// ... etc
```

When `ffi = privatekey`, the generated C functions use `signal_privatekey_clone` / `signal_privatekey_destroy` instead of the default snake_case conversion.

### Memory management

```c
// Free a string returned by libsignal
void signal_free_string(const char* buf);

// Free a buffer returned by libsignal
void signal_free_buffer(const unsigned char* buf, size_t buf_len);

// Free an error object
void signal_error_free(SignalFfiError* err);
```

## Protocol Implementation

**Source:** `rust/protocol/src/`

### Key agreement: X3DH with PQXDH (Kyber)

Session establishment uses Extended Triple Diffie-Hellman (X3DH) augmented with post-quantum key encapsulation (PQXDH using Kyber1024).

**Ratchet initialization** (`rust/protocol/src/ratchet.rs`):
- `initialize_alice_session()` -- Alice (sender) performs X3DH + Kyber encapsulation, derives root/chain keys via HKDF with label `"WhisperText_X25519_SHA-256_CRYSTALS-KYBER-1024"`
- `initialize_bob_session()` -- Bob (receiver) performs corresponding X3DH + Kyber decapsulation
- Post-quantum ratchet state (`spqr`) is initialized alongside the classical ratchet

**Session processing** (`rust/protocol/src/session.rs`):
- `process_prekey_bundle()` -- process a pre-key bundle to establish a session (Alice side)
- `process_prekey()` -- process an incoming PreKeySignalMessage (Bob side)

**FFI functions:**
```c
// Session establishment (Alice)
SignalFfiError* signal_process_prekey_bundle(
    const SignalPreKeyBundle* bundle,
    const SignalProtocolAddress* address,
    SignalSessionStore* session_store,
    SignalIdentityKeyStore* identity_store,
    uint64_t now);

// Encrypt a message
SignalFfiError* signal_encrypt_message(
    SignalCiphertextMessage** out,
    const unsigned char* ptext, size_t ptext_len,
    const SignalProtocolAddress* address,
    SignalSessionStore* session_store,
    SignalIdentityKeyStore* identity_store,
    uint64_t now);

// Decrypt a SignalMessage (normal ratchet message)
SignalFfiError* signal_decrypt_message(
    const unsigned char** out, size_t* out_len,
    const SignalMessage* message,
    const SignalProtocolAddress* address,
    SignalSessionStore* session_store,
    SignalIdentityKeyStore* identity_store);

// Decrypt a PreKeySignalMessage (session-establishing message)
SignalFfiError* signal_decrypt_pre_key_message(
    const unsigned char** out, size_t* out_len,
    const SignalPreKeySignalMessage* message,
    const SignalProtocolAddress* address,
    SignalSessionStore* session_store,
    SignalIdentityKeyStore* identity_store,
    SignalPreKeyStore* prekey_store,
    SignalSignedPreKeyStore* signed_prekey_store,
    SignalKyberPreKeyStore* kyber_prekey_store);
```

### Double Ratchet

**Source:** `rust/protocol/src/ratchet/`

The Double Ratchet advances the encryption keys with each message:
- `RootKey` -- derives new chain keys when ratcheting
- `ChainKey` -- advances per-message, generates message keys
- `MessageKeyGenerator` -- produces the actual encryption keys for individual messages

The current message version is 4 (`CIPHERTEXT_MESSAGE_CURRENT_VERSION`), which includes post-quantum ratchet support. Version 3 (`CIPHERTEXT_MESSAGE_PRE_KYBER_VERSION`) is the backward-compatible version without Kyber keys.

## Crypto Primitives

### Key types

**EC keys** (`rust/core/` re-exported via `rust/protocol/`):
- `PublicKey` -- Curve25519 public key (33 bytes serialized: 1 type byte + 32 key bytes)
- `PrivateKey` -- Curve25519 private key (32 bytes serialized)
- `KeyPair` -- public + private key pair
- `IdentityKey` -- wrapper around `PublicKey` for identity representation
- `IdentityKeyPair` -- identity key pair (public + private)

**Kyber keys** (`rust/protocol/src/kem.rs`, re-exported as `kem::*`):
- `kem::KeyPair` (aliased as `KyberKeyPair`) -- Kyber1024 key pair
- `kem::PublicKey` (aliased as `KyberPublicKey`) -- Kyber1024 public key
- `kem::SecretKey` (aliased as `KyberSecretKey`) -- Kyber1024 secret key
- `kem::KeyType::Kyber1024` -- the only supported KEM type

**FFI functions for keys:**
```c
// EC key operations
signal_privatekey_generate(SignalPrivateKey** out);
signal_privatekey_get_public_key(SignalPublicKey** out, const SignalPrivateKey* k);
signal_privatekey_sign(const unsigned char** out, size_t* out_len, ...);
signal_privatekey_agree(const unsigned char** out, size_t* out_len, ...);
signal_privatekey_serialize(const unsigned char** out, size_t* out_len, const SignalPrivateKey* key);
signal_privatekey_deserialize(SignalPrivateKey** out, const unsigned char* data, size_t data_len);
signal_publickey_serialize(const unsigned char** out, size_t* out_len, const SignalPublicKey* key);
signal_publickey_deserialize(SignalPublicKey** out, const unsigned char* data, size_t data_len);
signal_publickey_verify(bool* out, const SignalPublicKey* key, ...);
signal_publickey_get_public_key_bytes(const unsigned char** out, size_t* out_len, const SignalPublicKey* key);

// Identity key pair
signal_identitykeypair_serialize(const unsigned char** out, size_t* out_len, ...);
signal_identitykeypair_deserialize(SignalPublicKey** out_pub, SignalPrivateKey** out_priv, ...);

// Kyber key operations
signal_kyber_key_pair_generate(SignalKyberKeyPair** out);
signal_kyber_key_pair_get_public_key(SignalKyberPublicKey** out, const SignalKyberKeyPair* kp);
signal_kyber_key_pair_get_secret_key(SignalKyberSecretKey** out, const SignalKyberKeyPair* kp);
signal_kyber_public_key_serialize(const unsigned char** out, size_t* out_len, ...);
signal_kyber_public_key_deserialize(SignalKyberPublicKey** out, ...);
signal_kyber_secret_key_serialize(const unsigned char** out, size_t* out_len, ...);
signal_kyber_secret_key_deserialize(SignalKyberSecretKey** out, ...);
```

### Pre-key types

**Source:** `rust/protocol/src/state/`

- `PreKeyRecord` -- one-time EC pre-key (id, public, private)
- `SignedPreKeyRecord` -- signed EC pre-key (id, timestamp, keypair, signature)
- `KyberPreKeyRecord` -- Kyber pre-key (id, timestamp, keypair, signature)
- `PreKeyBundle` -- combined pre-key set sent to initiating party

**Pre-key bundle construction** (requires Kyber in v0.87.0):
```c
signal_pre_key_bundle_new(
    SignalPreKeyBundle** out,
    uint32_t registration_id,
    uint32_t device_id,           // must be 1-127
    /* optional */ uint32_t prekey_id,
    /* optional */ const SignalPublicKey* prekey,
    uint32_t signed_prekey_id,
    const SignalPublicKey* signed_prekey,
    const unsigned char* signed_prekey_signature, size_t sig_len,
    const SignalPublicKey* identity_key,
    uint32_t kyber_prekey_id,     // required in v0.87.0
    const SignalKyberPublicKey* kyber_prekey,
    const unsigned char* kyber_prekey_signature, size_t kyber_sig_len);
```

### HKDF

```c
// FFI-only variant that writes into a pre-allocated buffer
signal_hkdf_derive(
    unsigned char* output, size_t output_len,
    const unsigned char* ikm, size_t ikm_len,
    const unsigned char* label, size_t label_len,
    const unsigned char* salt, size_t salt_len);
```

## Message Types

**Source:** `rust/protocol/src/protocol.rs`

### CiphertextMessageType enum

```c
enum SignalCiphertextMessageType {
    SignalCiphertextMessageType_Whisper   = 2,  // Normal ratchet message
    SignalCiphertextMessageType_PreKey    = 3,  // Session-establishing message
    SignalCiphertextMessageType_SenderKey = 7,  // Group message (sender key)
    SignalCiphertextMessageType_Plaintext = 8,  // Unencrypted (retry receipt)
};
```

### CiphertextMessage

Variant wrapper for all encrypted message types:
- `SignalMessage` (Whisper) -- normal Double Ratchet message
- `PreKeySignalMessage` (PreKey) -- contains a `SignalMessage` + pre-key info for session setup
- `SenderKeyMessage` (SenderKey) -- group encrypted message
- `PlaintextContent` (Plaintext) -- unencrypted content (used for retry receipts)

**FFI accessors:**
```c
signal_ciphertext_message_type(uint8_t* out, const SignalCiphertextMessage* msg);
signal_ciphertext_message_serialize(const unsigned char** out, size_t* out_len, ...);
```

### SignalMessage

```c
signal_message_deserialize(SignalMessage** out, ...);
signal_message_get_body(const unsigned char** out, size_t* out_len, ...);
signal_message_get_counter(uint32_t* out, ...);
signal_message_get_message_version(uint32_t* out, ...);
signal_message_get_sender_ratchet_key(SignalPublicKey** out, ...);
signal_message_get_serialized(const unsigned char** out, size_t* out_len, ...);
signal_message_verify_mac(bool* out, ...);
```

### PreKeySignalMessage

```c
signal_pre_key_signal_message_deserialize(SignalPreKeySignalMessage** out, ...);
signal_pre_key_signal_message_get_version(uint32_t* out, ...);
signal_pre_key_signal_message_get_registration_id(uint32_t* out, ...);
signal_pre_key_signal_message_get_pre_key_id(/* optional */ uint32_t* out, ...);
signal_pre_key_signal_message_get_signed_pre_key_id(uint32_t* out, ...);
signal_pre_key_signal_message_get_base_key(SignalPublicKey** out, ...);
signal_pre_key_signal_message_get_identity_key(SignalPublicKey** out, ...);
signal_pre_key_signal_message_get_signal_message(SignalMessage** out, ...);
signal_pre_key_signal_message_serialize(const unsigned char** out, size_t* out_len, ...);
```

### DecryptionErrorMessage

Used for retry receipt flow:

```c
signal_decryption_error_message_for_original_message(
    SignalDecryptionErrorMessage** out,
    const unsigned char* original_bytes, size_t original_bytes_len,
    uint8_t original_type,
    uint64_t original_timestamp,
    uint32_t original_sender_device_id);

signal_decryption_error_message_extract_from_serialized_content(SignalDecryptionErrorMessage** out, ...);
signal_decryption_error_message_get_timestamp(uint64_t* out, ...);
signal_decryption_error_message_get_device_id(uint32_t* out, ...);
signal_decryption_error_message_get_ratchet_key(SignalPublicKey** out, ...);  // may be NULL
signal_decryption_error_message_serialize(const unsigned char** out, size_t* out_len, ...);
```

### PlaintextContent

Wraps unencrypted content for delivery (e.g., retry receipts):

```c
signal_plaintext_content_from_decryption_error_message(SignalPlaintextContent** out, ...);
signal_plaintext_content_deserialize(SignalPlaintextContent** out, ...);
signal_plaintext_content_get_body(const unsigned char** out, size_t* out_len, ...);
signal_plaintext_content_serialize(const unsigned char** out, size_t* out_len, ...);
```

## Sealed Sender

**Source:** `rust/protocol/src/sealed_sender.rs`

Sealed sender (UNIDENTIFIED_SENDER) hides the sender's identity from the server. The message is encrypted with an ephemeral key agreement between sender and recipient identity keys.

### Types

- `ServerCertificate` -- server's signing certificate (key_id, public key, certificate bytes, signature)
- `SenderCertificate` -- sender's certificate signed by server (UUID, E164, device ID, key, expiration, signer)
- `UnidentifiedSenderMessageContent` (USMC) -- encrypted content + sender cert + content hint + optional group ID
- `SealedSenderDecryptionResult` -- result of decryption (sender UUID, E164, device ID, plaintext)

### Known server certificates

libsignal v0.87.0 embeds known server certificates for space savings (`KNOWN_SERVER_CERTIFICATES` in `sealed_sender.rs`):
- ID 2: Staging trust root
- ID 3: Production trust root
- ID `0x7357C357`: Test certificate

### ContentHint enum

```c
enum SignalContentHint {
    SignalContentHint_Default    = 0,
    SignalContentHint_Resendable = 1,
    SignalContentHint_Implicit   = 2,
};
```

### FFI functions

**Server/Sender certificates:**
```c
signal_server_certificate_deserialize(SignalServerCertificate** out, ...);
signal_server_certificate_get_key_id(uint32_t* out, ...);
signal_server_certificate_get_key(SignalPublicKey** out, ...);

signal_sender_certificate_deserialize(SignalSenderCertificate** out, ...);
signal_sender_certificate_get_sender_uuid(const char** out, ...);
signal_sender_certificate_get_sender_e164(const char** out, ...);  // may be NULL
signal_sender_certificate_get_device_id(uint32_t* out, ...);
signal_sender_certificate_get_expiration(uint64_t* out, ...);
signal_sender_certificate_get_key(SignalPublicKey** out, ...);
signal_sender_certificate_validate(bool* out, ..., trust_roots, time);
```

**USMC (UnidentifiedSenderMessageContent):**
```c
// Create from ciphertext message + sender cert (FFI-specific, uses empty slice for no group)
signal_unidentified_sender_message_content_new(
    SignalUnidentifiedSenderMessageContent** out,
    const SignalCiphertextMessage* message,
    const SignalSenderCertificate* sender,
    uint32_t content_hint,
    const unsigned char* group_id, size_t group_id_len);

// Create from raw content bytes + type
signal_unidentified_sender_message_content_new_from_content_and_type(
    SignalUnidentifiedSenderMessageContent** out,
    const unsigned char* message_content, size_t message_content_len,
    uint8_t message_type, ...);

signal_unidentified_sender_message_content_get_msg_type(uint8_t* out, ...);
signal_unidentified_sender_message_content_get_contents(const unsigned char** out, size_t* out_len, ...);
signal_unidentified_sender_message_content_get_sender_cert(SignalSenderCertificate** out, ...);
signal_unidentified_sender_message_content_get_content_hint(uint32_t* out, ...);
signal_unidentified_sender_message_content_get_group_id_or_empty(const unsigned char** out, size_t* out_len, ...);
```

**Sealed sender encrypt/decrypt:**
```c
// Encrypt sealed sender message
signal_sealed_session_cipher_encrypt(
    const unsigned char** out, size_t* out_len,
    const SignalProtocolAddress* destination,
    const SignalUnidentifiedSenderMessageContent* content,
    SignalIdentityKeyStore* identity_store);

// Multi-recipient encrypt (for server-side fan-out)
signal_sealed_sender_multi_recipient_encrypt(
    const unsigned char** out, size_t* out_len,
    ...recipients, ...sessions, ...excluded,
    const SignalUnidentifiedSenderMessageContent* content,
    SignalIdentityKeyStore* identity_store);

// Decrypt to USMC (intermediate step)
signal_sealed_session_cipher_decrypt_to_usmc(
    SignalUnidentifiedSenderMessageContent** out,
    const unsigned char* ctext, size_t ctext_len,
    SignalIdentityKeyStore* identity_store);
```

## Groups (Sender Keys)

**Source:** `rust/protocol/src/group_cipher.rs`, `rust/protocol/src/sender_keys.rs`

Group messaging uses sender keys: each group member distributes a `SenderKeyDistributionMessage` (SKDM) to all other members. Messages are then encrypted with AES-256-CBC using keys derived from the sender key chain.

### SenderKeyDistributionMessage (SKDM)

```c
// Create a new SKDM (generates sender key state if needed)
signal_sender_key_distribution_message_create(
    SignalSenderKeyDistributionMessage** out,
    const SignalProtocolAddress* sender,
    /* UUID distribution_id */,
    SignalSenderKeyStore* store);

// Process a received SKDM
signal_process_sender_key_distribution_message(
    const SignalProtocolAddress* sender,
    const SignalSenderKeyDistributionMessage* skdm,
    SignalSenderKeyStore* store);

signal_sender_key_distribution_message_deserialize(...);
signal_sender_key_distribution_message_get_chain_key(...);
signal_sender_key_distribution_message_get_distribution_id(...);
signal_sender_key_distribution_message_get_chain_id(...);
signal_sender_key_distribution_message_get_iteration(...);
signal_sender_key_distribution_message_serialize(...);
```

### Group encrypt/decrypt

```c
// Encrypt a group message (returns CiphertextMessage of type SenderKey)
signal_group_encrypt_message(
    SignalCiphertextMessage** out,
    const SignalProtocolAddress* sender,
    /* UUID distribution_id */,
    const unsigned char* message, size_t message_len,
    SignalSenderKeyStore* store);

// Decrypt a group message
signal_group_decrypt_message(
    const unsigned char** out, size_t* out_len,
    const SignalProtocolAddress* sender,
    const unsigned char* message, size_t message_len,
    SignalSenderKeyStore* store);
```

### SenderKeyRecord

Serializable record storing sender key state:

```c
signal_sender_key_record_deserialize(SignalSenderKeyRecord** out, ...);
signal_sender_key_record_serialize(const unsigned char** out, size_t* out_len, ...);
```

## SessionRecord

**Source:** `rust/protocol/src/state/`

```c
signal_session_record_deserialize(SignalSessionRecord** out, ...);
signal_session_record_serialize(const unsigned char** out, size_t* out_len, ...);
signal_session_record_archive_current_state(SignalSessionRecord* record);
signal_session_record_has_usable_sender_chain(bool* out, const SignalSessionRecord* s, uint64_t now);
signal_session_record_current_ratchet_key_matches(bool* out, ..., const SignalPublicKey* key);
signal_session_record_get_local_registration_id(uint32_t* out, ...);
signal_session_record_get_remote_registration_id(uint32_t* out, ...);
```

## zkgroup

**Source:** `rust/zkgroup/src/`, bridge in `rust/bridge/shared/src/zkgroup.rs`

### GroupMasterKey / GroupSecretParams / GroupPublicParams

These are fixed-length serializable types (not opaque handles). They are passed as byte arrays across FFI.

```c
// Derive GroupSecretParams from a master key
signal_group_secret_params_derive_from_master_key(
    unsigned char* out, size_t out_len,     // serialized GroupSecretParams
    const unsigned char* master_key, size_t master_key_len);

// Get master key from secret params
signal_group_secret_params_get_master_key(
    unsigned char* out, size_t out_len,
    const unsigned char* params, size_t params_len);

// Get public params from secret params
signal_group_secret_params_get_public_params(
    unsigned char* out, size_t out_len,
    const unsigned char* params, size_t params_len);

// Encrypt/decrypt ServiceId within a group
signal_group_secret_params_encrypt_service_id(...);
signal_group_secret_params_decrypt_service_id(...);

// Encrypt/decrypt blobs
signal_group_secret_params_encrypt_blob_with_padding_deterministic(...);
signal_group_secret_params_decrypt_blob_with_padding(...);
```

### ProfileKey

```c
signal_profile_key_get_commitment(...);
signal_profile_key_get_profile_key_version(...);
signal_profile_key_derive_access_key(...);  // -> [u8; 16]
```

### Auth credentials

```c
// Receive auth credential with PNI
signal_server_public_params_receive_auth_credential_with_pni_as_service_id(
    const unsigned char** out, size_t* out_len,
    const SignalServerPublicParams* params,
    /* aci */, /* pni */, uint64_t redemption_time,
    const unsigned char* response_bytes, size_t response_bytes_len);

// Create auth credential presentation
signal_server_public_params_create_auth_credential_with_pni_presentation_deterministic(
    const unsigned char** out, size_t* out_len,
    const SignalServerPublicParams* params,
    const unsigned char* randomness, size_t randomness_len,
    const unsigned char* group_secret_params, size_t group_secret_params_len,
    const unsigned char* credential_bytes, size_t credential_bytes_len);
```

### ServerPublicParams / ServerSecretParams

These are opaque handle types (variable-length serializable):

```c
signal_server_public_params_deserialize(SignalServerPublicParams** out, ...);
signal_server_public_params_serialize(const unsigned char** out, size_t* out_len, ...);
signal_server_secret_params_generate_deterministic(SignalServerSecretParams** out, ...);
signal_server_secret_params_get_public_params(SignalServerPublicParams** out, ...);
```

## CDSI (Contact Discovery Service)

**Source:** `rust/net/src/cdsi.rs`, bridge in `rust/bridge/shared/src/net/cdsi.rs`

CDSI uses an attested enclave connection for privacy-preserving phone number lookups.

### Types

- `LookupRequest` -- accumulator for E164s and previously-known ACI+access key pairs
- `CdsiLookup` -- represents an in-progress CDSI lookup
- `LookupResponse` -- contains a list of `(E164, Aci, Pni)` entries

### FFI functions

```c
// Create and configure a lookup request
signal_lookup_request_new(SignalLookupRequest** out);
signal_lookup_request_add_e164(...);
signal_lookup_request_add_previous_e164(...);
signal_lookup_request_set_token(...);
signal_lookup_request_add_aci_and_access_key(...);

// Start a CDSI lookup (async, uses bridge_io with CPromise)
signal_cdsi_lookup_new(
    SignalCPromiseFfiCdsiLookup* promise,
    const SignalTokioAsyncContext* async_runtime,
    const SignalConnectionManager* connection_manager,
    const char* username,
    const char* password,
    const SignalLookupRequest* request);

// Get the continuation token
signal_cdsi_lookup_token(const unsigned char** out, size_t* out_len, ...);

// Complete the lookup (async)
signal_cdsi_lookup_complete(
    SignalCPromise...* promise,
    const SignalTokioAsyncContext* async_runtime,
    const SignalCdsiLookup* lookup);
```

### AciAndAccessKey

```rust
pub struct AciAndAccessKey {
    pub aci: Aci,
    pub access_key: [u8; 16],  // 16-byte access key derived from profile key
}
```

## Store Traits

**Source:** `rust/protocol/src/storage/traits.rs` (Rust traits), `rust/bridge/shared/types/src/ffi/storage.rs` (FFI callback structs)

The protocol requires 6 store interfaces. Each is bridged via a C struct of function pointers + an opaque context pointer.

### IdentityKeyStore

**Rust trait:**
```rust
trait IdentityKeyStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair>;
    async fn get_local_registration_id(&self) -> Result<u32>;
    async fn save_identity(&mut self, address: &ProtocolAddress, identity: &IdentityKey) -> Result<IdentityChange>;
    async fn is_trusted_identity(&self, address: &ProtocolAddress, identity: &IdentityKey, direction: Direction) -> Result<bool>;
    async fn get_identity(&self, address: &ProtocolAddress) -> Result<Option<IdentityKey>>;
}
```

**FFI bridge trait** (simplified for C, in `storage.rs`):
```rust
trait BridgeIdentityKeyStore {
    fn get_local_identity_private_key(&self) -> Result<PrivateKey>;  // not IdentityKeyPair
    fn get_local_registration_id(&self) -> Result<u32>;
    fn get_identity_key(&self, address: ProtocolAddress) -> Result<Option<PublicKey>>;
    fn save_identity_key(&self, address: ProtocolAddress, public_key: PublicKey) -> Result<u8>;
    fn is_trusted_identity(&self, address: ProtocolAddress, public_key: PublicKey, direction: u32) -> Result<bool>;
}
```

**C struct** (from cbindgen):
```c
typedef struct SignalIdentityKeyStore {
    void* ctx;
    int (*get_local_identity_private_key)(void* ctx, SignalPrivateKey** out);
    int (*get_local_registration_id)(void* ctx, uint32_t* out);
    int (*get_identity_key)(void* ctx, SignalPublicKey** out, const SignalProtocolAddress* address);
    int (*save_identity_key)(void* ctx, uint8_t* out, const SignalProtocolAddress* address, const SignalPublicKey* public_key);
    int (*is_trusted_identity)(void* ctx, bool* out, const SignalProtocolAddress* address, const SignalPublicKey* public_key, uint32_t direction);
    void (*destroy)(void* ctx);
} SignalIdentityKeyStore;
```

**Direction values:** `SignalDirection_Sending = 0`, `SignalDirection_Receiving = 1`

**IdentityChange values:** `IdentityChange_NewOrUnchanged = 0`, `IdentityChange_ReplacedExisting = 1`

### SessionStore

```c
typedef struct SignalSessionStore {
    void* ctx;
    int (*load_session)(void* ctx, SignalSessionRecord** out, const SignalProtocolAddress* address);
    int (*store_session)(void* ctx, const SignalProtocolAddress* address, const SignalSessionRecord* record);
    void (*destroy)(void* ctx);
} SignalSessionStore;
```

### PreKeyStore

```c
typedef struct SignalPreKeyStore {
    void* ctx;
    int (*load_pre_key)(void* ctx, SignalPreKeyRecord** out, uint32_t id);
    int (*store_pre_key)(void* ctx, uint32_t id, const SignalPreKeyRecord* record);
    int (*remove_pre_key)(void* ctx, uint32_t id);
    void (*destroy)(void* ctx);
} SignalPreKeyStore;
```

### SignedPreKeyStore

```c
typedef struct SignalSignedPreKeyStore {
    void* ctx;
    int (*load_signed_pre_key)(void* ctx, SignalSignedPreKeyRecord** out, uint32_t id);
    int (*store_signed_pre_key)(void* ctx, uint32_t id, const SignalSignedPreKeyRecord* record);
    void (*destroy)(void* ctx);
} SignalSignedPreKeyStore;
```

### KyberPreKeyStore

```c
typedef struct SignalKyberPreKeyStore {
    void* ctx;
    int (*load_kyber_pre_key)(void* ctx, SignalKyberPreKeyRecord** out, uint32_t id);
    int (*store_kyber_pre_key)(void* ctx, uint32_t id, const SignalKyberPreKeyRecord* record);
    int (*mark_kyber_pre_key_used)(void* ctx, uint32_t id, uint32_t ec_prekey_id, const SignalPublicKey* base_key);
    void (*destroy)(void* ctx);
} SignalKyberPreKeyStore;
```

### SenderKeyStore

```c
typedef struct SignalSenderKeyStore {
    void* ctx;
    int (*load_sender_key)(void* ctx, SignalSenderKeyRecord** out, const SignalProtocolAddress* sender, const unsigned char* distribution_id);
    int (*store_sender_key)(void* ctx, const SignalProtocolAddress* sender, const unsigned char* distribution_id, const SignalSenderKeyRecord* record);
    void (*destroy)(void* ctx);
} SignalSenderKeyStore;
```

### Callback return convention

All store callbacks return `int`:
- `0` = success
- Non-zero = error (converted to `CallbackError`)

For `load_*` callbacks that may not find a record, the output pointer should be set to `NULL` and the function should return `0` (success). The Rust bridge converts this to the appropriate "not found" error.

**Critical:** The `destroy` callback must NOT be `NULL`. Rust clones callback structs via `OwnedCallbackStruct` and calls `destroy(ctx)` when dropped. Use a no-op function if no cleanup is needed.

## Error Handling

**Source:** `rust/bridge/shared/types/src/ffi/error.rs`

### SignalFfiError

Opaque error type returned from FFI functions. The caller owns the error and must free it with `signal_error_free`.

### SignalErrorCode

```c
enum SignalErrorCode {
    SignalErrorCode_UnknownError              = 1,
    SignalErrorCode_InvalidState              = 2,
    SignalErrorCode_InternalError             = 3,
    SignalErrorCode_NullParameter             = 4,
    SignalErrorCode_InvalidArgument           = 5,
    SignalErrorCode_InvalidType               = 6,
    SignalErrorCode_InvalidUtf8String         = 7,
    SignalErrorCode_Cancelled                 = 8,
    SignalErrorCode_ProtobufError             = 10,
    SignalErrorCode_LegacyCiphertextVersion   = 21,
    SignalErrorCode_UnknownCiphertextVersion  = 22,
    SignalErrorCode_UnrecognizedMessageVersion = 23,
    SignalErrorCode_InvalidMessage            = 30,
    SignalErrorCode_SealedSenderSelfSend      = 31,
    SignalErrorCode_InvalidKey                = 40,
    SignalErrorCode_InvalidSignature          = 41,
    SignalErrorCode_UntrustedIdentity         = 60,
    SignalErrorCode_InvalidKeyIdentifier      = 70,
    SignalErrorCode_SessionNotFound           = 80,
    SignalErrorCode_InvalidRegistrationId     = 81,
    SignalErrorCode_InvalidSession            = 82,
    SignalErrorCode_InvalidSenderKeySession   = 83,
    SignalErrorCode_InvalidProtocolAddress    = 84,
    SignalErrorCode_DuplicatedMessage         = 90,
    SignalErrorCode_CallbackError             = 100,
    SignalErrorCode_VerificationFailure       = 110,
    SignalErrorCode_IoError                   = 140,
    SignalErrorCode_ConnectionTimedOut        = 143,
    SignalErrorCode_NetworkProtocol           = 144,
    SignalErrorCode_RateLimited               = 145,
    SignalErrorCode_WebSocket                 = 146,
    SignalErrorCode_CdsiInvalidToken          = 147,
    SignalErrorCode_ConnectionFailed          = 148,
    SignalErrorCode_ChatServiceInactive       = 149,
    SignalErrorCode_RequestTimedOut           = 150,
    SignalErrorCode_RateLimitChallenge        = 151,
    SignalErrorCode_AppExpired                = 170,
    SignalErrorCode_DeviceDeregistered        = 171,
    SignalErrorCode_RequestUnauthorized       = 220,
    SignalErrorCode_MismatchedDevices         = 221,
    // ... plus username, SVR, registration, key transparency codes
};
```

### Error accessors

```c
// Get error code (returns 0 for NULL)
uint32_t signal_error_get_type(const SignalFfiError* err);

// Get error message string (caller must free with signal_free_string)
SignalFfiError* signal_error_get_message(const char** out, const SignalFfiError* err);

// Get protocol address associated with error
SignalFfiError* signal_error_get_address(SignalProtocolAddress** out, const SignalFfiError* err);

// Get UUID from error (e.g., InvalidSenderKeySession distribution_id)
SignalFfiError* signal_error_get_uuid(/* UUID bytes out */, const SignalFfiError* err);

// Get retry-after seconds (for RateLimited errors)
SignalFfiError* signal_error_get_retry_after_seconds(uint32_t* out, const SignalFfiError* err);
```

### Error propagation flow

1. Rust function returns `Result<T, E>` where E implements `IntoFfiError`
2. `run_ffi_safe` catches panics and converts errors to `SignalFfiError`
3. Error is heap-allocated via `Box::into_raw(Box::new(err))` and returned as `*mut SignalFfiError`
4. On success, returns `NULL` (null pointer)
5. Caller checks return value, extracts error code/message if needed, then calls `signal_error_free`

## Async FFI (TokioAsyncContext)

**Source:** `rust/bridge/shared/types/src/net/tokio.rs`, `rust/bridge/shared/types/src/ffi/futures.rs`

Some FFI functions (CDSI lookup, chat service) are async and require a Tokio runtime.

### TokioAsyncContext

Wraps a Tokio multi-threaded runtime. Created once and shared across async operations.

```c
typedef struct SignalTokioAsyncContext SignalTokioAsyncContext;
```

### CPromise pattern

Async FFI functions take a `CPromise` struct that contains:
- `complete` -- callback function pointer to report result
- `context` -- opaque user context passed through to callback
- `cancellation_id` -- set by the runtime, can be used to cancel

```c
typedef struct SignalCPromise_<ResultType> {
    void (*complete)(SignalFfiError* error, const <ResultType>* result, const void* context);
    const void* context;
    uint64_t cancellation_id;
} SignalCPromise_<ResultType>;
```

The `bridge_io` macro generates async FFI functions that:
1. Borrow arguments synchronously
2. Spawn the async work on the Tokio runtime
3. Call `complete` when done (on a blocking thread, safe for CGO)

### Usage from Go

The Go side constructs a `CPromise` with a callback that writes to a channel, passes it to the async FFI function, then blocks on the channel. See `internal/libsignal/cdsi.go` and `bridge_async.c` in the Go project for the concrete implementation pattern.

## ProtocolAddress

**Source:** `rust/core/`

```c
signal_address_new(SignalProtocolAddress** out, const char* name, uint32_t device_id);
signal_address_get_name(const char** out, const SignalProtocolAddress* addr);
signal_address_get_device_id(uint32_t* out, const SignalProtocolAddress* addr);
```

- `name` is the ServiceId string (UUID format)
- `device_id` must be in range 1-127 (validated in v0.87.0, returns `InvalidProtocolAddress` error otherwise)

## ServiceId

```c
signal_service_id_parse_from_service_id_binary(/* ServiceId out */, const unsigned char* input, size_t input_len);
signal_service_id_parse_from_service_id_string(/* ServiceId out */, const char* input);
signal_service_id_service_id_binary(const unsigned char** out, size_t* out_len, /* ServiceId */);
signal_service_id_service_id_string(const char** out, /* ServiceId */);
```

ServiceIds are 17 bytes in binary format (1 type byte + 16 UUID bytes):
- ACI type byte: `0x00`
- PNI type byte: `0x01`

## Fingerprints

Safety number generation and comparison:

```c
signal_fingerprint_new(
    SignalFingerprint** out,
    uint32_t iterations,    // typically 5200
    uint32_t version,       // typically 2
    const unsigned char* local_id, size_t local_id_len,
    const SignalPublicKey* local_key,
    const unsigned char* remote_id, size_t remote_id_len,
    const SignalPublicKey* remote_key);

signal_fingerprint_display_string(const char** out, const SignalFingerprint* fp);
signal_fingerprint_scannable_encoding(const unsigned char** out, size_t* out_len, ...);
signal_fingerprint_compare(bool* out, const unsigned char* fp1, size_t fp1_len, const unsigned char* fp2, size_t fp2_len);
```

## Timestamp

Timestamps in libsignal are `u64` values representing milliseconds since the Unix epoch. They are passed as `uint64_t` in FFI.

```rust
pub struct Timestamp(u64);  // milliseconds since epoch
```

In the FFI bridge, `Timestamp` is treated as a transparent `uint64_t`.
