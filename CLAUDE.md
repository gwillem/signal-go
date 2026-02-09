# signal-go

Go library for Signal messenger, replacing the Java signal-cli dependency. Licensed under AGPL-3.0.

## Housekeeping

- Keep `docs/*.md` up to date when completing tasks, learning something new, or making architectural decisions. Update phase status markers, implementation notes, and reference information.

## Architecture

- `client.go` — Public API: `Client` with `Link`, `Load`, `Send`, `Receive`, `SyncContacts`, `LookupNumber`, `Close`, `Number`, `DeviceID`
- `internal/libsignal/` — CGO bindings to libsignal's Rust C FFI (Phase 1, complete)
- `internal/proto/` — Protobuf definitions and generated Go code (Provisioning, WebSocket, DeviceName, SignalService)
- `internal/provisioncrypto/` — Provisioning envelope encrypt/decrypt (HKDF, AES-CBC, HMAC, PKCS7), device name encryption
- `internal/signalcrypto/` — Stateless crypto utilities: profile encryption, storage service crypto, access key derivation, attachment decryption
- `internal/signalws/` — Protobuf-framed WebSocket layer with keep-alive and reconnection
- `internal/signalservice/` — Provisioning orchestration, device registration, HTTP client, pre-key generation, message sending/receiving, retry receipts, contact sync, attachment download
- `internal/store/` — SQLite persistent storage (sessions, identity keys, pre-keys, account credentials, contacts)
- `docs/` — Phase plans and architecture docs

## Reference implementation

When debugging or implementing new functionality, consult the Signal-Android source at `../Signal-Android`. **Signal-Android is the source of truth** for expected protocol behavior.

### MANDATORY: Verify before implementing

Before implementing any protocol behavior, **always check Signal-Android first**:

1. **Error handling** (409, 410, 401, etc.) — check `PushServiceSocket.java` and `SignalServiceMessageSender.java`
2. **Session/crypto operations** — check how they use libsignal APIs (e.g., `getRemoteRegistrationId()` comes from session, not a separate cache)
3. **Retry logic** — check actual retry counts, what state is preserved/cleared
4. **Data storage** — check what goes in RecipientDatabase vs SessionStore vs elsewhere

**Red flags that require Signal-Android verification:**
- Adding new database columns or caches
- Implementing workarounds for server errors
- Making assumptions about "what the server expects"
- Any behavior where you're guessing instead of knowing

### Key locations:

See `docs/signal-android.md` for a comprehensive index of Signal-Android's service layer, including message sending/receiving flows, HTTP endpoints, sealed sender, groups, retry handling, and more.

Quick reference for the most commonly consulted paths:
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/push/` — PushServiceSocket (REST API calls, 409/410 error throwing)
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/SignalServiceMessageSender.java` — Message sending, 409/410 retry handling (handleMismatchedDevices, handleStaleDevices)
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/crypto/` — Encryption, registration ID retrieval

For libsignal Rust FFI architecture, see `docs/libsignal.md`.

### Anti-patterns to avoid

These mistakes have caused bugs in the past:

- **Caching protocol state separately** — Registration IDs, identity keys, etc. are already in libsignal's data structures. Don't duplicate them in custom database tables.
- **Inventing retry/recovery logic** — Signal-Android's retry logic is simple (archive + retry N times). Don't add staleSeen tracking or other "clever" solutions.
- **Assuming server behavior** — If unsure what the server expects, grep Signal-Android for the endpoint or error code.
- **Skipping message formatting steps** — Signal uses transport-level padding (`PushTransportDetails.getPaddedMessageBody()`) before encryption. Missing this causes decryption failures even though the protocol-level crypto succeeds.
- **Duplicating 409/410 retry logic** — All send paths must handle device mismatch (409) and stale sessions (410). Use `withDeviceRetry` in `deviceretry.go` instead of writing a new retry loop. Missing retry handling caused SKDM delivery failures to multi-device recipients.

## Prerequisites

- Go 1.25+
- Rust nightly toolchain (`rustup install nightly`)
- cbindgen (`cargo install cbindgen`)
- libsignal source is included as a git submodule at `build/libsignal/` (pinned to v0.87.0)

## Building

```
git submodule update --init   # fetch libsignal source (first time only)
make deps     # builds libsignal_ffi.a + generates header for current platform
make test     # runs go test ./...
```

Cross-compilation:
```
make deps-darwin-arm64   # build for macOS ARM64
make deps-linux-amd64    # build for Linux x86_64 (requires musl-cross toolchain)
make deps-all            # build for all platforms
```

## Testing

Always use `make test` to run tests — it sets the required `CGO_LDFLAGS_ALLOW` and `CGO_LDFLAGS` flags. Never run `go build` or `go test ./...` directly — always use `make test` to verify compilation and run tests.

## CGO callback pattern

Store interfaces (SessionStore, IdentityKeyStore, etc.) use CGO callbacks:

1. Go `//export` functions in `callbacks.go` receive raw C pointers
2. C bridge functions in `bridge.c` unwrap by-value wrapper structs to raw pointers
3. `pointer.go` provides a handle map for passing Go interfaces through C `void*`
4. `memstore.go` has in-memory implementations for testing

## FFI pointer lifecycle — preventing leaks

Every libsignal FFI type (types with a `ptr *C.Signal...` field) holds a Rust-allocated pointer that **must** be explicitly freed via `Destroy()`. Go's GC does not free these — a missed Destroy is a silent memory leak.

### Rules for working with FFI types

1. **Prefer `[]byte` over FFI types in interfaces.** Store methods already accept `[]byte` for writes (StoreSession, StorePreKey, etc). When a function only needs serialized data, pass `[]byte` instead of an FFI wrapper. This eliminates the leak risk entirely.

2. **Every FFI allocation must have a matching Destroy.** Any function that calls `Deserialize*`, `New*`, `Generate*`, or an accessor that returns a new FFI object (e.g. `PrivateKey.PublicKey()`, `KyberKeyPair.PublicKey()`, `USMC.GetSenderCert()`) creates a Rust allocation. The caller owns it.

3. **Use `defer X.Destroy()` immediately after creation** when the object's lifetime matches the function scope. This is the safest pattern:
   ```go
   key, err := libsignal.DeserializePublicKey(data)
   if err != nil { return err }
   defer key.Destroy()
   ```

4. **For loop-scoped FFI objects, destroy before next iteration or use a cleanups slice:**
   ```go
   var cleanups []func()
   defer func() { for _, fn := range cleanups { fn() } }()
   for _, item := range items {
       addr, _ := libsignal.NewAddress(item, 1)
       cleanups = append(cleanups, addr.Destroy)
   }
   ```

5. **When returning FFI types from a function, document that the caller must Destroy.** If possible, return `[]byte` (serialized) instead to avoid leak risk.

6. **Never create new FFI wrapper types.** If you need new functionality, prefer functions that accept/return `[]byte`. Only add FFI wrapper types if the Rust FFI requires holding a pointer across multiple C calls.

7. **CGO callback path is different.** In `callbacks.go`, Load callbacks (goLoadSession, etc.) create FFI objects and pass ownership to Rust via `recordp.raw = rec.ptr`. Rust destroys these — do NOT call Destroy on the Go side.

### FFI leak detection

The `ffitrack` build tag enables runtime leak detection. When enabled, every FFI allocation is tracked, and `runtime.SetFinalizer` logs a warning if an object is garbage-collected without `Destroy()` being called. See `internal/libsignal/ffitrack.go`.

## Logging convention

All logging uses an optional `*log.Logger` instance threaded from `Client.logger` (set via `WithLogger`). Never use the global `log.Printf` — always accept a `*log.Logger` parameter and use the nil-safe `logf()` helper in `internal/signalservice/receiver.go`:

```go
func logf(logger *log.Logger, format string, args ...any) {
    if logger != nil {
        logger.Printf(format, args...)
    }
}
```

When adding new functions that need logging, accept `logger *log.Logger` as a parameter and pass it through to `NewTransport` and any callees. Logging is disabled by default (nil logger).

## Key files

| File                                     | Purpose                                                                                            |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `client.go`                              | Public API: Client, Link, Load, Send, Receive, SyncContacts, SyncGroups, LookupNumber, Groups, Close |
| `libsignal.go`                           | CGO preamble (LDFLAGS, includes)                                                                   |
| `error.go`                               | FFI error wrapping, owned buffer handling                                                          |
| `privatekey.go`                          | PrivateKey: generate, serialize, sign, agree                                                       |
| `publickey.go`                           | PublicKey: derive, serialize, verify, compare                                                      |
| `identitykey.go`                         | IdentityKeyPair: serialize/deserialize                                                             |
| `address.go`                             | Protocol address (name + device ID)                                                                |
| `prekey.go`                              | PreKeyRecord, SignedPreKeyRecord                                                                   |
| `kyberprekey.go`                         | KyberKeyPair, KyberPreKeyRecord                                                                    |
| `prekeybundle.go`                        | PreKeyBundle construction                                                                          |
| `session.go`                             | SessionRecord                                                                                      |
| `message.go`                             | CiphertextMessage, PreKeySignalMessage, SignalMessage                                              |
| `store.go`                               | Store interfaces (6 types including SenderKeyStore)                                                |
| `senderkey.go`                           | SenderKeyRecord, SenderKeyDistributionMessage, GroupDecryptMessage                                 |
| `zkgroup.go`                             | GroupMasterKey, GroupSecretParams, GroupPublicParams, GroupIdentifier: zkgroup crypto operations   |
| `callbacks.go`                           | CGO callback exports + store wrappers                                                              |
| `bridge.c`                               | C bridge functions for callback type conversion                                                    |
| `memstore.go`                            | In-memory store implementations                                                                    |
| `pointer.go`                             | Handle map for Go→C→Go pointer passing                                                             |
| `protocol.go`                            | ProcessPreKeyBundle, Encrypt, Decrypt                                                              |
| `sealedsender.go`                        | SealedSenderDecrypt: sealed sender (UNIDENTIFIED_SENDER) decryption                                |
| `internal/provisioncrypto/devicename.go` | Device name encrypt/decrypt (DeviceNameCipher)                                                     |
| `internal/signalws/persistent.go`        | PersistentConn: keep-alive heartbeats + automatic reconnection                                     |
| `internal/signalservice/keygen.go`       | Pre-key set generation (signed EC + Kyber)                                                         |
| `internal/signalservice/transport.go`    | HTTP transport layer: rate limiting, retry logic, JSON helpers (PutJSON, PostJSON, etc.)           |
| `internal/signalservice/httptypes.go`    | JSON request/response types for all endpoints                                                      |
| `internal/signalservice/registration.go` | RegisterLinkedDevice orchestration                                                                 |
| `internal/signalservice/sender.go`       | SendTextMessage, padMessage: session establishment + transport padding + encryption + delivery     |
| `internal/signalservice/groupsender.go`  | GroupSender: sender key distribution + group encryption + sealed sender delivery                   |
| `internal/signalservice/deviceretry.go`  | withDeviceRetry: centralized 409/410 device mismatch retry loop for all send paths                |
| `internal/signalservice/retryreceipt.go` | SendRetryReceipt, HandleRetryReceipt: DecryptionErrorMessage retry flow                            |
| `internal/signalservice/dump.go`         | dumpEnvelope: raw envelope debug dump to file, LoadDump for test replay                            |
| `internal/signalservice/receiver.go`     | ReceiveMessages: WebSocket receive loop + decryption + retry receipts + contact sync + iterator    |
| `internal/signalcrypto/profilecipher.go` | ProfileCipher: AES-GCM profile field encryption/decryption, padding helpers                        |
| `internal/signalcrypto/storagecrypto.go` | DecryptStorageManifest, DecryptStorageItem: AES-256-GCM Storage Service decryption                  |
| `internal/signalcrypto/storagekeys.go`   | StorageKey, StorageManifestKey, StorageItemKey, RecordIkm: Storage Service key derivation           |
| `internal/signalcrypto/accesskey.go`     | DeriveAccessKey: sealed sender access key derivation from profile key (AES-GCM)                    |
| `internal/signalcrypto/attachment.go`    | DecryptAttachment, AttachmentURL: attachment AES-CBC decryption + CDN URL construction              |
| `internal/signalservice/attachment.go`   | downloadAttachment: CDN download + decryption orchestration                                        |
| `internal/signalservice/contactsync.go`  | ParseContactStream, RequestContactSync: contact sync request + response parsing                    |
| `internal/signalservice/storage.go`      | SyncGroupsFromStorage: Storage Service client for group discovery                                  |
| `internal/signalservice/accesskey.go`    | deriveAccessKeyForRecipient: recipient profile key lookup + access key derivation                   |
| `internal/signalservice/trustroot.go`    | Signal sealed sender trust root public keys                                                        |
| `internal/libsignal/decryptionerror.go`  | DecryptionErrorMessage: CGO bindings for retry receipts                                            |
| `internal/libsignal/plaintextcontent.go` | PlaintextContent: CGO bindings for unencrypted retry receipt delivery                              |
| `internal/store/store.go`                | SQLite store: Open, Close, migrations, SetIdentity, SetPNIIdentity                                 |
| `internal/store/pni.go`                  | PNIIdentityStore wrapper: returns PNI identity for GetIdentityKeyPair/GetLocalRegistrationID        |
| `internal/store/account.go`              | Account CRUD (credentials persistence)                                                             |
| `internal/store/session.go`              | SessionStore + ArchiveSession implementation                                                       |
| `internal/store/identity.go`             | IdentityKeyStore implementation (TOFU)                                                             |
| `internal/store/prekey.go`               | PreKeyStore, SignedPreKeyStore, KyberPreKeyStore implementations                                   |
| `internal/store/senderkey.go`            | SenderKeyStore implementation for group messaging                                                  |
| `internal/store/contact.go`              | Contact CRUD: SaveContact, GetContactByACI, SaveContacts (bulk upsert)                             |
| `internal/store/group.go`                | Group CRUD: SaveGroup, GetGroup, GetAllGroups                                                      |
| `cmd/sgnl/groups.go`                     | CLI: list groups, sync from Storage Service, fetch details from Groups V2 API                      |
| `internal/libsignal/net.go`              | TokioAsyncContext, ConnectionManager: async runtime + network connection wrappers                   |
| `internal/libsignal/bridge_async.c`      | C bridge functions for CDSI async completion callbacks                                              |
| `internal/libsignal/cdsi.go`             | LookupRequest, CDSILookup: CDSI phone number lookup with async FFI bridge                          |
| `internal/libsignal/authcredential.go`   | ServerPublicParams: zkgroup auth credential presentation for Groups V2 API                         |
| `internal/signalservice/cdsi.go`         | CDSI auth endpoint + LookupNumbers orchestration: phone number → ACI resolution                    |
| `internal/signalservice/groupsv2.go`     | Groups V2 API client: fetch group details (name, members) using zkgroup auth                       |
