# signal-go

Go library for Signal messenger, replacing the Java signal-cli dependency. Licensed under AGPL-3.0.

## Housekeeping

- Keep `docs/*.md` up to date when completing tasks, learning something new, or making architectural decisions. Update phase status markers, implementation notes, and reference information.

## Architecture

- `client.go` — Public API: `Client` with `Link`, `Load`, `Send`, `Receive`, `SyncContacts`, `LookupNumber`, `Close`, `Number`, `DeviceID`
- `internal/libsignal/` — CGO bindings to libsignal's Rust C FFI (Phase 1, complete)
- `internal/proto/` — Protobuf definitions and generated Go code (Provisioning, WebSocket, DeviceName, SignalService)
- `internal/provisioncrypto/` — Provisioning envelope encrypt/decrypt (HKDF, AES-CBC, HMAC, PKCS7), device name encryption
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

- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/websocket/` — WebSocket connection (OkHttpWebSocketConnection, LibSignalChatConnection)
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/websocket/` — SignalWebSocket, message batching
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/push/` — PushServiceSocket (REST API calls, 409/410 error throwing)
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/` — High-level service APIs
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/SignalServiceMessageSender.java` — Message sending, 409/410 retry handling (handleMismatchedDevices, handleStaleDevices)
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/crypto/` — Encryption, registration ID retrieval

### Anti-patterns to avoid

These mistakes have caused bugs in the past:

- **Caching protocol state separately** — Registration IDs, identity keys, etc. are already in libsignal's data structures. Don't duplicate them in custom database tables.
- **Inventing retry/recovery logic** — Signal-Android's retry logic is simple (archive + retry N times). Don't add staleSeen tracking or other "clever" solutions.
- **Assuming server behavior** — If unsure what the server expects, grep Signal-Android for the endpoint or error code.
- **Skipping message formatting steps** — Signal uses transport-level padding (`PushTransportDetails.getPaddedMessageBody()`) before encryption. Missing this causes decryption failures even though the protocol-level crypto succeeds.

## Prerequisites

- Go 1.25+
- Rust nightly toolchain (`rustup install nightly`)
- cbindgen (`cargo install cbindgen`)
- Local libsignal checkout at `../libsignal`

## Building

```
make build    # builds libsignal_ffi.a + generates libsignal-ffi.h
make test     # runs go test ./...
```

## Testing

Always use `make test` to run tests — it sets the required `CGO_LDFLAGS_ALLOW` and `CGO_LDFLAGS` flags. Never run `go build` — always use `make test` to verify compilation.

## CGO callback pattern

Store interfaces (SessionStore, IdentityKeyStore, etc.) use CGO callbacks:

1. Go `//export` functions in `callbacks.go` receive raw C pointers
2. C bridge functions in `bridge.c` unwrap by-value wrapper structs to raw pointers
3. `pointer.go` provides a handle map for passing Go interfaces through C `void*`
4. `memstore.go` has in-memory implementations for testing

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
| `client.go`                              | Public API: Client, Link, Load, Send, Receive, SyncContacts, LookupNumber, Close, Number, DeviceID |
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
| `internal/signalservice/retryreceipt.go` | SendRetryReceipt, HandleRetryReceipt: DecryptionErrorMessage retry flow                            |
| `internal/signalservice/dump.go`         | dumpEnvelope: raw envelope debug dump to file, LoadDump for test replay                            |
| `internal/signalservice/receiver.go`     | ReceiveMessages: WebSocket receive loop + decryption + retry receipts + contact sync + iterator    |
| `internal/signalservice/attachment.go`   | DownloadAttachment, DecryptAttachment: CDN download + AES-CBC decryption                           |
| `internal/signalservice/contactsync.go`  | ParseContactStream, RequestContactSync: contact sync request + response parsing                    |
| `internal/signalservice/trustroot.go`    | Signal sealed sender trust root public keys                                                        |
| `internal/libsignal/decryptionerror.go`  | DecryptionErrorMessage: CGO bindings for retry receipts                                            |
| `internal/libsignal/plaintextcontent.go` | PlaintextContent: CGO bindings for unencrypted retry receipt delivery                              |
| `internal/store/store.go`                | SQLite store: Open, Close, migrations, SetIdentity                                                 |
| `internal/store/account.go`              | Account CRUD (credentials persistence)                                                             |
| `internal/store/session.go`              | SessionStore + ArchiveSession implementation                                                       |
| `internal/store/identity.go`             | IdentityKeyStore implementation (TOFU)                                                             |
| `internal/store/prekey.go`               | PreKeyStore, SignedPreKeyStore, KyberPreKeyStore implementations                                   |
| `internal/store/senderkey.go`            | SenderKeyStore implementation for group messaging                                                  |
| `internal/store/contact.go`              | Contact CRUD: SaveContact, GetContactByACI, SaveContacts (bulk upsert)                             |
