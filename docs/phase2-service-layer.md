# Phase 2: Signal Service Layer (Pure Go)

**Status: IN PROGRESS** — Device provisioning (secondary device linking) implemented.

Goal: link as secondary device, send text messages, receive text messages. Pure Go implementation of the Signal server protocol, using Phase 1's CGO bindings for crypto.

**Primary reference:** `../Signal-Android/lib/libsignal-service/` (official, canonical).

Note: Signal no longer publishes `libsignal-service-java` as a standalone library. It's embedded in Signal-Android, coupled to Android/GCM. Third-party clients like signal-cli depend on the Turasa fork which strips GCM and adds provisioning support. We avoid both problems by reimplementing the minimal protocol subset in pure Go, referencing Signal-Android's source directly.

## Protobuf definitions

Source: `../Signal-Android/lib/libsignal-service/src/main/protowire/`

| Proto file                 | Key messages                                                              | Status  |
| -------------------------- | ------------------------------------------------------------------------- | ------- |
| `Provisioning.proto`       | `ProvisionEnvelope`, `ProvisionMessage`, `ProvisioningAddress`            | Done    |
| `WebSocketResources.proto` | `WebSocketMessage`, `WebSocketRequestMessage`, `WebSocketResponseMessage` | Done    |
| `SignalService.proto`      | `Envelope`, `Content`, `DataMessage`, `SyncMessage`, `ReceiptMessage`     | Not yet |

Generated into `internal/proto/` using `protoc --go_out` with `paths=source_relative`. Run `make proto` to regenerate.

Each `.proto` file has `option go_package = "github.com/gwillem/signal-go/internal/proto";` added. Signal-Android uses Square Wire for proto compilation; the files needed only this one-line addition for `protoc-gen-go` compatibility.

## HTTP client (`internal/signalservice/client.go`)

REST client for Signal's API at `https://chat.signal.org`.

Authentication: HTTP Basic with `{aci_uuid}.{deviceId}:{password}`.

Endpoints needed for minimal scope:

| Method | Path                                | Purpose                      | Reference                |
| ------ | ----------------------------------- | ---------------------------- | ------------------------ |
| `PUT`  | `/v1/devices/{provisioningCode}`    | Finalize device registration | `LinkDeviceApi.kt`       |
| `PUT`  | `/v2/keys?identity={aci\|pni}`      | Upload pre-keys              | `PushServiceSocket.java` |
| `GET`  | `/v2/keys/{destination}/{deviceId}` | Get recipient's pre-keys     | `PushServiceSocket.java` |
| `PUT`  | `/v1/messages/{destination}`        | Send message                 | `PushServiceSocket.java` |

Reference: `../Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java`

## WebSocket (`internal/signalws/`)

**Status: COMPLETE** (basic framing). Keep-alive and reconnection deferred.

Two connection types:

1. **Provisioning** (unauthenticated): `wss://chat.signal.org/v1/websocket/provisioning/`
2. **Messages** (authenticated): `wss://chat.signal.org/v1/websocket/?login={aci}.{deviceId}&password={pass}`

Protocol: each frame is a `WebSocketMessage` protobuf. Server sends `WebSocketRequestMessage` (new messages); client responds with `WebSocketResponseMessage` (status 200 to ACK).

Implementation: `internal/signalws/conn.go` wraps `github.com/coder/websocket` with protobuf marshaling. Provides `Dial`, `ReadMessage`, `WriteMessage`, `SendResponse`. Tested with `httptest` WebSocket server.

Keep-alive (every 30s, expect response within 20s) and reconnection are deferred to the message receiving phase.

Reference: `../Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/websocket/SignalWebSocket.kt`

## Device linking

Derived from Signal-Android's `LinkDeviceApi.kt` and `ProvisioningApi.kt`.

```
Step 1:  ✅ Generate temporary EC key pair
         → libsignal.GeneratePrivateKey() + PrivateKey.PublicKey()

Step 2:  Generate random password (18 bytes, base64) — deferred to registration step

Step 3:  ✅ Connect provisioning WebSocket
         wss://chat.signal.org/v1/websocket/provisioning/

Step 4:  ✅ Read first message → provisioning UUID
         Server sends WebSocketRequestMessage with PUT /v1/address
         Body is ProvisioningAddress protobuf containing UUID

Step 5:  ✅ Build device link URI
         sgnl://linkdevice?uuid={uuid}&pub_key={base64url(tempPublicKey)}
         Display as QR code for user to scan with primary device

Step 6:  ✅ Read second message → ProvisionEnvelope (encrypted)
         Server sends WebSocketRequestMessage with PUT /v1/message
         Body is ProvisionEnvelope protobuf

Step 7:  ✅ Decrypt ProvisionEnvelope
         - ECDH: sharedSecret = libsignal.PrivateKey.Agree(envelope.publicKey)
           (uses signal_privatekey_agree from FFI)
         - HKDF(sharedSecret, salt=nil, info="TextSecure Provisioning Message") → 64 bytes
           (pure Go: golang.org/x/crypto/hkdf)
           [0:32] = AES key, [32:64] = MAC key
         - Body wire format: version(1) || iv(16) || ciphertext(variable) || mac(32)
         - Check version == 0x01
         - Verify HMAC-SHA256(macKey, version || iv || ciphertext) against mac
         - AES-256-CBC decrypt with cipherKey + iv → padded plaintext
         - PKCS7 unpad → raw plaintext

Step 8:  ✅ Parse ProvisionMessage protobuf → ProvisionData struct
         - ACI + PNI identity key pairs (public + private)
         - Phone number, ACI (UUID), PNI (UUID)
         - Profile key, master key, account entropy pool
         - Provisioning code
         - Ephemeral backup key, media root backup key

Step 9:  Generate pre-keys for both ACI and PNI — NOT STARTED
         For each: 100 one-time EC pre-keys + 1 signed pre-key
         + 1 last-resort Kyber pre-key (KYBER_1024)

Step 10: Encrypt device name — NOT STARTED
         AES-256-GCM with HKDF-derived key from ACI private key

Step 11: PUT /v1/devices/{provisioningCode} — NOT STARTED
         Body: registrationId, pniRegistrationId, fetchesMessages: true,
               name, aciSignedPreKey, pniSignedPreKey,
               aciPqLastResortPreKey, pniPqLastResortPreKey
         Response: { deviceId }

Step 12: Upload pre-keys — NOT STARTED
         PUT /v2/keys?identity=aci
         PUT /v2/keys?identity=pni

Step 13: Request sync data from primary — NOT STARTED
         Send SyncMessage.Request for: GROUPS, CONTACTS, BLOCKED, CONFIGURATION, KEYS
```

### Implementation details

Provisioning crypto is split into its own package (`internal/provisioncrypto/`) separate from transport (`internal/signalws/`), making the full decrypt pipeline testable with synthetic test vectors and no network. The end-to-end test in `internal/signalservice/provisioning_test.go` uses an `httptest` WebSocket server that simulates the primary device: performs real ECDH key agreement, encrypts a ProvisionMessage, and sends it through the WebSocket. The secondary side decrypts and parses it, validating the full flow.

Key insight: the provisioning envelope body uses `version(1) || iv(16) || ciphertext || mac(32)` wire format, where the MAC covers `version || iv || ciphertext` (everything except the MAC itself). This is verified before decryption (encrypt-then-MAC pattern).

Key insight: the link URI uses URL-safe base64 (`base64.URLEncoding`) for the public key, not standard base64.

### Packages

| Package                | Purpose                                                                   |
| ---------------------- | ------------------------------------------------------------------------- |
| `internal/provisioncrypto/` | PKCS7, HKDF, HMAC, AES-CBC, envelope decrypt, ProvisionData parsing       |
| `internal/signalws/`        | Protobuf-framed WebSocket (Dial, ReadMessage, WriteMessage, SendResponse) |
| `client.go`          | Public API: Client with Link, Send, Receive                              |
| `internal/signalservice/`   | Orchestration: RunProvisioning, DeviceLinkURI                             |

Reference files in Signal-Android:

- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/link/LinkDeviceApi.kt`
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/provisioning/ProvisioningApi.kt`
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/crypto/PrimaryProvisioningCipher.java`

## Message sending (`internal/signalservice/sender.go`)

```
Step 1:  Build Content protobuf
         Content { dataMessage: DataMessage { body: "hello", timestamp: now } }

Step 2:  Serialize Content to bytes

Step 3:  Get recipient's pre-key bundle (if no session exists)
         GET /v2/keys/{destination}/{deviceId}
         → PreKeyBundle

Step 4:  Process bundle to establish session
         libsignal.ProcessPreKeyBundle(bundle, address, stores...)

Step 5:  Encrypt via session cipher
         libsignal.Encrypt(contentBytes, address, stores...)
         → CiphertextMessage

Step 6:  Build OutgoingPushMessage
         { type, destinationDeviceId, content: base64(ciphertext) }

Step 7:  PUT /v1/messages/{destination}
         Body: { messages: [OutgoingPushMessage], timestamp, online: false }
```

Reference: `../Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/SignalServiceMessageSender.java`

## Message receiving (`internal/signalservice/receiver.go`)

```
Step 1:  Connect authenticated WebSocket

Step 2:  Read loop — for each WebSocketRequestMessage with PUT /api/v1/message:

Step 3:  Parse body as Envelope protobuf

Step 4:  Decrypt based on envelope type:
         - PREKEY_BUNDLE (type=3) → libsignal.DecryptPreKeyMessage()
           (requires all 5 stores: session, identity, preKey, signedPreKey, kyberPreKey)
         - CIPHERTEXT (type=1) → libsignal.DecryptMessage()
           (requires session + identity stores)
         - UNIDENTIFIED_SENDER (type=6) → sealed sender decrypt

Step 5:  Parse decrypted bytes as Content protobuf
         Content.dataMessage.body = the text message

Step 6:  ACK: send WebSocketResponseMessage { status: 200, id: request.id }

Step 7:  Emit to consumer via channel or callback
```

Reference: `../Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/SignalServiceMessageReceiver.java`

## Persistent storage (`internal/store/sqlite/`)

SQLite via `modernc.org/sqlite` (pure Go). Tables:

| Table            | Columns                                                                                                      | Purpose                       |
| ---------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------------- |
| `account`        | number, aci, pni, device_id, password, identity_key_pair_aci, identity_key_pair_pni, profile_key, master_key | Local device credentials      |
| `session`        | service_id, device_id, record (BLOB)                                                                         | Signal Protocol sessions      |
| `pre_key`        | id, public_key, private_key                                                                                  | One-time pre-keys             |
| `signed_pre_key` | id, public_key, private_key, signature, timestamp                                                            | Signed pre-keys               |
| `kyber_pre_key`  | id, key_pair (BLOB), signature, timestamp                                                                    | Post-quantum (Kyber) pre-keys |
| `identity`       | address, identity_key, trust_level                                                                           | Recipient identity keys       |

All stores implement interfaces from `internal/libsignal/store.go`.

## Public API (`client.go`)

The root `signal` package provides a `Client` that wraps all internal packages behind a simple interface:

```go
client := signal.NewClient()

// Link as secondary device — blocks until QR is scanned
err := client.Link(ctx, func(uri string) {
    qrterminal.Generate(uri, os.Stdout)
})
fmt.Println("Linked to", client.Number())

// Send a message (not yet implemented)
err = client.Send(ctx, "+31612345678", "Hello from signal-go!")

// Receive messages (not yet implemented)
for msg := range client.Receive(ctx) {
    fmt.Printf("[%s] %s: %s\n", msg.Timestamp, msg.From, msg.Body)
}
```

`Client.Link()` internally calls `signalservice.RunProvisioning()` with the correct WebSocket URL and stores the resulting credentials. The caller only needs to display the QR code URI.

## Implementation order (TDD — tiny steps)

Each step is independently testable and committable. Phase 1 provides the following APIs used here:

- `libsignal.GeneratePrivateKey()`, `PrivateKey.PublicKey()`, `PrivateKey.Sign()`, `PrivateKey.Agree()`
- `libsignal.GenerateIdentityKeyPair()`, `SerializeIdentityKeyPair()`, `DeserializeIdentityKeyPair()`
- `libsignal.GenerateKyberKeyPair()`
- `libsignal.NewPreKeyRecord()`, `NewSignedPreKeyRecord()`, `NewKyberPreKeyRecord()`
- `libsignal.NewPreKeyBundle()`, `ProcessPreKeyBundle()`
- `libsignal.Encrypt()`, `DecryptPreKeyMessage()`, `DecryptMessage()`
- Store interfaces: `SessionStore`, `IdentityKeyStore`, `PreKeyStore`, `SignedPreKeyStore`, `KyberPreKeyStore`

### G. Protobuf + wire format

| Step  | Files        | Test proves                                                                         |
| ----- | ------------ | ----------------------------------------------------------------------------------- |
| G1 ✅ | `internal/proto/` | Copy proto files, `protoc` generates Go code                                        |
| G2    | `internal/proto/` | Construct a `DataMessage{body: "hi", timestamp: 123}`, marshal/unmarshal round-trip |
| G3 ✅ | `internal/proto/` | Construct `WebSocketMessage` wrapping a `WebSocketRequestMessage`, round-trip       |
| G4 ✅ | `internal/proto/` | Construct `ProvisionEnvelope` + `ProvisionMessage`, round-trip                      |

Note: G2 deferred — `SignalService.proto` not yet copied (needed for message send/receive phase). G1 uses `protoc --go_out` instead of `buf generate`.

### H. WebSocket framing

| Step  | Files                  | Test proves                                                          |
| ----- | ---------------------- | -------------------------------------------------------------------- |
| H1 ✅ | `internal/signalws/conn.go` | Connect to local `httptest` server, send/receive protobuf messages   |
| H2 ✅ | `internal/signalws/conn.go` | Read `WebSocketMessage` request, send ACK response                   |
| H3    | —                      | Keep-alive ping/pong every 30s (deferred to message receiving phase) |
| H4    | —                      | Reconnect on disconnect (deferred to message receiving phase)        |

### I. Provisioning (device linking)

| Step   | Files                                       | Test proves                                                                                 |
| ------ | ------------------------------------------- | ------------------------------------------------------------------------------------------- |
| I1 ✅  | `internal/signalservice/provisioning.go`         | Generate temp EC key pair (in RunProvisioning)                                              |
| I2 ✅  | `internal/signalservice/linkuri.go`              | Format `sgnl://linkdevice?uuid={uuid}&pub_key={base64url}` URI correctly                    |
| I3 ✅  | `internal/provisioncrypto/provision.go`          | ECDH shared secret via `PrivateKey.Agree(publicKey)`                                        |
| I4 ✅  | `internal/provisioncrypto/kdf.go`                | HKDF derive AES+MAC keys from shared secret (deterministic output)                          |
| I5 ✅  | `internal/provisioncrypto/mac.go`                | Verify HMAC-SHA256, reject tampered MAC/data                                                |
| I6 ✅  | `internal/provisioncrypto/aescbc.go`, `pkcs7.go` | AES-256-CBC decrypt + PKCS7 unpad, reject bad ciphertext                                    |
| I7 ✅  | `internal/provisioncrypto/provision.go`          | Full provisioning decrypt: key pair + envelope → plaintext                                  |
| I8 ✅  | `internal/provisioncrypto/provisiondata.go`      | Parse ProvisionMessage → ProvisionData, validate required fields                            |
| I9     | —                                           | Encrypt device name (AES-256-GCM with HKDF from ACI private key) — deferred to registration |
| I10 ✅ | `internal/signalservice/provisioning.go`         | Full provisioning flow against mock WebSocket (end-to-end with real crypto)                 |

### J. HTTP client

| Step | Files       | Test proves                                                             |
| ---- | ----------- | ----------------------------------------------------------------------- |
| J1   | `client.go` | HTTP Basic auth header: `{aci}.{deviceId}:{password}`                   |
| J2   | `client.go` | `PUT /v1/devices/{code}` → mock returns `{deviceId}`                    |
| J3   | `client.go` | `PUT /v2/keys?identity=aci` → upload pre-keys (mock verifies JSON body) |
| J4   | `client.go` | `GET /v2/keys/{dest}/{devId}` → parse pre-key bundle response           |
| J5   | `client.go` | `PUT /v1/messages/{dest}` → send encrypted message (mock verifies body) |

### K. Message sending

| Step | Files       | Test proves                                                                |
| ---- | ----------- | -------------------------------------------------------------------------- |
| K1   | `sender.go` | Build `Content{dataMessage{body, timestamp}}` protobuf, serialize          |
| K2   | `sender.go` | Fetch pre-key bundle from mock server, parse into `PreKeyBundle`           |
| K3   | `sender.go` | Establish session from fetched bundle (uses Phase 1 `ProcessPreKeyBundle`) |
| K4   | `sender.go` | Encrypt content via session cipher → `OutgoingPushMessage`                 |
| K5   | `sender.go` | Full send: build, encrypt, PUT to mock server                              |

### L. Message receiving

| Step | Files         | Test proves                                                                        |
| ---- | ------------- | ---------------------------------------------------------------------------------- |
| L1   | `receiver.go` | Parse `Envelope` from raw bytes                                                    |
| L2   | `receiver.go` | Decrypt `PREKEY_BUNDLE` envelope → `Content` (uses Phase 1 `DecryptPreKeyMessage`) |
| L3   | `receiver.go` | Decrypt `CIPHERTEXT` envelope → `Content` (uses Phase 1 `DecryptMessage`)          |
| L4   | `receiver.go` | ACK: send `WebSocketResponseMessage{status: 200, id: request.id}`                  |
| L5   | `receiver.go` | Full receive loop: mock WebSocket sends envelopes, receiver decrypts and ACKs      |

### M. Persistent storage

| Step | Files               | Test proves                                                                   |
| ---- | ------------------- | ----------------------------------------------------------------------------- |
| M1   | `internal/store/sqlite/` | Create database, run migrations, tables exist                                 |
| M2   | `internal/store/sqlite/` | `SessionStore` CRUD: store, load, overwrite                                   |
| M3   | `internal/store/sqlite/` | `IdentityKeyStore` CRUD: save, get, trust check                               |
| M4   | `internal/store/sqlite/` | `PreKeyStore` CRUD: store, load, remove                                       |
| M5   | `internal/store/sqlite/` | `SignedPreKeyStore` CRUD: store, load                                         |
| M6   | `internal/store/sqlite/` | `KyberPreKeyStore` CRUD: store, load, mark-used                               |
| M7   | `internal/store/sqlite/` | `Account` table: save and load credentials                                    |
| M8   | `internal/store/sqlite/` | All SQLite stores pass same tests as in-memory stores (interface conformance) |

### N. Integration

| Step | Files              | Test proves                                                    |
| ---- | ------------------ | -------------------------------------------------------------- |
| N1   | `cmd/signal-link/` | CLI scaffolding: parse flags, print usage                      |
| N2   | `cmd/signal-link/` | Link to real Signal account (manual test, QR code in terminal) |
| N3   | `cmd/signal-link/` | Send a real text message                                       |
| N4   | `cmd/signal-link/` | Receive and print real text messages                           |

## Implementation notes

### Differences from original plan

- **Package layout changed:** Crypto split into `internal/provisioncrypto/` (pure Go, no network) separate from `internal/signalws/` (WebSocket transport) and `internal/signalservice/` (orchestration). This makes the full decrypt pipeline testable with synthetic test vectors.
- **`protoc` instead of `buf`:** Using `protoc --go_out` with `paths=source_relative` directly. No need for `buf.yaml` / `buf.gen.yaml` config. Proto files go into `internal/proto/` (not `internal/proto/gen/`).
- **`github.com/coder/websocket` instead of `nhooyr.io/websocket`:** The nhooyr.io package is deprecated; the maintainer moved to `github.com/coder/websocket` with the same API.
- **WebSocket request paths:** The provisioning server sends `PUT /v1/address` (address) and `PUT /v1/message` (envelope). The body of each is a protobuf (`ProvisioningAddress` and `ProvisionEnvelope` respectively).
- **URL-safe base64:** The device link URI uses `base64.URLEncoding` (RFC 4648 §5) for the public key, not standard base64. This avoids `+` and `/` characters in the URI.

### Provisioning wire format details

The provision envelope body has this wire format:

```
version(1 byte) || iv(16 bytes) || ciphertext(variable) || mac(32 bytes)
```

- Version must be `0x01`
- MAC covers everything except itself: `HMAC-SHA256(macKey, version || iv || ciphertext)`
- This is an encrypt-then-MAC construction (MAC is verified before decryption)
- HKDF uses `salt=nil` (not empty bytes — both are equivalent for HKDF but nil is the standard representation)

### ProvisionMessage fields

The `ProvisionMessage` protobuf contains more fields than originally documented. Notable additions:

- `accountEntropyPool` (string) — new field for account recovery
- `ephemeralBackupKey` (32 bytes) — backup-related
- `mediaRootBackupKey` (32 bytes) — backup-related
- `aciBinary` / `pniBinary` (16-byte UUIDs) — binary UUID representation alongside string UUIDs

The `ProvisionData` Go struct captures all of these. Required field validation: `provisioningCode` and `aciIdentityKeyPublic`/`Private` must be present.

## Server endpoints

| Service  | URL                       |
| -------- | ------------------------- |
| Chat API | `https://chat.signal.org` |
| CDN 0    | `https://cdn.signal.org`  |
| CDN 2    | `https://cdn2.signal.org` |
| CDN 3    | `https://cdn3.signal.org` |

Source: `../Signal-Android/lib/libsignal-service/` — `LiveConfig` equivalent in the service configuration.
