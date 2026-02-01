# Phase 2: Signal Service Layer (Pure Go)

**Status: NOT STARTED** — Phase 1 (CGO bindings) is complete.

Goal: link as secondary device, send text messages, receive text messages. Pure Go implementation of the Signal server protocol, using Phase 1's CGO bindings for crypto.

**Primary reference:** `../Signal-Android/lib/libsignal-service/` (official, canonical).

Note: Signal no longer publishes `libsignal-service-java` as a standalone library. It's embedded in Signal-Android, coupled to Android/GCM. Third-party clients like signal-cli depend on the Turasa fork which strips GCM and adds provisioning support. We avoid both problems by reimplementing the minimal protocol subset in pure Go, referencing Signal-Android's source directly.

## Protobuf definitions

Source: `../Signal-Android/lib/libsignal-service/src/main/protowire/`

| Proto file | Key messages |
|---|---|
| `SignalService.proto` | `Envelope`, `Content`, `DataMessage`, `SyncMessage`, `ReceiptMessage` |
| `Provisioning.proto` | `ProvisionEnvelope`, `ProvisionMessage` |
| `WebSocketResources.proto` | `WebSocketMessage`, `WebSocketRequestMessage`, `WebSocketResponseMessage` |

Generate Go code with `buf generate` into `pkg/proto/gen/`.

Note: Signal-Android uses Square Wire for proto compilation. We use standard `protoc-gen-go`. The proto files may need minor adjustments (Wire uses different package/import conventions).

## HTTP client (`pkg/signalservice/client.go`)

REST client for Signal's API at `https://chat.signal.org`.

Authentication: HTTP Basic with `{aci_uuid}.{deviceId}:{password}`.

Endpoints needed for minimal scope:

| Method | Path | Purpose | Reference |
|---|---|---|---|
| `PUT` | `/v1/devices/{provisioningCode}` | Finalize device registration | `LinkDeviceApi.kt` |
| `PUT` | `/v2/keys?identity={aci\|pni}` | Upload pre-keys | `PushServiceSocket.java` |
| `GET` | `/v2/keys/{destination}/{deviceId}` | Get recipient's pre-keys | `PushServiceSocket.java` |
| `PUT` | `/v1/messages/{destination}` | Send message | `PushServiceSocket.java` |

Reference: `../Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java`

## WebSocket (`pkg/signalservice/websocket.go`)

Two connections:

1. **Provisioning** (unauthenticated): `wss://chat.signal.org/v1/websocket/provisioning/`
2. **Messages** (authenticated): `wss://chat.signal.org/v1/websocket/?login={aci}.{deviceId}&password={pass}`

Protocol: each frame is a `WebSocketMessage` protobuf. Server sends `WebSocketRequestMessage` (new messages); client responds with `WebSocketResponseMessage` (status 200 to ACK).

Keep-alive: every 30s, expect response within 20s.

Reference: `../Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/websocket/SignalWebSocket.kt`

## Device linking (`pkg/signalservice/provisioning.go`)

Derived from Signal-Android's `LinkDeviceApi.kt` and `ProvisioningApi.kt`.

```
Step 1:  Generate temporary EC key pair
         → libsignal.GenerateIdentityKeyPair()

Step 2:  Generate random password (18 bytes, base64)

Step 3:  Connect provisioning WebSocket
         wss://chat.signal.org/v1/websocket/provisioning/

Step 4:  Read first message → provisioning UUID
         Server sends WebSocketRequestMessage with path "/v1/address"
         Body contains provisioning UUID

Step 5:  Build device link URI
         sgnl://linkdevice?uuid={uuid}&pub_key={base64(tempPublicKey)}
         Display as QR code for user to scan with primary device

Step 6:  Read second message → ProvisionEnvelope (encrypted)
         Primary device sends provisioning data via server

Step 7:  Decrypt ProvisionEnvelope
         - ECDH: sharedSecret = libsignal.PrivateKey.Agree(envelope.publicKey)
           (uses signal_privatekey_agree from FFI)
         - HKDF(sharedSecret, info="TextSecure Provisioning Message") → 64 bytes
           (pure Go: golang.org/x/crypto/hkdf)
           [0:32] = AES key, [32:64] = MAC key
         - Verify HMAC-SHA256(version || iv || ciphertext)
         - AES-256-CBC decrypt + PKCS7 unpad
         - Parse as ProvisionMessage protobuf

Step 8:  Extract from ProvisionMessage:
         - ACI + PNI identity key pairs
         - Phone number, ACI (UUID), PNI (UUID)
         - Profile key, master key, account entropy pool
         - Provisioning code
         - Read receipts preference

Step 9:  Generate pre-keys for both ACI and PNI
         For each: 100 one-time EC pre-keys + 1 signed pre-key
         + 1 last-resort Kyber pre-key (KYBER_1024)

Step 10: Encrypt device name
         AES-256-GCM with HKDF-derived key from ACI private key

Step 11: PUT /v1/devices/{provisioningCode}
         Body: registrationId, pniRegistrationId, fetchesMessages: true,
               name, aciSignedPreKey, pniSignedPreKey,
               aciPqLastResortPreKey, pniPqLastResortPreKey
         Response: { deviceId }

Step 12: Upload pre-keys
         PUT /v2/keys?identity=aci
         PUT /v2/keys?identity=pni

Step 13: Request sync data from primary
         Send SyncMessage.Request for: GROUPS, CONTACTS, BLOCKED, CONFIGURATION, KEYS
```

Reference files in Signal-Android:
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/link/LinkDeviceApi.kt`
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/provisioning/ProvisioningApi.kt`
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/crypto/PrimaryProvisioningCipher.java`

## Message sending (`pkg/signalservice/sender.go`)

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

## Message receiving (`pkg/signalservice/receiver.go`)

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

## Persistent storage (`pkg/store/sqlite/`)

SQLite via `modernc.org/sqlite` (pure Go). Tables:

| Table | Columns | Purpose |
|---|---|---|
| `account` | number, aci, pni, device_id, password, identity_key_pair_aci, identity_key_pair_pni, profile_key, master_key | Local device credentials |
| `session` | service_id, device_id, record (BLOB) | Signal Protocol sessions |
| `pre_key` | id, public_key, private_key | One-time pre-keys |
| `signed_pre_key` | id, public_key, private_key, signature, timestamp | Signed pre-keys |
| `kyber_pre_key` | id, key_pair (BLOB), signature, timestamp | Post-quantum (Kyber) pre-keys |
| `identity` | address, identity_key, trust_level | Recipient identity keys |

All stores implement interfaces from `pkg/libsignal/store.go`.

## Demo CLI (`cmd/signal-link/`)

```go
func main() {
    pm := signalservice.NewProvisioningManager()
    uri, _ := pm.GetDeviceLinkURI(ctx)
    fmt.Println("Scan this QR code with your phone:")
    qrterminal.Generate(uri, os.Stdout)

    account, _ := pm.WaitAndFinish(ctx, "signal-go")
    fmt.Printf("Linked as device %d for %s\n", account.DeviceID, account.Number)

    // Send a test message
    sender := signalservice.NewSender(account, stores)
    sender.Send(ctx, recipientUUID, "Hello from signal-go!")

    // Receive messages
    receiver := signalservice.NewReceiver(account, stores)
    for msg := range receiver.Receive(ctx) {
        fmt.Printf("[%s] %s: %s\n", msg.Timestamp, msg.Sender, msg.Body)
    }
}
```

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

| Step | Files | Test proves |
|---|---|---|
| G1 | `pkg/proto/` | Copy proto files, `buf generate` compiles without error |
| G2 | `pkg/proto/` | Construct a `DataMessage{body: "hi", timestamp: 123}`, marshal/unmarshal round-trip |
| G3 | `pkg/proto/` | Construct `WebSocketMessage` wrapping a `WebSocketRequestMessage`, round-trip |
| G4 | `pkg/proto/` | Construct `ProvisionEnvelope`, round-trip |

### H. WebSocket framing

| Step | Files | Test proves |
|---|---|---|
| H1 | `websocket.go` | Connect to local test server, send/receive raw bytes |
| H2 | `websocket.go` | Send `WebSocketMessage` protobuf, receive decoded response |
| H3 | `websocket.go` | Keep-alive ping/pong every 30s (mock server tracks timing) |
| H4 | `websocket.go` | Reconnect on disconnect |

### I. Provisioning (device linking)

| Step | Files | Test proves |
|---|---|---|
| I1 | `provisioning.go` | Generate temp EC key pair + random password |
| I2 | `provisioning.go` | Format `sgnl://linkdevice?uuid={uuid}&pub_key={b64}` URI correctly |
| I3 | `provisioning.go` | ECDH shared secret: `PrivateKey.Agree(publicKey)` matches known test vector |
| I4 | `provisioning.go` | HKDF derive AES+MAC keys from shared secret (pure Go, known test vector) |
| I5 | `provisioning.go` | Verify HMAC-SHA256 of provisioning envelope |
| I6 | `provisioning.go` | AES-256-CBC decrypt + PKCS7 unpad (known test vector) |
| I7 | `provisioning.go` | Full provisioning decrypt: envelope → `ProvisionMessage` protobuf |
| I8 | `provisioning.go` | Extract ACI/PNI identity keys, phone number, provisioning code from message |
| I9 | `provisioning.go` | Encrypt device name (AES-256-GCM with HKDF from ACI private key) |
| I10 | `provisioning.go` | Full provisioning flow against mock WebSocket (steps 1-8 end-to-end) |

### J. HTTP client

| Step | Files | Test proves |
|---|---|---|
| J1 | `client.go` | HTTP Basic auth header: `{aci}.{deviceId}:{password}` |
| J2 | `client.go` | `PUT /v1/devices/{code}` → mock returns `{deviceId}` |
| J3 | `client.go` | `PUT /v2/keys?identity=aci` → upload pre-keys (mock verifies JSON body) |
| J4 | `client.go` | `GET /v2/keys/{dest}/{devId}` → parse pre-key bundle response |
| J5 | `client.go` | `PUT /v1/messages/{dest}` → send encrypted message (mock verifies body) |

### K. Message sending

| Step | Files | Test proves |
|---|---|---|
| K1 | `sender.go` | Build `Content{dataMessage{body, timestamp}}` protobuf, serialize |
| K2 | `sender.go` | Fetch pre-key bundle from mock server, parse into `PreKeyBundle` |
| K3 | `sender.go` | Establish session from fetched bundle (uses Phase 1 `ProcessPreKeyBundle`) |
| K4 | `sender.go` | Encrypt content via session cipher → `OutgoingPushMessage` |
| K5 | `sender.go` | Full send: build, encrypt, PUT to mock server |

### L. Message receiving

| Step | Files | Test proves |
|---|---|---|
| L1 | `receiver.go` | Parse `Envelope` from raw bytes |
| L2 | `receiver.go` | Decrypt `PREKEY_BUNDLE` envelope → `Content` (uses Phase 1 `DecryptPreKeyMessage`) |
| L3 | `receiver.go` | Decrypt `CIPHERTEXT` envelope → `Content` (uses Phase 1 `DecryptMessage`) |
| L4 | `receiver.go` | ACK: send `WebSocketResponseMessage{status: 200, id: request.id}` |
| L5 | `receiver.go` | Full receive loop: mock WebSocket sends envelopes, receiver decrypts and ACKs |

### M. Persistent storage

| Step | Files | Test proves |
|---|---|---|
| M1 | `pkg/store/sqlite/` | Create database, run migrations, tables exist |
| M2 | `pkg/store/sqlite/` | `SessionStore` CRUD: store, load, overwrite |
| M3 | `pkg/store/sqlite/` | `IdentityKeyStore` CRUD: save, get, trust check |
| M4 | `pkg/store/sqlite/` | `PreKeyStore` CRUD: store, load, remove |
| M5 | `pkg/store/sqlite/` | `SignedPreKeyStore` CRUD: store, load |
| M6 | `pkg/store/sqlite/` | `KyberPreKeyStore` CRUD: store, load, mark-used |
| M7 | `pkg/store/sqlite/` | `Account` table: save and load credentials |
| M8 | `pkg/store/sqlite/` | All SQLite stores pass same tests as in-memory stores (interface conformance) |

### N. Integration

| Step | Files | Test proves |
|---|---|---|
| N1 | `cmd/signal-link/` | CLI scaffolding: parse flags, print usage |
| N2 | `cmd/signal-link/` | Link to real Signal account (manual test, QR code in terminal) |
| N3 | `cmd/signal-link/` | Send a real text message |
| N4 | `cmd/signal-link/` | Receive and print real text messages |

## Server endpoints

| Service | URL |
|---|---|
| Chat API | `https://chat.signal.org` |
| CDN 0 | `https://cdn.signal.org` |
| CDN 2 | `https://cdn2.signal.org` |
| CDN 3 | `https://cdn3.signal.org` |

Source: `../Signal-Android/lib/libsignal-service/` — `LiveConfig` equivalent in the service configuration.
