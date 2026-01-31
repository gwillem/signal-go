# Phase 2: Signal Service Layer (Pure Go)

Goal: link as secondary device, send text messages, receive text messages. Pure Go implementation of the Signal server protocol, using Phase 1's CGO bindings for crypto.

**Primary reference:** `../Signal-Android/lib/libsignal-service/` (official, canonical).

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

## Implementation order (TDD)

| Step | What | Test |
|---|---|---|
| 1 | Protobuf setup | Parse known envelope bytes |
| 2 | WebSocket framing | Encode/decode WebSocket protobuf messages |
| 3 | Provisioning URI | Format matches `sgnl://linkdevice?...` |
| 4 | Provisioning decrypt | Decrypt known test vector |
| 5 | HTTP client | Mock server, verify auth headers and paths |
| 6 | Full provisioning flow | Mock WebSocket, complete link |
| 7 | Message sending | Encrypt + send via mock server |
| 8 | Envelope decryption | Decrypt known ciphertext with test session |
| 9 | Message receive loop | Mock WebSocket, receive and ACK |
| 10 | SQLite stores | CRUD on all tables |
| 11 | Integration test | Link real device, send + receive real message |

## Server endpoints

| Service | URL |
|---|---|
| Chat API | `https://chat.signal.org` |
| CDN 0 | `https://cdn.signal.org` |
| CDN 2 | `https://cdn2.signal.org` |
| CDN 3 | `https://cdn3.signal.org` |

Source: `../Signal-Android/lib/libsignal-service/` — `LiveConfig` equivalent in the service configuration.
