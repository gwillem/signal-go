# Signal-Android Reference for signal-go

Practical reference extracted from the Signal-Android codebase (`../Signal-Android`). Covers the service/protocol layer that signal-go reimplements. Focuses on `lib/libsignal-service/` -- the transport and crypto layer that is independent of Android UI.

> **Source of truth**: Signal-Android is the authoritative reference for expected protocol behavior. When in doubt, check the Java/Kotlin source.

---

## Table of Contents

1. [Service Layer Architecture](#1-service-layer-architecture)
2. [WebSocket Connection](#2-websocket-connection)
3. [Message Sending Flow](#3-message-sending-flow)
4. [Message Receiving Flow](#4-message-receiving-flow)
5. [Pre-Key Management](#5-pre-key-management)
6. [Sealed Sender (Unidentified Delivery)](#6-sealed-sender-unidentified-delivery)
7. [Groups V2 / Sender Key](#7-groups-v2--sender-key)
8. [Contact Sync](#8-contact-sync)
9. [Storage Service](#9-storage-service)
10. [Retry and Error Handling](#10-retry-and-error-handling)
11. [Device Management / Provisioning](#11-device-management--provisioning)
12. [Profile Operations](#12-profile-operations)
13. [CDSI (Contact Discovery)](#13-cdsi-contact-discovery)
14. [HTTP Endpoints Summary](#14-http-endpoints-summary)
15. [Attachment Handling](#15-attachment-handling)

---

## 1. Service Layer Architecture

The service layer lives in `lib/libsignal-service/`. It has been recently refactored from monolithic classes into modular API classes.

### Key Classes

| Class | File | Purpose |
|-------|------|---------|
| `SignalServiceMessageSender` | `api/SignalServiceMessageSender.java` | Central message sending orchestrator (3000+ lines). Handles single, multi-recipient, and sender-key sends. |
| `SignalServiceCipher` | `api/crypto/SignalServiceCipher.java` | Encryption (encrypt, encryptForGroup) and decryption (decrypt) of message envelopes. |
| `EnvelopeContent` | `api/crypto/EnvelopeContent.java` | Abstraction for message content. Two implementations: `Encrypted` (normal) and `Plaintext` (for retry receipts). |
| `PushServiceSocket` | `internal/push/PushServiceSocket.java` | Legacy REST HTTP client (2300+ lines). Still used for some endpoints not yet migrated to modular APIs. |
| `PushTransportDetails` | `internal/push/PushTransportDetails.java` | Transport-level message padding (0x80 + 0x00 padding to 80-byte blocks). |

### Modular API Classes (new pattern)

These Kotlin classes wrap WebSocket/REST calls with `NetworkResult` return types:

| Class | File | Purpose |
|-------|------|---------|
| `MessageApi` | `api/message/MessageApi.kt` | `sendMessage`, `sendGroupMessage`, `reportSpam` |
| `KeysApi` | `api/keys/KeysApi.kt` | Pre-key upload/download, availability counts, key checks |
| `ProfileApi` | `api/profiles/ProfileApi.kt` | Profile get/set, avatar upload |
| `StorageServiceApi` | `api/storage/StorageServiceApi.kt` | Storage service auth, manifest, read/write items |
| `AttachmentApi` | `api/attachment/AttachmentApi.kt` | Attachment upload form, resumable upload |
| `LinkDeviceApi` | `api/link/LinkDeviceApi.kt` | Device listing, linking, provisioning, transfer archive |
| `RegistrationApi` | `api/registration/RegistrationApi.kt` | Verification sessions, registration, secondary device |
| `CdsApi` | `api/cds/CdsApi.kt` | CDSI auth + lookup |
| `AccountApi` | `api/account/AccountApi.kt` | whoami, attributes, registration lock |
| `GroupsV2Api` | `api/groupsv2/GroupsV2Api.java` | Group CRUD, credentials, auth string generation |

### Architecture Pattern

```
Public API (SignalServiceMessageSender, etc.)
    |
    v
Modular API classes (MessageApi, KeysApi, etc.)
    |
    v
SignalWebSocket (auth + unauth) or PushServiceSocket (REST fallback)
    |
    v
WebSocketConnection interface (OkHttpWebSocketConnection or LibSignalChatConnection)
```

---

## 2. WebSocket Connection

### Files
- `internal/websocket/WebSocketConnection.kt` -- Interface
- `internal/websocket/LibSignalChatConnection.kt` -- libsignal-net implementation
- `api/websocket/SignalWebSocket.kt` -- High-level wrapper

### WebSocketConnection Interface

```kotlin
interface WebSocketConnection {
    companion object {
        val DEFAULT_SEND_TIMEOUT = 10.seconds
    }
    val name: String
    fun connect(): Observable<WebSocketConnectionState>
    fun isDead(): Boolean
    fun disconnect()
    fun sendRequest(request: WebSocketRequestMessage, timeoutSeconds: Long): Single<WebsocketResponse>
    fun sendKeepAlive()
    fun readRequestIfAvailable(): Optional<WebSocketRequestMessage>
    fun readRequest(timeoutMillis: Long): WebSocketRequestMessage
    fun sendResponse(response: WebSocketResponseMessage)
}
```

### SignalWebSocket

Two sealed subclasses:
- **`AuthenticatedWebSocket`** -- Identified connection. Has `readMessageBatch()` for receiving envelopes.
- **`UnauthenticatedWebSocket`** -- Unidentified (sealed sender) connection. Has `request()` with `SealedSenderAccess` header injection and 401 fallback.

Key behaviors:
- **Keep-alive tokens**: Named tokens (`"Foregrounded"`, etc.) track who needs the connection alive. When all tokens are removed, a delayed disconnect starts.
- **Delayed disconnect**: Configurable timeout. Resets on each request. Disconnects if no keep-alive tokens remain.
- **Connection lifecycle**: `getWebSocket()` creates connection lazily, reconnects if dead.

### WebSocket Message Framing

Messages are protobuf `WebSocketMessage` with type REQUEST or RESPONSE:
- Incoming envelopes arrive as: `PUT /api/v1/message` (body = serialized `Envelope` protobuf)
- Queue empty signal: `PUT /api/v1/queue/empty`
- Keep-alive: `GET /v1/keepalive`
- ACK responses use status 200 for envelopes, 400 for unknown paths

### Server Timestamp Header

`X-Signal-Timestamp` header on incoming WebSocket requests contains the server-delivered timestamp as a long value.

---

## 3. Message Sending Flow

### File
`api/SignalServiceMessageSender.java`

### Single Recipient Flow

```
1. Content protobuf is built (DataMessage, SyncMessage, etc.)
2. Wrapped in EnvelopeContent.encrypted(content, contentHint, groupId)
3. sendMessage() retry loop (RETRY_COUNT = 4):
   a. getEncryptedMessages() -- for each device:
      - Check if session exists
      - If not: fetch prekeys via KeysApi, process PreKeyBundle with SessionBuilder
      - Encrypt via SignalServiceCipher.encrypt()
   b. Build OutgoingPushMessageList (destination, timestamp, messages, online, urgent)
   c. Send via MessageApi.sendMessage() over WebSocket
   d. On failure: fall back to PushServiceSocket REST
   e. Handle errors:
      - MismatchedDevicesException (409): handleMismatchedDevices()
      - StaleDevicesException (410): handleStaleDevices()
      - AuthorizationFailedException: switchToFallback() on sealed sender
      - InvalidKeyException: switchToFallback() on sealed sender
4. After success, send sync message to self if isMultiDevice
```

### Encryption (EnvelopeContent.Encrypted)

```java
// Sealed sender path (processSealedSender):
PushTransportDetails transport = new PushTransportDetails();
CiphertextMessage message = sessionCipher.encrypt(transport.getPaddedMessageBody(content.encode()));
UnidentifiedSenderMessageContent messageContent = new UnidentifiedSenderMessageContent(
    message, senderCertificate, contentHint.getType(), groupId);
byte[] ciphertext = sealedSessionCipher.encrypt(destination, messageContent);
// Type: UNIDENTIFIED_SENDER

// Unsealed sender path (processUnsealedSender):
CiphertextMessage message = sessionCipher.encrypt(transport.getPaddedMessageBody(content.encode()));
// Type: PREKEY_BUNDLE or CIPHERTEXT (depending on message.getType())
```

### Transport Padding (CRITICAL for interop)

File: `internal/push/PushTransportDetails.java`

```java
PADDING_BLOCK_SIZE = 80;

// Pad: append 0x80, then 0x00 to next 80-byte boundary
// Note: +1 -1 accounts for cipher adding its own padding byte
byte[] paddedMessage = new byte[getPaddedMessageLength(messageBody.length + 1) - 1];
System.arraycopy(messageBody, 0, paddedMessage, 0, messageBody.length);
paddedMessage[messageBody.length] = (byte) 0x80;

// Strip: scan from end for 0x80 marker, trim
```

Missing transport padding causes decryption failures even when protocol-level crypto succeeds.

### OutgoingPushMessage Structure

```java
new OutgoingPushMessage(
    type,           // int: envelope type value
    deviceId,       // int: target device
    registrationId, // int: remote registration ID (from session)
    body            // String: base64-encoded ciphertext
)
```

### OutgoingPushMessageList

```java
new OutgoingPushMessageList(
    destination,  // String: recipient service ID
    timestamp,    // long
    messages,     // List<OutgoingPushMessage> (one per device)
    online,       // boolean
    urgent        // boolean
)
```

---

## 4. Message Receiving Flow

### File
`api/websocket/SignalWebSocket.kt` (AuthenticatedWebSocket)

### readMessageBatch()

```kotlin
fun readMessageBatch(timeout: Long, batchSize: Int, callback: MessageReceivedCallback): Boolean {
    // 1. Wait for first message via readRequest(timeout)
    // 2. Check if it's an envelope (PUT /api/v1/message) or empty signal (PUT /api/v1/queue/empty)
    // 3. Greedily read additional available messages up to batchSize
    // 4. Parse envelopes: Envelope.ADAPTER.decode(request.body)
    // 5. Extract X-Signal-Timestamp header
    // 6. Invoke callback with EnvelopeResponse list
    // 7. Return false if queue is drained, true if more messages expected
}
```

### Decryption (SignalServiceCipher.decrypt)

File: `api/crypto/SignalServiceCipher.java`

Handles four envelope types:

1. **PREKEY_BUNDLE**: `SessionCipher.decrypt(PreKeySignalMessage)` + clear sender key shared state
2. **CIPHERTEXT**: `SessionCipher.decrypt(SignalMessage)`
3. **PLAINTEXT_CONTENT**: `PlaintextContent(envelope.content)` -- used for retry receipts
4. **UNIDENTIFIED_SENDER**: `SealedSessionCipher.decrypt()` -- sealed sender; also clears sender key on PREKEY_TYPE

After decryption, transport padding is stripped via `PushTransportDetails.getStrippedPaddingMessageBody()`, then `Content.ADAPTER.decode()` produces the Content protobuf.

---

## 5. Pre-Key Management

### File
`api/keys/KeysApi.kt`

### Pre-Key Types

| Type | Persistence | Purpose |
|------|-------------|---------|
| Signed EC pre-key | Long-lived (rotated periodically) | Main session establishment key |
| One-time EC pre-key | Consumed on use | Provides forward secrecy for initial message |
| Last-resort Kyber pre-key | Long-lived | Post-quantum key exchange fallback |
| One-time Kyber pre-key | Consumed on use | Post-quantum forward secrecy |

### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v2/keys?identity={aci\|pni}` | GET | Get available pre-key counts |
| `/v2/keys?identity={aci\|pni}` | PUT | Upload pre-keys (PreKeyState) |
| `/v2/keys/{identifier}/{deviceSpecifier}` | GET | Fetch pre-keys for recipient |
| `/v2/keys/check` | POST | Check repeated-use key consistency |

### PreKeyBundle Construction

When fetching pre-keys, devices **must** have both a signed prekey AND a kyber prekey. Devices missing either are skipped:

```kotlin
if (device.getSignedPreKey() == null) { continue }  // Skip
if (device.getKyberPreKey() == null) { continue }    // Skip

PreKeyBundle(registrationId, deviceId,
    preKeyId, preKey,           // EC one-time (optional)
    signedPreKeyId, signedPreKey, signedPreKeySignature,
    identityKey,
    kyberPreKeyId, kyberPreKey, kyberPreKeySignature)
```

### Device Specifier

- `*` = all devices (used when deviceId is 1, the primary)
- `{deviceId}` = specific device

---

## 6. Sealed Sender (Unidentified Delivery)

### Files
- `api/crypto/SealedSenderAccess.kt` -- Access type hierarchy
- `api/crypto/UnidentifiedAccess.java` -- Access key derivation
- `api/crypto/EnvelopeContent.java` -- Encryption path selection

### Access Key Derivation

```java
// UnidentifiedAccess.deriveAccessKeyFrom(profileKey):
byte[] nonce = new byte[12];  // all zeros
byte[] input = new byte[16];  // all zeros
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
cipher.init(ENCRYPT_MODE, new SecretKeySpec(profileKey.serialize(), "AES"), new GCMParameterSpec(128, nonce));
byte[] ciphertext = cipher.doFinal(input);
return ByteUtil.trim(ciphertext, 16);  // first 16 bytes of ciphertext
```

### SealedSenderAccess Hierarchy

Sealed class with four variants:

| Type | Header | Fallback | Use Case |
|------|--------|----------|----------|
| `IndividualUnidentifiedAccessFirst` | `Unidentified-Access-Key: {base64}` | `IndividualGroupSendTokenFirst` (lazy) | Default individual send |
| `IndividualGroupSendTokenFirst` | `Group-Send-Token: {base64}` | `IndividualUnidentifiedAccessFirst` | When group token is preferred |
| `GroupGroupSendToken` | `Group-Send-Token: {base64}` | None | Multi-recipient group send |
| `StorySendNoop` | (no header) | None | Story sends |

### Fallback Chain

On 401 (authorization failure), `switchToFallback()` is called:
1. `IndividualUnidentifiedAccessFirst` -> tries `IndividualGroupSendTokenFirst` (if group token available)
2. `IndividualGroupSendTokenFirst` -> tries `IndividualUnidentifiedAccessFirst` (if UA available)
3. `GroupGroupSendToken` -> no fallback
4. If all sealed sender fails -> falls back to authenticated send (no sealed sender)

### UnauthenticatedWebSocket Header Injection

```kotlin
// UnauthenticatedWebSocket.request():
if (sealedSenderAccess.applyHeader()) {
    headers.add(sealedSenderAccess.header)  // e.g. "Unidentified-Access-Key:base64..."
}
// On 401 response:
val fallback = sealedSenderAccess.switchToFallback()
if (fallback != null) { return request(requestMessage, fallback) }
```

---

## 7. Groups V2 / Sender Key

### Files
- `api/SignalServiceMessageSender.java` -- `sendGroupMessage()` method
- `api/crypto/SignalServiceCipher.java` -- `encryptForGroup()`
- `api/groupsv2/GroupsV2Api.java` -- Group API
- `api/groupsv2/GroupSendEndorsements.kt` -- Per-member endorsements

### Group (Sender Key) Send Flow

```
1. sendGroupMessage(distributionId, recipients, ...):
   for i in 0..RETRY_COUNT:
     a. buildGroupTargetInfo() -- collect all device addresses + sessions
     b. Check which recipients need sender key distribution:
        - Filter destinations not in getSenderKeySharedWith(distributionId)
     c. If any need SKDM:
        - getOrCreateNewGroupSession(distributionId) -> SenderKeyDistributionMessage
        - sendSenderKeyDistributionMessage() to those recipients (fan-out, per-recipient encrypt)
        - markSenderKeySharedWith() on success
     d. Encrypt for group:
        cipher.encryptForGroup(distributionId, destinations, sessions, cert, content, hint, groupId)
     e. Send via MessageApi.sendGroupMessage() (multi-recipient endpoint)
     f. Handle 409 (GroupMismatchedDevicesException): handleMismatchedDevices for each UUID
     g. Handle 410 (GroupStaleDevicesException): handleStaleDevices for each UUID
```

### Group Encryption

```java
// SignalServiceCipher.encryptForGroup():
CiphertextMessage message = groupCipher.encrypt(distributionId, transport.getPaddedMessageBody(content));
UnidentifiedSenderMessageContent messageContent = new UnidentifiedSenderMessageContent(
    message, senderCertificate, contentHint, groupId);
return sessionCipher.multiRecipientEncrypt(destinations, sessionMap, messageContent);
```

### Multi-Recipient Endpoint

```
PUT /v1/messages/multi_recipient?ts={timestamp}&online={bool}&urgent={bool}&story={bool}
Content-Type: application/vnd.signal-messenger.mrm
Body: multiRecipientEncrypt output (binary)
```

### Group Send Endorsements

`GroupSendEndorsements` contains per-member `GroupSendEndorsement` objects. For multi-recipient sends, they are serialized into a `GroupSendFullToken`. For SKDM distribution (fan-out individual sends), per-recipient tokens are extracted via `forIndividuals()`.

### GroupsV2 API Endpoints

| Endpoint | Purpose |
|----------|---------|
| `GET /v2/groups/` | Fetch group details |
| `PUT /v2/groups/` | Create new group |
| `PATCH /v2/groups/` | Modify group |
| `GET /v2/groups/logs/{fromVersion}` | Group history/changes |
| `GET /v1/certificate/auth/group` | Group auth credentials (7-day batch) |

Auth uses zkgroup `AuthCredentialWithPni` -> `AuthCredentialPresentation` for group-scoped authorization.

---

## 8. Contact Sync

Contact sync is done via a sync message sent to linked devices. The primary device sends a `SyncMessage` with contacts attached. The mechanism uses the standard attachment upload/download flow.

Related classes:
- `api/messages/multidevice/SignalServiceSyncMessage.java`
- The actual contact data is serialized as a `DeviceContact` protobuf stream attachment

---

## 9. Storage Service

### Files
- `api/storage/StorageServiceApi.kt` -- API endpoints
- `api/storage/SignalStorageCipher.kt` -- AES-256-GCM encrypt/decrypt
- `api/storage/RecordIkm.kt` -- Per-item key derivation

### Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/storage/auth` | GET | Get auth credentials (username:password) |
| `/v1/storage/manifest` | GET | Get latest storage manifest |
| `/v1/storage/manifest/version/{version}` | GET | Get manifest if different from version (204 if same) |
| `/v1/storage/read` | PUT | Read specific storage items |
| `/v1/storage` | PUT | Write storage items (409 if version mismatch) |

### Storage Encryption

```kotlin
// SignalStorageCipher:
// Encrypt: IV (12 bytes random) || AES-256-GCM(key, iv, data)
// Decrypt: split IV from ciphertext, AES-256-GCM decrypt

object SignalStorageCipher {
    private const val IV_LENGTH = 12
    // encrypt(key, data) -> iv + ciphertext
    // decrypt(key, data) -> plaintext
}
```

### RecordIkm (Per-Item Key Derivation)

```kotlin
// RecordIkm: 32-byte key from ManifestRecord.recordIkm
// Derives per-item keys via HKDF:
fun deriveStorageItemKey(rawId: ByteArray): StorageItemKey {
    return StorageItemKey(Crypto.hkdf(
        inputKeyMaterial = this.value,
        info = "20240801_SIGNAL_STORAGE_SERVICE_ITEM_".toByteArray() + rawId,
        outputLength = 32
    ))
}
```

When `recordIkm` is present in the manifest, each storage item is encrypted with its own derived key. The HKDF info string is the literal prefix `20240801_SIGNAL_STORAGE_SERVICE_ITEM_` concatenated with the raw storage item ID bytes.

---

## 10. Retry and Error Handling

### File
`api/SignalServiceMessageSender.java`

### Retry Constants

```java
private static final int RETRY_COUNT = 4;
```

### Device Mismatch (409) Handling

```java
private void handleMismatchedDevices(recipient, mismatchedDevices) {
    // 1. Archive sessions for extra devices
    archiveSessions(recipient, mismatchedDevices.getExtraDevices());
    // 2. For each missing device: fetch prekey, build session
    for (int missingDeviceId : mismatchedDevices.getMissingDevices()) {
        PreKeyBundle preKey = keysApi.getPreKey(recipient, missingDeviceId);
        sessionBuilder.process(preKey);
    }
}
```

### Stale Devices (410) Handling

```java
private void handleStaleDevices(recipient, staleDevices) {
    // Simply archive sessions for stale devices (forces re-establishment on next send)
    archiveSessions(recipient, staleDevices.getStaleDevices());
}
```

### archiveSessions

Archives both by service ID and phone number (if available) for each device:

```java
private void archiveSessions(recipient, devices) {
    for (SignalProtocolAddress address : convertToProtocolAddresses(recipient, devices)) {
        aciStore.archiveSession(address);
    }
}
```

### Group Send 409/410

For multi-recipient sends, the server returns per-UUID mismatch/stale info. The handler iterates over each and calls the same `handleMismatchedDevices`/`handleStaleDevices`.

### Sealed Sender Auth Failure

On `AuthorizationFailedException` when using sealed sender:
1. Call `sealedSenderAccess.switchToFallback()`
2. If fallback available, retry with new access type
3. If no fallback, throw (propagate to caller)

### WebSocket Failure -> REST Fallback

If WebSocket send fails and `useRestFallback` is true, falls back to `PushServiceSocket` REST endpoint.

---

## 11. Device Management / Provisioning

### Files
- `api/link/LinkDeviceApi.kt` -- Primary device operations
- `api/provisioning/ProvisioningSocket.kt` -- New device WebSocket
- `api/registration/RegistrationApi.kt` -- Device registration

### Provisioning Flow (Linking a New Device)

**New device side** (`ProvisioningSocket`):

```
1. Connect WebSocket to wss://.../v1/websocket/provisioning/
2. Receive PUT /v1/address -> extract device identifier
3. Generate provisioning URL:
   sgnl://linkdevice?uuid={deviceIdentifier}&pub_key={ecPublicKey}&capabilities=backup5
4. Display QR code with URL
5. Receive PUT /v1/message -> decrypt with SecondaryProvisioningCipher
6. Extract provisioning data (identity keys, profile key, etc.)
```

Provisioning socket constants:
- LIFESPAN = 90 seconds
- Keepalive every 30 seconds (`GET /v1/keepalive`)
- Timeout for device ID: 10 seconds

**Primary device side** (`LinkDeviceApi`):

```
1. GET /v1/devices/provisioning/code -> get verification code + token
2. Scan QR code to get device identifier + public key
3. Encrypt ProvisionMessage with PrimaryProvisioningCipher:
   - ACI/PNI identity key pairs (public + private)
   - ACI, PNI, phone number
   - Provisioning code
   - Profile key
   - Master key, account entropy pool, media root backup key
4. PUT /v1/provisioning/{deviceIdentifier} -> send encrypted message
5. GET /v1/devices/wait_for_linked_device/{token} -> long-poll until complete
```

**New device registration** (`RegistrationApi`):

```
PUT /v1/devices/link
Body: RegisterAsSecondaryDeviceRequest {
    verificationCode,
    accountAttributes,
    aciSignedPreKey, pniSignedPreKey,
    aciPqLastResortPreKey, pniPqLastResortPreKey,
    gcmToken (optional)
}
```

### Device Management Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/devices` | GET | List linked devices |
| `/v1/devices/{id}` | DELETE | Remove linked device |
| `/v1/devices/provisioning/code` | GET | Get provisioning code (411 if at device limit) |
| `/v1/provisioning/{deviceIdentifier}` | PUT | Send provisioning message to new device |
| `/v1/devices/link` | PUT | Register as secondary device |
| `/v1/devices/wait_for_linked_device/{token}` | GET | Long-poll for link completion (max 30s) |
| `/v1/devices/transfer_archive` | PUT | Share backup archive with linked device |
| `/v1/devices/transfer_archive` | GET | Long-poll for primary device sync data |
| `/v1/accounts/name?deviceId={id}` | PUT | Set encrypted device name |

---

## 12. Profile Operations

### Files
- `api/profiles/ProfileApi.kt` -- API endpoints
- `api/crypto/ProfileCipher.java` -- Profile field encryption

### Profile Encryption

Uses AES-256-GCM with the 32-byte profile key. Each field is padded to a specific length before encryption.

```java
// ProfileCipher constants:
NAME_PADDED_LENGTH_1 = 53;    // names <= 53 bytes UTF-8
NAME_PADDED_LENGTH_2 = 257;   // names > 53 bytes UTF-8
ABOUT_PADDED_LENGTH_1 = 128;
ABOUT_PADDED_LENGTH_2 = 254;
ABOUT_PADDED_LENGTH_3 = 512;
EMOJI_PADDED_LENGTH = 32;
ENCRYPTION_OVERHEAD = 28;     // 12 (nonce) + 16 (GCM tag)

// encrypt(input, paddedLength):
// 1. Zero-pad input to paddedLength
// 2. Generate random 12-byte nonce
// 3. AES-256-GCM encrypt with profile key
// 4. Return nonce || ciphertext (total = paddedLength + 28 bytes)
```

### Padding Selection

```java
// Name: pick smallest bucket that fits
static int getTargetNameLength(String name) {
    return (name.getBytes(UTF_8).length <= 53) ? 53 : 257;
}

// About: pick smallest bucket that fits
static int getTargetAboutLength(String about) {
    int len = about.getBytes(UTF_8).length;
    if (len <= 128) return 128;
    else if (len < 254) return 254;
    else return 512;
}
```

### Profile Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/v1/profile` | PUT | Auth | Set versioned profile |
| `/v1/profile/{aci}/{version}/{request}?credentialType=expiringProfileKey` | GET | Auth or Unauth | Get profile + credential |
| `/v1/profile/{aci}/{version}` | GET | Auth or Unauth | Get versioned profile |
| `/v1/profile/{serviceId}` | GET | Auth or Unauth | Get unversioned profile |

Profile gets support sealed sender: try unauth first, fall back to auth on 401.

### Profile Write Fields

```kotlin
SignalServiceProfileWrite(
    version,           // profile key version
    name,              // encrypted, padded
    about,             // encrypted, padded
    aboutEmoji,        // encrypted, padded to 32
    paymentAddress,    // encrypted with length prefix
    phoneNumberSharing,// encrypted boolean
    avatar,            // boolean: has avatar
    sameAvatar,        // boolean: keep existing
    commitment,        // profile key commitment
    badgeIds           // list of visible badge IDs
)
```

### Unidentified Access Verifier

To check if someone has your profile key (for sealed sender):

```java
// ProfileCipher.verifyUnidentifiedAccess():
byte[] accessKey = UnidentifiedAccess.deriveAccessKeyFrom(profileKey);
Mac mac = Mac.getInstance("HmacSHA256");
mac.init(new SecretKeySpec(accessKey, "HmacSHA256"));
byte[] verifier = mac.doFinal(new byte[32]);
return MessageDigest.isEqual(theirVerifier, verifier);
```

---

## 13. CDSI (Contact Discovery)

### File
`api/cds/CdsApi.kt`

### Two-Step Flow

```
1. GET /v2/directory/auth -> CdsiAuthResponse { username, password }
2. CdsiV2Service.getRegisteredUsers(username, password, request, tokenSaver)
   -> libsignal-net handles CDSI protocol (Ristretto, SGX attestation, etc.)
```

### Request Structure

```kotlin
CdsiV2Service.Request(
    previousE164s,  // Set<String>: previously-looked-up numbers
    newE164s,       // Set<String>: new numbers to look up
    serviceIds,     // Map<ServiceId, ProfileKey>: existing contacts
    token           // Optional<ByteArray>: continuation token
)
```

### Response

Returns a mapping of phone numbers to ServiceId (ACI/PNI) pairs. A continuation token is saved via `tokenSaver` for incremental lookups.

### Error Handling

- `CdsiResourceExhaustedException`: Rate limited
- `CdsiInvalidTokenException`: Saved token no longer valid
- `CdsiProtocolException`: Protocol-level failure

---

## 14. HTTP Endpoints Summary

### Messages

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/messages/{destination}?story={bool}` | PUT | Send to single recipient |
| `/v1/messages/multi_recipient?ts={ts}&online={bool}&urgent={bool}&story={bool}` | PUT | Multi-recipient (sender key) |
| `/v1/messages/report/{serviceId}/{serverGuid}` | POST | Report spam |

### Keys

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v2/keys?identity={aci\|pni}` | GET | Pre-key counts |
| `/v2/keys?identity={aci\|pni}` | PUT | Upload pre-keys |
| `/v2/keys/{identifier}/{deviceSpecifier}` | GET | Fetch pre-keys |
| `/v2/keys/check` | POST | Check repeated-use keys |

### Profiles

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/profile` | PUT | Set profile |
| `/v1/profile/{aci}/{version}` | GET | Get versioned profile |
| `/v1/profile/{aci}/{version}/{request}?credentialType=expiringProfileKey` | GET | Get profile + credential |
| `/v1/profile/{serviceId}` | GET | Get unversioned profile |

### Storage

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/storage/auth` | GET | Storage auth token |
| `/v1/storage/manifest` | GET | Get manifest |
| `/v1/storage/manifest/version/{version}` | GET | Get manifest if different |
| `/v1/storage/read` | PUT | Read items |
| `/v1/storage` | PUT | Write items (409 on version conflict) |

### Devices

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/devices` | GET | List devices |
| `/v1/devices/{id}` | DELETE | Remove device |
| `/v1/devices/provisioning/code` | GET | Get provisioning code |
| `/v1/provisioning/{deviceIdentifier}` | PUT | Send provisioning message |
| `/v1/devices/link` | PUT | Register as secondary device |
| `/v1/devices/wait_for_linked_device/{token}` | GET | Wait for link completion |
| `/v1/devices/transfer_archive` | PUT | Share transfer archive |
| `/v1/devices/transfer_archive` | GET | Wait for primary data |
| `/v1/accounts/name?deviceId={id}` | PUT | Set device name |

### Account

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/accounts/whoami` | GET | Get account info |
| `/v1/accounts/attributes` | PUT | Update attributes |
| `/v1/accounts/gcm` | PUT/DELETE | FCM token |
| `/v1/accounts/registration_lock` | PUT/DELETE | Registration lock |
| `/v1/accounts/me` | DELETE | Delete account |

### Registration

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v1/verification/session` | POST | Create session |
| `/v1/verification/session/{id}` | GET | Get session status |
| `/v1/verification/session/{id}` | PATCH | Submit challenge token |
| `/v1/verification/session/{id}/code` | POST | Request SMS code |
| `/v1/verification/session/{id}/code` | PUT | Submit verification code |
| `/v1/registration` | POST | Register account |

### Contact Discovery

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v2/directory/auth` | GET | CDSI auth credentials |

### Attachments

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/v4/attachments/form/upload` | GET | Get upload form |

### Groups

| Endpoint | Purpose |
|----------|---------|
| `GET /v2/groups/` | Fetch group |
| `PUT /v2/groups/` | Create group |
| `PATCH /v2/groups/` | Modify group |
| `GET /v2/groups/logs/{fromVersion}` | Group change history |
| `GET /v1/certificate/auth/group` | Group auth credentials |

---

## 15. Attachment Handling

### File
`api/attachment/AttachmentApi.kt`

### Upload Flow (V4)

```
1. GET /v4/attachments/form/upload -> AttachmentUploadForm { cdn, key, headers, signedUploadLocation }
2. Get resumable upload URL from signedUploadLocation
3. Pad attachment with PaddingInputStream
4. Encrypt with AttachmentCipherOutputStream (AES-256-CBC + HMAC)
5. Upload encrypted data to CDN via resumable upload
6. Return AttachmentUploadResult { remoteId, cdnNumber, key, digest, ... }
```

### Attachment Padding

```kotlin
PaddingInputStream.getPaddedSize(length)
// Pads to next power-of-2-like boundary for privacy
```

### Attachment Encryption

Attachments use AES-256-CBC with HMAC-SHA256 (not GCM like profiles/storage). The key and IV are generated client-side and included in the `AttachmentPointer` protobuf shared with recipients.

### CDN Resumable Upload

```kotlin
CDN2_RESUMABLE_LINK_LIFETIME_MILLIS  // expiration for resumable upload URL
```

The resumable upload spec stores `attachmentKey`, `attachmentIv`, `cdnKey`, `cdnNumber`, `resumeLocation`, and `expirationTimestamp`, allowing upload retry across attempts.

---

## Appendix: Key Constants

| Constant | Value | Location |
|----------|-------|----------|
| `RETRY_COUNT` | 4 | `SignalServiceMessageSender.java` |
| `PADDING_BLOCK_SIZE` | 80 | `PushTransportDetails.java` |
| `DEFAULT_SEND_TIMEOUT` | 10 seconds | `WebSocketConnection.kt` |
| `NAME_PADDED_LENGTH_1` | 53 | `ProfileCipher.java` |
| `NAME_PADDED_LENGTH_2` | 257 | `ProfileCipher.java` |
| `ABOUT_PADDED_LENGTH_1` | 128 | `ProfileCipher.java` |
| `ABOUT_PADDED_LENGTH_2` | 254 | `ProfileCipher.java` |
| `ABOUT_PADDED_LENGTH_3` | 512 | `ProfileCipher.java` |
| `EMOJI_PADDED_LENGTH` | 32 | `ProfileCipher.java` |
| `ENCRYPTION_OVERHEAD` | 28 | `ProfileCipher.java` |
| `IV_LENGTH` (storage) | 12 | `SignalStorageCipher.kt` |
| `DEFAULT_DEVICE_ID` | 1 | `SignalServiceAddress` |
| Provisioning LIFESPAN | 90 seconds | `ProvisioningSocket.kt` |
| Provisioning keepalive | 30 seconds | `ProvisioningSocket.kt` |
| RecordIkm HKDF info prefix | `20240801_SIGNAL_STORAGE_SERVICE_ITEM_` | `RecordIkm.kt` |
| Provisioning URL host (link) | `linkdevice` | `ProvisioningSocket.kt` |
| Provisioning URL capabilities | `backup5` | `ProvisioningSocket.kt` |
| MRM content type | `application/vnd.signal-messenger.mrm` | `MessageApi.kt` |
