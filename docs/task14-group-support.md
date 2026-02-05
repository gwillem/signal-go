# Task 14: Full Group Support (Storage Service + Groups V2)

## Status: In Progress (Group Sending Implemented)

## Goal

Enable signal-go to:
1. Discover group memberships (sync from primary device)
2. Fetch group details (name, members, avatar)
3. Send messages to groups
4. Receive group messages (already done in task 13)

## Background

Signal groups (V2) use a complex architecture:

1. **Storage Service** - Encrypted key-value store that syncs account data across devices, including group master keys
2. **Groups V2 API** - Server-side group state (members, name, permissions) accessed via zero-knowledge credentials
3. **zkgroup** - Cryptographic library for zero-knowledge proofs that prove group membership without revealing identity

### Current State

| Feature | Status |
|---------|--------|
| Receive sender key messages (type 7) | Done (task 13) |
| Process sender key distribution | Done (task 13) |
| zkgroup bindings | **Done** (GroupMasterKey, GroupSecretParams, GroupPublicParams, GroupIdentifier) |
| Group storage (SQLite) | **Done** (master key, name, revision) |
| Extract group info from received messages | **Done** (populateGroupInfo in receiver.go, auto-fetches name on first message) |
| Public API (Groups, GetGroup, SyncGroups) | **Done** |
| Storage Service sync | **Done** (Phase 1 complete, uses RecordIkm key derivation) |
| CLI `sgnl groups` command | **Done** (list groups, --sync flag, --fetch flag) |
| Groups V2 API (fetch group details) | **Done** (Phase 3 complete) |
| Send to groups | **Done** (Phase 4 complete, uses sealed sender v1) |
| CLI `sgnl send-group` command | **Done** |

### Implemented Files

- `internal/libsignal/zkgroup.go` - CGO bindings for zkgroup operations
- `internal/libsignal/zkgroup_test.go` - Tests for zkgroup bindings
- `internal/store/group.go` - SQLite group storage (SaveGroup, GetGroup, GetAllGroups)
- `internal/signalservice/receiver.go` - populateGroupInfo() extracts and stores group info from messages
- `internal/signalservice/storagekeys.go` - Storage key derivation (StorageKey, ManifestKey, ItemKey)
- `internal/signalservice/storagecrypto.go` - AES-256-GCM decryption for storage records
- `internal/signalservice/storage.go` - Storage Service client (SyncGroupsFromStorage)
- `internal/proto/StorageService.proto` - Storage Service protobuf definitions
- `client.go` - Groups(), GetGroup(), SyncGroups(), FetchGroupDetails() public API methods
- `cmd/sgnl/groups.go` - CLI command for listing, syncing, and fetching groups
- `internal/libsignal/authcredential.go` - ServerPublicParams, auth credential presentation
- `internal/signalservice/groupsv2.go` - Groups V2 API client for fetching group details
- `internal/signalservice/groupsender.go` - Group message sending with sender keys
- `internal/proto/Groups.proto` - Groups V2 protobuf definitions
- `cmd/sgnl/sendgroup.go` - CLI command for sending group messages

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Primary Device                            │
│  (iPhone/Android - has all group master keys)                   │
└─────────────────────┬───────────────────────────────────────────┘
                      │ SyncMessage.Keys (master key / entropy pool)
                      │ Storage Service manifest + records
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Storage Service                              │
│  storage.signal.org - encrypted key-value store                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ StorageManifest (version, list of record IDs)               ││
│  │ StorageRecords:                                             ││
│  │   - ContactRecord (ACI, profile key, identity key)          ││
│  │   - GroupV2Record (master key, blocked, archived)           ││
│  │   - AccountRecord (profile, settings, pinned chats)         ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────┬───────────────────────────────────────────┘
                      │ Decrypt with storage key (derived from master/entropy)
                      ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Groups V2 API                                │
│  chat.signal.org/v2/groups/                                     │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ GET /v2/groups/ - fetch group state                         ││
│  │ GET /v2/groups/logs/{fromVersion} - fetch change history    ││
│  │ PUT /v2/groups/ - apply group changes                       ││
│  │ Authorization: zkgroup auth credential presentation         ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Phases

### Phase 1: Storage Service Sync

**Goal**: Retrieve group master keys from Storage Service

#### 1.1 Storage Key Derivation

The storage encryption key is derived from either:
- `SyncMessage.Keys.master` (legacy, 32 bytes)
- `SyncMessage.Keys.accountEntropyPool` (newer, base64 string)

```go
// Derive storage key from master key
storageKey := hkdf.Expand(sha256, masterKey, "Storage Service Encryption", 32)
```

#### 1.2 Storage Service Client

Endpoints (storage.signal.org):
- `GET /v1/storage/manifest` - Get current manifest
- `GET /v1/storage/manifest/version/{version}` - Get manifest if newer than version
- `PUT /v1/storage/read` - Read specific records by key
- `PUT /v1/storage` - Write records (not needed for read-only sync)

Auth: Uses same credentials as chat.signal.org but different host.

#### 1.3 Record Decryption

Storage records are encrypted with AES-GCM:
```
key = HKDF(storageKey, recordKey, "Manifest Record")
plaintext = AES-GCM-Decrypt(key, ciphertext)
```

#### 1.4 Group Discovery

Parse `GroupV2Record` from decrypted storage records:
```protobuf
message GroupV2Record {
  bytes masterKey = 1;           // 32-byte group master key
  bool blocked = 2;
  bool whitelisted = 3;
  bool archived = 4;
  bool markedUnread = 5;
  uint64 mutedUntilTimestamp = 6;
  // ...
}
```

**Files to create:**
- `internal/signalservice/storage.go` - Storage Service client
- `internal/signalservice/storagekeys.go` - Key derivation
- `internal/store/group.go` - Group storage (master keys, cached state)

### Phase 2: zkgroup Bindings

**Goal**: Wrap libsignal's zkgroup FFI for group crypto operations

#### 2.1 Core Types

```go
// GroupMasterKey is a 32-byte key that identifies a group
type GroupMasterKey [32]byte

// GroupSecretParams derived from master key, used for all group crypto
type GroupSecretParams [639]byte  // SignalGROUP_SECRET_PARAMS_LEN

// GroupPublicParams public portion, sent to server
type GroupPublicParams [289]byte  // SignalGROUP_PUBLIC_PARAMS_LEN

// GroupIdentifier 32-byte hash derived from public params
type GroupIdentifier [32]byte
```

#### 2.2 FFI Functions to Wrap

```c
// Derive secret params from master key
signal_group_secret_params_derive_from_master_key(out, master_key)

// Get public params for server requests
signal_group_secret_params_get_public_params(out, secret_params)

// Get group identifier (for matching received messages)
signal_group_public_params_get_group_identifier(out, public_params)

// Decrypt group data (member list, name, etc.)
signal_group_secret_params_decrypt_blob_with_padding(out, params, ciphertext)
signal_group_secret_params_decrypt_service_id(out, params, ciphertext)
signal_group_secret_params_decrypt_profile_key(out, params, ciphertext, user_id)
```

#### 2.3 Auth Credentials

Groups V2 API requires zero-knowledge auth credentials:

1. Fetch credentials from `/v1/certificate/auth/group` (7 days of credentials)
2. Create presentation using `signal_server_public_params_create_auth_credential_with_pni_presentation_deterministic`
3. Include presentation in Authorization header for groups API calls

**Files to create:**
- `internal/libsignal/zkgroup.go` - GroupSecretParams, GroupPublicParams, GroupIdentifier
- `internal/libsignal/authcredential.go` - Auth credential presentation
- `internal/signalservice/groupauth.go` - Credential fetching and caching

### Phase 3: Groups V2 API

**Goal**: Fetch group details from server

#### 3.1 API Client

```go
type GroupsV2Client struct {
    transport *Transport
    auth      *GroupAuthCredentials
}

// GetGroup fetches current group state
func (c *GroupsV2Client) GetGroup(ctx context.Context, secretParams GroupSecretParams) (*DecryptedGroup, error)

// GetGroupHistory fetches changes since a revision
func (c *GroupsV2Client) GetGroupHistory(ctx context.Context, secretParams GroupSecretParams, fromRevision int) ([]DecryptedGroupChange, error)
```

#### 3.2 Group State Decryption

Server returns encrypted group state:
```protobuf
message Group {
  bytes publicKey = 1;
  bytes title = 2;              // encrypted
  bytes avatar = 3;
  bytes disappearingMessagesTimer = 4;  // encrypted
  bytes accessControl = 5;
  uint32 revision = 6;
  repeated Member members = 7;  // member UUIDs encrypted
  // ...
}
```

Decrypt using `GroupSecretParams`:
```go
title := groupSecretParams.DecryptBlob(group.Title)
for _, member := range group.Members {
    aci := groupSecretParams.DecryptServiceId(member.UserId)
}
```

**Files to create:**
- `internal/signalservice/groupsv2.go` - Groups V2 API client
- `internal/proto/Groups.proto` - Group protobuf definitions (copy from Signal-Android)

### Phase 4: Send to Groups

**Goal**: Send messages to all group members

#### 4.1 Sender Key Distribution

Before sending, distribute sender key to all members:
```go
// Create distribution message
skdm := libsignal.CreateSenderKeyDistributionMessage(localAddress, distributionId, senderKeyStore)

// Send to each member via regular encrypted message
for _, member := range group.Members {
    content := &proto.Content{
        SenderKeyDistributionMessage: skdm.Serialize(),
    }
    sendEncryptedMessage(member, content)
}
```

#### 4.2 Group Message Send

```go
// Encrypt once with sender key
ciphertext := libsignal.GroupEncryptMessage(plaintext, localAddress, distributionId, senderKeyStore)

// Send to all members
for _, member := range group.Members {
    sendSenderKeyMessage(member, ciphertext, groupContext)
}
```

#### 4.3 GroupContextV2

Include in DataMessage:
```protobuf
message GroupContextV2 {
  bytes masterKey = 1;
  uint32 revision = 2;
  bytes groupChange = 3;  // optional, for group updates
}
```

**Files to modify:**
- `internal/signalservice/sender.go` - Add SendGroupMessage
- `internal/libsignal/senderkey.go` - Add CreateSenderKeyDistributionMessage, GroupEncryptMessage

### Phase 5: Public API

**Goal**: Expose group functionality in Client

```go
// List groups this device knows about
func (c *Client) Groups(ctx context.Context) ([]Group, error)

// Get group details
func (c *Client) GetGroup(ctx context.Context, groupID GroupIdentifier) (*GroupDetails, error)

// Send to group
func (c *Client) SendGroup(ctx context.Context, groupID GroupIdentifier, body string) error

// Sync groups from primary device (triggers storage service sync)
func (c *Client) SyncGroups(ctx context.Context) error
```

## Data Flow: Receiving Group Message

```
1. Receive UNIDENTIFIED_SENDER envelope
2. Decrypt outer layer → sender ACI, inner message type 7
3. GroupDecryptMessage(innerContent, senderAddr, senderKeyStore) → plaintext
4. Parse Content protobuf
5. Extract DataMessage.GroupV2.masterKey
6. Derive GroupIdentifier from masterKey
7. Look up group name from local cache (or fetch from server)
8. Return Message{Body, GroupID, GroupName, Sender, ...}
```

## Data Flow: Sending Group Message

```
1. Client.SendGroup(ctx, groupID, "Hello group!")
2. Look up group master key from store
3. Derive GroupSecretParams
4. Fetch group state (members) from cache or server
5. For each member without sender key:
   a. Create SenderKeyDistributionMessage
   b. Send via regular encrypted message
6. GroupEncryptMessage(plaintext, localAddr, distributionId, store)
7. For each member:
   a. Create sealed sender envelope
   b. PUT /v1/messages/{member}
```

## Dependencies

New dependencies:
- None (zkgroup is in libsignal FFI)

Existing:
- `golang.org/x/crypto` - HKDF for storage key derivation (already used)

## Testing Strategy

1. **Unit tests** for zkgroup bindings (key derivation, encryption/decryption)
2. **Unit tests** for storage record decryption (with test vectors)
3. **Integration test** for storage service sync (requires linked device)
4. **Integration test** for group message send/receive

## Estimated Effort

| Phase | Scope | Files |
|-------|-------|-------|
| Phase 1 | Storage Service | 3 new + 1 modified |
| Phase 2 | zkgroup bindings | 3 new |
| Phase 3 | Groups V2 API | 2 new + 1 proto |
| Phase 4 | Send to groups | 2 modified |
| Phase 5 | Public API | 1 modified |

Total: ~11 files, significant complexity due to zkgroup crypto.

## Signal-Android Reference

| Component | Location |
|-----------|----------|
| Storage Service | `app/src/main/java/org/thoughtcrime/securesms/storage/` |
| Groups V2 Operations | `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/groupsv2/` |
| Group Database | `app/src/main/java/org/thoughtcrime/securesms/database/GroupTable.java` |
| Group Send | `app/src/main/java/org/thoughtcrime/securesms/messages/GroupSendUtil.java` |

## Sealed Sender v1 vs v2

Signal uses two versions of sealed sender encryption:

| Version | Use Case | Method | Wire Format |
|---------|----------|--------|-------------|
| **v1** | 1:1 direct messages | Single-recipient KEM | Protobuf (`0x11` version byte) |
| **v2** | Group messages | Multi-recipient KEM | Flat binary (`0x22`/`0x23` version byte) |

### Version Selection

The version is determined by the encryption method called:
- `sealed_sender_encrypt()` → v1 (single recipient)
- `sealed_sender_multi_recipient_encrypt()` → v2 (multiple recipients)

### Key Differences

| Aspect | v1 | v2 |
|--------|-----|-----|
| Symmetric cipher | AES-256-CTR + HMAC-SHA256 | AES-256-GCM-SIV |
| Key derivation | Per-recipient DH | Single ephemeral, per-recipient XOR |
| Encryption | Re-encrypt for each recipient | Encrypt once, share with all |
| Efficiency | O(n) encryptions | O(1) encryption + O(n) key material |

### Current signal-go Status

**Receiving (both v1 and v2)**: ✅ Already supported. libsignal's `sealed_sender_decrypt` detects the version byte and routes automatically. No changes needed.

**Sending 1:1 (v1)**: ✅ Already supported via `SealedSenderEncrypt()` in `sealedsender.go`.

**Sending groups (v2)**: ❌ Not yet implemented. Requires:
1. CGO binding for `signal_sealed_sender_multi_recipient_encrypt`
2. Building recipient list with sessions from database
3. Server splits multi-recipient message and delivers to each recipient

### Implementation Note for Phase 4

When implementing group send, the choice is:

1. **Use v2 (recommended)**: More efficient, matches Signal-Android behavior. Requires new CGO binding.
2. **Use v1 per-recipient**: Simpler, works with existing code. Less efficient but functional.

Signal-Android uses v2 for all group messages via `encryptForGroup()` in `SignalServiceCipher.java`.

## Alternative: Simpler Group Send

If full Storage Service sync is too complex, a simpler approach:

1. **Log group master keys** from received group messages (`DataMessage.GroupV2.masterKey`)
2. **Store locally** - build group knowledge incrementally
3. **Send to known groups** - use logged master keys

This avoids Storage Service and auth credentials but only works for groups where you've received messages.
