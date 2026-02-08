# Task 19: Decompose Service God Object

## Status: TODO

## Problem

`Service` struct in `internal/signalservice/` handles at least 8 distinct concerns:
transport, auth, messages, groups, sync, attachments, storage, profiles, and keys.

All code depends on a single `*store.Store` (concrete SQLite), making unit testing
impossible without a real database. Similarly, the receiver depends on concrete
`*signalws.PersistentConn`, making the receive loop untestable without a real WebSocket.

## Key Design Insight: Separate Crypto Passthrough from Business Data

A naive `ServiceStore` interface that embeds all 6 libsignal store interfaces plus
business methods yields 20+ methods — too large.

The root cause: Signal crypto operations (decrypt, encrypt, process pre-key bundles)
require all 6 libsignal store interfaces simultaneously. For example:

```go
libsignal.DecryptPreKeyMessage(msg, addr, sessionStore, identityStore, preKeyStore, signedPreKeyStore, kyberPreKeyStore)
```

**Solution**: Don't embed crypto stores in business interfaces. Instead, treat the
crypto store as an opaque passthrough — components hold it as a single value and
pass it to libsignal calls, but don't call its methods directly. Business interfaces
stay small:

```go
// Small business interface — only methods the receiver calls directly
type receiverDataStore interface {
    GetContactByACI(string) (*store.Contact, error)
    SaveContact(*store.Contact) error
    SaveContacts([]*store.Contact) error
    LoadAccount() (*store.Account, error)
    GetGroup(string) (*store.Group, error)
    SaveGroup(*store.Group) error
}

// Crypto passthrough — passed to libsignal functions, not called by Go code
type cryptoStore interface {
    libsignal.SessionStore
    libsignal.IdentityKeyStore
    libsignal.PreKeyStore
    libsignal.SignedPreKeyStore
    libsignal.KyberPreKeyStore
    libsignal.SenderKeyStore
}
```

The Receiver holds both: `dataStore receiverDataStore` for business logic, and
`cryptoStore cryptoStore` for passing through to libsignal. `*store.Store` satisfies
both, but tests can mock each independently.

## Decomposition Plan

### Phase 1: Extract `internal/signalcrypto/` (stateless crypto)

Move pure crypto utilities with NO Service/store dependencies:

- `profilecipher.go` — Profile encryption/decryption (AES-GCM)
- `storagecrypto.go` — Storage Service decryption (AES-256-GCM)
- `storagekeys.go` — Storage Service key derivation (HMAC/HKDF)
- `DeriveAccessKey` from `accesskey.go` — Access key derivation (AES-GCM)
- `DecryptAttachment` + `AttachmentURL` from `attachment.go` — Attachment crypto

### Phase 2: Change `Store.PNI()` return type

Change from `*PNIIdentityStore` to `libsignal.IdentityKeyStore` (all callers
already assign to the interface type).

### Phase 3: Extract Receiver type

New `Receiver` struct with:
- `dataStore receiverDataStore` — small business interface (~6 methods)
- `cryptoStore cryptoStore` — opaque passthrough for libsignal calls
- `wsConn` interface — `ReadMessage`, `SendResponse`, `Close`
- Callback functions for cross-boundary operations (retry receipts, group details, profiles)

### Phase 4: Extract Sender type

New `Sender` struct with:
- `dataStore senderDataStore` — small business interface (LoadAccount, ArchiveSession, GetDevices, SetDevices, GetContactByACI, GetPNIIdentityKeyPair)
- `cryptoStore` — SessionStore + IdentityKeyStore passthrough for encrypt calls

### Phase 5: Extract GroupSender (extends Sender)

Adds group-specific data methods (GetGroup, SaveGroup, GetSenderKeySharedWith,
MarkSenderKeySharedWith) plus SenderKeyStore for group crypto.

### Phase 6: Slim Service to coordinator

Service becomes a thin facade that creates Receiver/Sender/GroupSender and
delegates. Its own store interface covers only remaining methods (RefreshPreKeys,
SyncGroupsFromStorage, etc.).

## Store Methods Used by Service (Complete Inventory)

### Called directly by Go code (business methods):
- `LoadAccount` — sender, groupsender, groupsv2, storage (5 call sites)
- `GetDevices` / `SetDevices` — deviceretry, groupsender, retryreceipt
- `ArchiveSession` — deviceretry, retryreceipt
- `GetGroup` / `SaveGroup` / `GetAllGroups` / `DeleteGroup` — groupsender, groupsv2, storage, receiver
- `SaveContact` / `GetContactByACI` / `SaveContacts` — groupsv2, receiver, accesskey
- `GetSenderKeySharedWith` / `MarkSenderKeySharedWith` — groupsender
- `GetIdentityKeyPair` / `GetPNIIdentityKeyPair` — sender (PNI signature)
- `LoadSignedPreKey` / `LoadKyberPreKey` — service (pre-key upload)
- `LoadSession` — sender, groupsender, retryreceipt (session existence check)
- `PNI()` — receiver (PNI-addressed message decryption)

### Passed through to libsignal FFI (crypto passthrough):
- SessionStore — Encrypt, ProcessPreKeyBundle, Decrypt*
- IdentityKeyStore — Encrypt, ProcessPreKeyBundle, SealedSenderEncrypt, Decrypt*
- PreKeyStore — DecryptPreKeyMessage
- SignedPreKeyStore — DecryptPreKeyMessage
- KyberPreKeyStore — DecryptPreKeyMessage
- SenderKeyStore — GroupEncryptMessage, GroupDecryptMessage, CreateSKDM, ProcessSKDM

## WebSocket Methods Used by Receiver

Only 3 methods (already minimal):
- `ReadMessage(ctx) (*proto.WebSocketMessage, error)`
- `SendResponse(ctx, id, status, message) error`
- `Close() error`

## Benefits

- Crypto functions become independently testable without SQLite
- Receiver testable with mock WebSocket and mock data store
- Sender testable with mock data store and mock transport
- Small, focused interfaces (6-7 methods each) instead of one 20+ method interface
- Clearer dependency graph

## Related

- Task 18 (`docs/todo/task18-service-store-interface.md`): Decouple Service from concrete `*store.Store`
