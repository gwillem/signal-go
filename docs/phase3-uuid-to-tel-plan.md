# Phase 3: UUID (ACI) to Telephone Number Lookup with Caching

## Status: Planning

## Problem

Received messages show raw ACI UUIDs as sender identifiers. Users want to see phone numbers instead.

## Research Findings

### Signal has no direct ACI-to-phone API

There are two mechanisms for resolving identities:

1. **Contact Discovery Service (CDSI)**: Works in the opposite direction (phone numbers → ACIs). Requires SGX attestation — too complex and wrong direction for this use case.

2. **Contact Sync via SyncMessage**: The primary device sends a stream of `ContactDetails` protobuf messages (defined in `SignalService.proto`), each containing both `aci` and `number` fields. A linked device requests this by sending a `SyncMessage.Request` with `type = CONTACTS`.

Contact sync is the correct mechanism. The proto definitions already exist:

```protobuf
message ContactDetails {
    optional string number = 1;
    optional string aci = 9;
    optional bytes aciBinary = 13;
    optional string name = 2;
}

message SyncMessage {
    message Request {
        enum Type {
            CONTACTS = 1;
        }
        optional Type type = 1;
    }
}
```

### Existing infrastructure

- **SQLite store** (`internal/store/store.go`): Schema-in-code with `CREATE TABLE IF NOT EXISTS`. Adding a new table follows the same pattern.
- **HTTP client** (`internal/signalservice/httpclient.go`): Authenticated REST methods via `HTTPClient`.
- **Message sending** (`internal/signalservice/sender.go`): Pattern for building + encrypting + sending `Content` protobufs already exists.
- **WebSocket receiver** (`internal/signalservice/receiver.go`): Handles incoming messages, already parses `SyncMessage`.

## Implementation Plan

### Approach: Two-tier strategy

- **Tier 1 (MVP)**: Add a `contact` SQLite table. Request contact sync from primary device, parse the `ContactDetails` stream, cache ACI→number mappings. Populate `SenderNumber` on received messages.
- **Tier 2 (future)**: CDSI for reverse lookups of unknown senders not in contacts.

### Step 1: Add `contact` table to the SQLite store

**File**: `internal/store/store.go`

Add to the schema:

```sql
CREATE TABLE IF NOT EXISTS contact (
    aci TEXT PRIMARY KEY,
    number TEXT NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
);
```

### Step 2: Add contact CRUD methods

**New file**: `internal/store/contact.go`

```go
type Contact struct {
    ACI       string
    Number    string
    Name      string
    UpdatedAt int64
}

func (s *Store) SaveContact(c *Contact) error
func (s *Store) GetContactByACI(aci string) (*Contact, error)  // returns nil, nil if not found
func (s *Store) GetAllContacts() ([]*Contact, error)
func (s *Store) SaveContacts(contacts []*Contact) error         // bulk upsert in a transaction
```

**Test file**: `internal/store/contact_test.go` (TDD first).

### Step 3: Add `SenderNumber` field to Message

**File**: `internal/signalservice/receiver.go`

```go
type Message struct {
    Sender       string    // sender ACI UUID
    SenderNumber string    // sender phone number (if known from contact cache)
    Device       uint32
    Timestamp    time.Time
    Body         string
    SyncTo       string
    SyncToNumber string    // recipient phone number (if known)
}
```

After decrypting a message in `handleEnvelope`, look up the sender ACI in the store's contact table and populate `SenderNumber`. Same for `SyncTo` → `SyncToNumber`. The store is already passed to `handleEnvelope`.

### Step 4: Send a contact sync request

**New file**: `internal/signalservice/contactsync.go`

```go
func RequestContactSync(ctx context.Context, apiURL string, st *store.Store, auth BasicAuth, tlsConf *tls.Config) error
```

Builds a `Content` protobuf with `SyncMessage.Request{Type: CONTACTS}`, encrypts it to self (own ACI, device 1), and sends via HTTP PUT `/v1/messages/{aci}`. The sending pattern already exists in `sender.go`.

### Step 5: Handle incoming contact sync response in receiver

**File**: `internal/signalservice/receiver.go`

When `handleEnvelope` detects a `SyncMessage.Contacts` message:

1. The `Contacts` field contains an `AttachmentPointer` blob.
2. Download the attachment using the CDN URL from the pointer.
3. Decrypt the attachment (AES-256-CTR with HMAC, using the key from the pointer).
4. Parse the decrypted data as a stream of varint-prefixed `ContactDetails` protobuf messages.
5. For each contact with both `aci` and `number`, save to the `contact` table.

**New helper** in `internal/signalservice/httpclient.go`:

```go
func (c *HTTPClient) DownloadAttachment(ctx context.Context, cdnURL string) ([]byte, error)
```

### Step 6: Add public API to Client

**File**: `client.go`

```go
// SyncContacts requests the primary device to send its contact list.
// Contacts are stored locally and used to resolve ACI UUIDs to phone numbers.
func (c *Client) SyncContacts(ctx context.Context) error

// LookupNumber returns the phone number for a given ACI UUID,
// or empty string if not known.
func (c *Client) LookupNumber(aci string) string
```

### Step 7: Update the CLI

**File**: `cmd/sig/main.go`

1. Add a `sync-contacts` subcommand that calls `c.SyncContacts(ctx)`.
2. In the `receive` command, display `msg.SenderNumber` when available, falling back to `msg.Sender`.
3. Optionally: in `send`, accept a phone number and resolve it to ACI via reverse lookup.

### Step 8 (optional): Auto-sync on first load

In `Client.Load()`, check if the contact table is empty and automatically trigger a contact sync. This ensures the cache is populated without a separate command.

## Implementation order

1. `internal/store/contact.go` + `contact_test.go` — contact table and CRUD (TDD)
2. `internal/signalservice/receiver.go` — add `SenderNumber`/`SyncToNumber` fields, populate from cache
3. `internal/signalservice/contactsync.go` — send `SyncMessage.Request(CONTACTS)`
4. `internal/signalservice/receiver.go` — handle `SyncMessage.Contacts` response (attachment download + parse)
5. `client.go` — add `SyncContacts()` and `LookupNumber()` public API
6. `cmd/sig/main.go` — add `sync-contacts` command, update receive display

## Challenges

- **Attachment download and decryption**: Contacts arrive as an encrypted attachment. Need CDN download + AES-256-CTR decryption + HMAC verification. Key material is in the `AttachmentPointer` proto fields.
- **Contact stream parsing**: The decrypted blob is a concatenation of varint-prefixed `ContactDetails` messages. Requires a streaming protobuf parser.
- **Async response timing**: After requesting sync, the response arrives asynchronously via WebSocket. `SyncContacts` should either open a temporary receive loop waiting for the response, or document that the user should call `Receive` after requesting sync.

## Key reference files

| File | Relevance |
|---|---|
| `internal/signalservice/sender.go` | Pattern for encrypting + sending Content protobufs |
| `internal/signalservice/receiver.go` | Where to handle SyncMessage.Contacts and populate SenderNumber |
| `internal/signalservice/httpclient.go` | Add CDN attachment download |
| `internal/store/store.go` | Add contact table to schema |
| `internal/proto/SignalService.proto` | ContactDetails and SyncMessage.Request definitions |
| `../Signal-Android/lib/libsignal-service/` | Reference implementation for contact sync flow |
