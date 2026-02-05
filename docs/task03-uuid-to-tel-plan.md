# Phase 3: UUID (ACI) to Telephone Number Lookup with Caching

## Status: Complete

## Problem

Received messages show raw ACI UUIDs as sender identifiers. Users want to see phone numbers and names instead.

## Solution

Request contact sync from primary device, parse the contact stream, cache ACI→number/name mappings in SQLite, and populate `SenderNumber`/`SenderName` on received messages.

## Implementation

### Contact store (`internal/store/contact.go`)

Added `contact` table to SQLite schema with ACI (primary key), number, and name columns. CRUD methods:

- `SaveContact(c *Contact)` — upsert single contact
- `GetContactByACI(aci string) (*Contact, error)` — lookup by ACI, returns nil if not found
- `SaveContacts(contacts []*Contact)` — bulk upsert in a transaction

### Message fields (`internal/signalservice/receiver.go`)

Added fields to `Message` struct:
- `SenderNumber` — sender phone number (from contact cache)
- `SenderName` — sender display name (from contact cache)
- `SyncToNumber` — recipient phone number for SyncMessage.Sent

After decryption, `populateContactInfo()` looks up sender/recipient ACIs in the contact table.

### Attachment download + decryption (`internal/signalservice/attachment.go`)

- `DecryptAttachment(data, key []byte)` — AES-CBC decrypt with HMAC-SHA256 verification and PKCS7 unpadding
- `DownloadAttachment(ctx, ptr, tlsConf)` — CDN download (cdn.signal.org / cdn2.signal.org) + decryption
- Key format: 64 bytes = 32 AES key + 32 HMAC key
- Data format: IV (16 bytes) || AES-CBC ciphertext || HMAC-SHA256 (32 bytes)

### Contact sync (`internal/signalservice/contactsync.go`)

- `ParseContactStream(data []byte) ([]*proto.ContactDetails, error)` — parses varint-length-prefixed protobuf stream, skips inline avatar bytes
- `RequestContactSync(ctx, apiURL, store, auth, localACI, tlsConf, logger)` — encrypts `SyncMessage.Request{Type:CONTACTS}` to self (device 1) and sends via PUT /v1/messages/{aci}

### Receiver integration (`internal/signalservice/receiver.go`)

When `handleEnvelope` sees `SyncMessage.Contacts`:
1. Downloads the attachment blob from CDN
2. Decrypts with the key from `AttachmentPointer`
3. Parses the contact stream
4. Saves all contacts with ACIs to the store
5. Returns nil (not a user-visible message)

### Public API (`client.go`)

- `SyncContacts(ctx) error` — requests contact sync from primary device
- `LookupNumber(aci string) string` — returns phone number for ACI or empty string

### CLI (`cmd/sgnl/`)

- `sgnl sync-contacts` — requests contact sync from primary device
- `sgnl receive` — displays `Name (Number)` or `Number` or ACI UUID (best available)

## Files created/modified

| File | Action |
|---|---|
| `internal/store/store.go` | Added `contact` table to schema |
| `internal/store/contact.go` | New: Contact struct + CRUD methods |
| `internal/store/contact_test.go` | New: TDD tests for contact store |
| `internal/signalservice/receiver.go` | Added Message fields, contact lookup, SyncMessage.Contacts handling |
| `internal/signalservice/attachment.go` | New: CDN download + AES-CBC decryption |
| `internal/signalservice/attachment_test.go` | New: TDD tests for attachment decryption |
| `internal/signalservice/contactsync.go` | New: ParseContactStream, RequestContactSync |
| `internal/signalservice/contactsync_test.go` | New: TDD tests for contact stream parsing |
| `client.go` | Added SyncContacts(), LookupNumber() |
| `cmd/sgnl/synccontacts.go` | New: sync-contacts subcommand |
| `cmd/sgnl/main.go` | Registered sync-contacts command |
| `cmd/sgnl/receive.go` | Display name/number instead of raw UUID |

## Usage

```bash
# Request contact sync from primary device
sgnl sync-contacts

# Then receive messages (will process the sync response and display contacts)
sgnl receive
```

## Future work

- **Auto-sync**: Trigger contact sync automatically on first `Load()` if contact table is empty
- **CDSI**: Contact Discovery Service for reverse lookups of unknown senders not in contacts
