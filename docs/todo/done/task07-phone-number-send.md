# Phase 7: Support Phone Numbers as Send Recipients

## Status: Done

## Problem

The current `Send()` API only accepts ACI UUIDs as recipients. Users typically think in terms of phone numbers, not UUIDs. After syncing contacts, the local store has ACI→phone mappings, but there's no reverse lookup to find an ACI from a phone number.

## Solution

Modify `Send()` to auto-detect whether the recipient is an ACI UUID or E.164 phone number. For phone numbers, perform a reverse lookup in the contact store to resolve the ACI, then proceed with the existing send flow.

## Design Decisions

- **Auto-detect format**: Single `Send()` method detects recipient type by format (UUID pattern vs `+` prefix)
- **Strict E.164**: Phone numbers must be exact E.164 format (`+31612345678`) - no normalization of other formats
- **Local lookup first**: Resolve phone→ACI from contact store; return error if not found
- **CDSI future work**: Contact Discovery Service integration for unknown numbers is out of scope for this phase

## Implementation

### 1. Store: Add reverse lookup (`internal/store/contact.go`)

Add method to lookup contact by phone number:

```go
// GetContactByNumber returns the contact with the given E.164 phone number.
// Returns nil, nil if not found.
func (s *Store) GetContactByNumber(number string) (*Contact, error) {
    row := s.db.QueryRow("SELECT aci, number, name FROM contact WHERE number = ?", number)
    var c Contact
    err := row.Scan(&c.ACI, &c.Number, &c.Name)
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, fmt.Errorf("get contact by number: %w", err)
    }
    return &c, nil
}
```

Add index on `number` column for efficient reverse lookups (schema migration):

```sql
CREATE INDEX IF NOT EXISTS idx_contact_number ON contact(number);
```

### 2. Store: Add LookupACI helper (`internal/store/contact.go`)

```go
// LookupACI returns the ACI for the given E.164 phone number, or empty string if not found.
func (s *Store) LookupACI(number string) string {
    c, err := s.GetContactByNumber(number)
    if err != nil || c == nil {
        return ""
    }
    return c.ACI
}
```

### 3. Client: Recipient detection (`client.go`)

Add helper to detect recipient type and resolve ACI:

```go
// isE164 returns true if s looks like an E.164 phone number (+country code + number).
func isE164(s string) bool {
    if len(s) < 8 || s[0] != '+' {
        return false
    }
    for _, r := range s[1:] {
        if r < '0' || r > '9' {
            return false
        }
    }
    return true
}

// isUUID returns true if s looks like a UUID (36 chars with hyphens in standard positions).
func isUUID(s string) bool {
    if len(s) != 36 {
        return false
    }
    // Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    for i, r := range s {
        if i == 8 || i == 13 || i == 18 || i == 23 {
            if r != '-' {
                return false
            }
        } else {
            if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
                return false
            }
        }
    }
    return true
}
```

### 4. Client: Modify Send() (`client.go`)

Update `Send()` to auto-detect and resolve:

```go
// Send sends a text message to the given recipient.
// Recipient can be an ACI UUID (e.g., "550e8400-e29b-41d4-a716-446655440000")
// or an E.164 phone number (e.g., "+31612345678").
// For phone numbers, the recipient must exist in the local contact store
// (call SyncContacts first).
func (c *Client) Send(ctx context.Context, recipient string, text string) error {
    if c.store == nil {
        return fmt.Errorf("client: not linked (call Link or Load first)")
    }

    // Resolve recipient to ACI
    var aci string
    switch {
    case isUUID(recipient):
        aci = recipient
    case isE164(recipient):
        aci = c.store.LookupACI(recipient)
        if aci == "" {
            return fmt.Errorf("client: unknown phone number %s (call SyncContacts first)", recipient)
        }
    default:
        return fmt.Errorf("client: invalid recipient format %q (expected UUID or E.164 phone number)", recipient)
    }

    auth := signalservice.BasicAuth{
        Username: fmt.Sprintf("%s.%d", c.aci, c.deviceID),
        Password: c.password,
    }
    return signalservice.SendTextMessage(ctx, c.apiURL, aci, text, c.store, auth, c.tlsConfig, c.logger)
}
```

### 5. Client: Add LookupACI method (`client.go`)

Expose reverse lookup on client for callers who need it:

```go
// LookupACI returns the ACI UUID for the given E.164 phone number from the local
// contact store. Returns empty string if not found.
func (c *Client) LookupACI(number string) string {
    if c.store == nil {
        return ""
    }
    return c.store.LookupACI(number)
}
```

### 6. CLI: Update send command (`cmd/sgnl/send.go`)

The `sgnl send` command already passes the recipient to `client.Send()`. With the auto-detect change, it will automatically support phone numbers. Update help text:

```go
type sendCommand struct {
    Args struct {
        Recipient string `positional-arg-name:"recipient" required:"true" description:"ACI UUID or E.164 phone number (+31612345678)"`
        Message   string `positional-arg-name:"message" required:"true" description:"Message text to send"`
    } `positional-args:"true" required:"true"`
}
```

## Files to modify

| File | Action |
|------|--------|
| `internal/store/store.go` | Add migration for `idx_contact_number` index |
| `internal/store/contact.go` | Add `GetContactByNumber()`, `LookupACI()` |
| `internal/store/contact_test.go` | Add TDD tests for reverse lookup |
| `client.go` | Add `isE164()`, `isUUID()`, modify `Send()`, add `LookupACI()` |
| `client_test.go` | Add tests for recipient detection and resolution |
| `cmd/sgnl/send.go` | Update help text for recipient argument |

## Test plan

### Unit tests (`internal/store/contact_test.go`)

1. `TestGetContactByNumber_Found` - lookup existing contact by number
2. `TestGetContactByNumber_NotFound` - lookup non-existent number returns nil
3. `TestGetContactByNumber_MultipleContacts` - correct contact returned when multiple exist
4. `TestLookupACI_Found` - helper returns ACI string
5. `TestLookupACI_NotFound` - helper returns empty string

### Unit tests (`client_test.go`)

1. `TestIsE164_Valid` - various valid E.164 formats
2. `TestIsE164_Invalid` - missing +, letters, too short
3. `TestIsUUID_Valid` - standard UUID format
4. `TestIsUUID_Invalid` - wrong length, wrong separators
5. `TestSend_ResolvePhoneNumber` - phone number resolved via contact store
6. `TestSend_ResolveUUID` - UUID passed through directly
7. `TestSend_UnknownPhoneNumber` - error for unknown number
8. `TestSend_InvalidFormat` - error for invalid recipient format

### Integration test

1. Link device, sync contacts, send message by phone number, verify delivery

## Usage

```bash
# Sync contacts first (required for phone number lookup)
sgnl sync-contacts

# Send by phone number
sgnl send "+31612345678" "Hello from signal-go"

# Send by ACI UUID (still works)
sgnl send "550e8400-e29b-41d4-a716-446655440000" "Hello"
```

```go
// Go API usage
client, _ := signal.Load(ctx, "/path/to/store.db")
client.SyncContacts(ctx)

// Wait for contact sync to complete (via Receive loop)

// Send by phone number
err := client.Send(ctx, "+31612345678", "Hello!")

// Or by ACI
err := client.Send(ctx, "550e8400-e29b-41d4-a716-446655440000", "Hello!")
```

## Future work

### CDSI integration (Phase 8 candidate)

Contact Discovery Service to resolve unknown phone numbers to ACIs without requiring contact sync. This enables sending to any Signal user by phone number, even if they're not in your contacts.

**Implementation approach**: Extend CGO bindings to expose `libsignal-net` CDSI functions.

**Required components:**

1. **Rust async runtime bridge** (`internal/libsignal/`)
   - Initialize tokio runtime for async libsignal-net operations
   - Bridge Go context cancellation to Rust futures

2. **ConnectionManager bindings** (`internal/libsignal/net.go`)
   - `NewConnectionManager(env)` — create manager with Signal environment (production/staging)
   - Configure DNS resolver, transport connector, user agent
   - Handle proxy configuration if needed

3. **CDSI auth endpoint** (`internal/signalservice/httpclient.go`)
   - `GetCdsiAuth()` — fetch CDSI-specific credentials from `/v2/directory/auth`
   - Returns username/password for CDSI service (different from message API auth)

4. **CDSI lookup bindings** (`internal/libsignal/cdsi.go`)
   - `NewLookupRequest()` — create request with E.164 numbers to look up
   - `CdsiLookup(connMgr, auth, request)` — perform SGX enclave lookup
   - Parse `FfiCdsiLookupResponse` into Go structs (ACI, PNI per number)
   - Handle rate limiting (`RetryLater`), token management

5. **Client integration** (`client.go`)
   - Lazy-init ConnectionManager on first CDSI call
   - Cache CDSI auth credentials (short-lived)
   - `ResolveNumber(number) (aci string, err error)` — CDSI lookup with local cache fallback
   - Update `Send()` to use CDSI when local lookup fails

**Key files in libsignal:**
- `rust/bridge/shared/types/src/net/cdsi.rs` — bridge types
- `rust/bridge/shared/types/src/ffi/convert.rs` — FFI conversions for `FfiCdsiLookupResponse`
- `rust/net/src/cdsi.rs` — core CDSI client implementation

**Challenges:**
- Tokio runtime lifecycle management across CGO boundary
- Async/await bridging (Rust futures → Go channels or blocking calls)
- SGX attestation is handled by libsignal internally, but errors need proper Go mapping

### Other future work

- **Phone number normalization**: Accept flexible formats (national, with spaces/dashes) and normalize to E.164
- **Batch send**: Send to multiple recipients in one call
