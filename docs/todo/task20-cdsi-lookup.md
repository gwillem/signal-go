# Task 20: CDSI Phone Number Lookup

## Problem

Currently, resolving phone numbers to ACI UUIDs requires a full contact sync from the primary device. This means we can only message people already in our contact list. Signal's Contact Discovery Service (CDSI) allows looking up any phone number to find its ACI/PNI, enabling sending to arbitrary Signal users by phone number.

## Background

CDSI runs inside an SGX enclave for privacy. The client authenticates with dedicated CDSI credentials (separate from message API auth), sends E.164 numbers into the enclave, and receives back ACI/PNI mappings. libsignal already implements the full CDSI client in `rust/net/src/cdsi.rs` — we need to bridge it to Go via CGO.

## Implementation

### 1. CDSI auth endpoint (`internal/signalservice/`)

Fetch CDSI-specific credentials from the Signal server:

- `GET /v2/directory/auth` — returns username/password for CDSI service
- Uses standard message API auth (BasicAuth)
- Credentials are short-lived, fetch fresh per lookup

### 2. Rust async runtime bridge (`internal/libsignal/`)

libsignal's CDSI client uses async Rust (tokio). Need to bridge this to Go:

- Initialize a tokio runtime (once, kept alive for the process)
- Expose a blocking FFI function that runs the async lookup to completion
- Bridge Go context cancellation to Rust `CancellationToken`

### 3. ConnectionManager bindings (`internal/libsignal/`)

- `NewConnectionManager(env)` — create manager with Signal environment (production/staging)
- Configure user agent
- Handle proxy configuration if needed

### 4. CDSI lookup bindings (`internal/libsignal/`)

- `NewLookupRequest()` — create request with E.164 numbers to look up
- `CdsiLookup(connMgr, auth, request)` — perform SGX enclave lookup
- Parse `FfiCdsiLookupResponse` into Go structs (ACI, PNI per number)
- Handle rate limiting (`RetryLater`), token management

### 5. Client integration (`client.go`)

- Lazy-init ConnectionManager on first CDSI call
- `LookupACI(number string) (string, error)` — CDSI lookup with local contact store fallback
- Update `Send()` to accept E.164 phone numbers and auto-resolve via CDSI when local lookup fails

## Key files in libsignal

| File | Purpose |
|------|---------|
| `rust/net/src/cdsi.rs` | Core CDSI client implementation |
| `rust/bridge/shared/src/net/cdsi.rs` | Bridge functions for CDSI |
| `rust/bridge/shared/types/src/net/cdsi.rs` | Bridge types |
| `rust/bridge/shared/types/src/ffi/convert.rs` | FFI conversions for `FfiCdsiLookupResponse` |
| `rust/net/examples/cdsi_lookup.rs` | Example usage |

## Challenges

- **Tokio runtime lifecycle**: Must keep a single runtime alive across multiple CGO calls without leaking
- **Async/await bridging**: Rust futures need to map to Go blocking calls or channels
- **SGX attestation**: Handled by libsignal internally, but errors need proper Go mapping
- **Rate limiting**: CDSI has strict rate limits; need to surface `RetryLater` errors to callers

## Related

- Task 7 (`docs/todo/task07-phone-number-send.md`): Phone number send support using local contact store (precursor)
