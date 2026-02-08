# Task 20: CDSI Phone Number Lookup

**Status: Complete**

## Problem

Previously, resolving phone numbers to ACI UUIDs required a full contact sync from the primary device. This meant we could only message people already in our contact list. Signal's Contact Discovery Service (CDSI) allows looking up any phone number to find its ACI/PNI, enabling sending to arbitrary Signal users by phone number.

## Implementation

### Architecture

CDSI runs inside an SGX enclave for privacy. The client authenticates with dedicated CDSI credentials (separate from message API auth), sends E.164 numbers into the enclave, and receives back ACI/PNI mappings. libsignal implements the full CDSI client in Rust — we bridge it to Go via CGO with an async callback pattern.

### Async FFI Bridge Pattern

This is the first async FFI operation in the codebase. The core challenge is bridging Rust's tokio-based async CDSI client to Go:

1. Go creates a buffered channel and saves a handle via `savePointer`
2. C bridge function constructs promise struct (with callback + context) and calls FFI function
3. If synchronous error → callback won't fire, return error immediately
4. Rust spawns async work on tokio runtime
5. When complete, Rust calls C bridge callback → Go `//export` function → sends result to channel
6. Go unblocks on channel receive, returns result

**Key design decisions:**
- Promise structs are constructed entirely in C (inline functions) to avoid CGO Go-pointer checks
- Context passed as `uintptr_t` (not `void*`) to bypass CGO pointer validation
- Response entries are copied into Go slices inside the `//export` callback before returning (Rust owns the response memory)
- 30s timeout on channel receive prevents hanging if Rust never calls back

### Files Created

| File | Purpose |
|------|---------|
| `internal/libsignal/net.go` | `TokioAsyncContext`, `ConnectionManager` FFI wrappers |
| `internal/libsignal/net_test.go` | Lifecycle tests (create/destroy, double-destroy) |
| `internal/libsignal/bridge_async.c` | C bridge functions for async completion callbacks |
| `internal/libsignal/cdsi.go` | `LookupRequest`, `CDSILookup`, async callbacks, response parsing |
| `internal/libsignal/cdsi_test.go` | Request building tests |
| `internal/signalservice/cdsi.go` | CDSI auth endpoint + `LookupNumbers` orchestration |

### Files Modified

| File | Changes |
|------|---------|
| `client.go` | Added CDSI fields (`asyncCtx`, `connMgr`, `cdsiOnce`), `ensureCDSI()` lazy init, `cdsiLookup()`, `isPNIServiceID()`, updated `resolveRecipient` to accept `ctx`/`PNI:uuid` and fall back to CDSI, updated `Close()` for cleanup |
| `client_test.go` | Updated `TestSend_UnknownPhoneNumber` for new CDSI behavior |

### Flow

```
Send(ctx, "+31612345678", "hi")
  → resolveRecipient(ctx, "+31612345678")
    → store.LookupACI("+31612345678")  // local contact store
    → [miss] cdsiLookup(ctx, "+31612345678")
      → ensureCDSI()  // lazy init tokio runtime + connection manager (once)
      → service.LookupNumbers(ctx, ["+31612345678"], asyncCtx, connMgr)
        → GetCDSIAuth(ctx)  // GET /v2/directory/auth
        → CDSILookup(asyncCtx, connMgr, user, pass, request)
          → cdsiLookupNew()   // phase 1: async, blocks on channel
          → cdsiLookupComplete()  // phase 2: async, blocks on channel
        → store.SaveContact()  // cache result for future lookups
      → return service ID (ACI or "PNI:uuid")
  → sendInternal(ctx, serviceID, text)
```

### PNI Fallback

CDSI returns both ACI and PNI for each number. Some accounts return ACI=nil with only a PNI (e.g. when the account has "who can find me by number" set to Nobody, or for other server-side reasons). In this case we use the PNI as the service ID with the `PNI:` prefix, matching Signal-Android's `ServiceId` format:

- ACI: bare UUID (e.g. `550e8400-e29b-41d4-a716-446655440000`)
- PNI: prefixed UUID (e.g. `PNI:d31bf8fe-6263-4229-9afe-20f9a7d89248`)

The `PNI:` prefix flows through all API calls: `/v2/keys/PNI:uuid/1`, `/v1/messages/PNI:uuid`, and is used as the protocol address name for session storage. The first message to a PNI recipient may not display immediately on the recipient's device (treated as a message request); subsequent messages arrive normally.

## Key Patterns

### CGO Pointer Safety

The `uintptr_t` trick: Go pointers from `savePointer` are cast to `uintptr` before passing to C functions, then cast back to `void*` on the C side. This bypasses CGO's pointer check (which would flag a Go pointer inside a C struct) while remaining safe because the handle wrapper is pinned.

### Two-Phase Async

CDSI lookup requires two async operations:
1. `signal_cdsi_lookup_new` — establishes connection to SGX enclave, returns handle
2. `signal_cdsi_lookup_complete` — sends request, receives response

Each uses the same channel-based async bridge pattern.

## Related

- Task 7 (`docs/todo/done/task07-phone-number-send.md`): Phone number send support using local contact store (precursor)
