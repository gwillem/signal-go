# Refactoring Opportunities

This document identifies opportunities for improving the signal-go codebase.

## 1. Duplicate Code

### 1.1 HTTP Request Boilerplate (httpclient.go - 13+ occurrences) ✅ DONE
~~Every HTTP method repeats: create request, set headers, set auth, do request, read body, check status.~~

**Completed:** Added `doJSON()` helper with `apiRequest` struct supporting three auth types (none, Basic, UAK).
Refactored 15 methods. Reduced file from 848 to 720 lines (~15% reduction, 128 lines saved).

### 1.2 Pre-Key Store Methods (internal/store/prekey.go) — SKIPPED
`StorePreKey`, `StoreSignedPreKey`, `StoreKyberPreKey` have identical serialize-insert patterns.

**Decision:** Not worth refactoring. Only 3 methods with ~10 lines each. Using generics would:
- Require a common interface (all types have `Serialize()`)
- Lose specific error messages ("serialize pre-key" vs "serialize signed pre-key")
- Add complexity for minimal line savings (~20 lines total)

---

## 2. Inconsistent Behavior

### 2.1 Logger Parameter Position ✅ RESOLVED
~~Logger appears in different positions across similar functions.~~

**Status:** Resolved by architecture refactoring. Most functions are now methods on `Service` struct
which holds logger internally. Remaining standalone functions (`handleContactSync`, `saveContactProfileKey`,
`dumpEnvelope`, `dumpContent`) all consistently have logger as the last parameter.

### 2.2 Return Values for "Not Found" — ACCEPTABLE AS-IS
Mixed patterns reflect semantics:
- `(nil, nil)` - store/contact.go, store/account.go — for **optional** data lookups (documented in comments)
- `("", nil)` - client.go LookupNumber — convenience wrapper returning just a string
- `(nil, error)` - prekey.go methods — for **required** data (missing pre-key is an error)

**Decision:** Current behavior is semantically correct. No change needed.

### 2.3 Resource Cleanup — MOSTLY CORRECT
Reviewed usage patterns:
- Most cases use `defer obj.Destroy()` properly (e.g., sender.go:88, 103)
- Manual cleanup in error paths (client.go:87-112) is correct when resource should be preserved on success
- No obvious missing cleanup cases found

**Decision:** Current patterns are appropriate. Manual cleanup is correct when ownership transfers on success.

### 2.4 HTTP Success Status Codes — ACCEPTABLE AS-IS
Different endpoints check different combinations based on their semantics:
- `StatusOK` only — for GET/query operations
- `StatusOK || StatusNoContent` — for PUT/update operations
- `StatusOK || StatusCreated || StatusAccepted || StatusNoContent` — for send operations

**Decision:** Current behavior matches HTTP semantics. Each caller knows its endpoint's valid responses.

---

## 3. Defensive Programming Opportunities

### 3.1 Missing Nil Checks ✅ RESOLVED
All `LoadAccount()` calls now have proper nil checks:

**client.go:** All 8 LoadAccount calls have both error and nil checks (lines 307-312, 502-507, 549-554, 596-601, 827-832, 850-855, 910-915, 1037-1039).

**sender.go:** Uses defensive nil checks where needed (line 43, 301) and functions accepting acct handle nil (createPniSignatureMessage line 75-77).

### 3.2 Ignored Errors — ACCEPTABLE AS-IS
Reviewed remaining ignored errors:

**httpclient.go:134:** `io.ReadAll()` error discarded in 429 retry handler — acceptable because this is
error-handling code where body reading failure doesn't prevent retry logic.

**client.go:892:** `cipher.DecryptString()` error discarded in `decryptProfileField()` — intentional,
function comment documents "Returns empty string on any error" for graceful handling of malformed profile data.

Most io.ReadAll calls now properly return errors via the new doJSON() helper.

### 3.3 Unchecked Slice Access ✅ RESOLVED
All `Devices[0]` accesses now have proper length checks:
- sender.go:391-393: checks `len(preKeyResp.Devices) == 0` before access
- retryreceipt.go:300-302: checks `len(preKeyResp.Devices) == 0` before access

### 3.4 Context Cancellation — ACCEPTABLE AS-IS
**receiver.go SendResponse errors:** Discarding ACK response errors is standard practice because:
- No meaningful recovery action for failed ACKs
- Message already processed locally
- Server will retry if needed

**sender.go goroutine:** No fire-and-forget goroutines found in current code.

---

## 4. Missing Unit Test Coverage

### Files Without Any Tests

**internal/signalservice:**
- `primary_registration.go` - Full registration orchestration
- `dump.go`, `tlsconfig.go`, `trustroot.go`

**internal/store:**
- `account.go` - Account persistence
- `identity.go` - Identity key operations
- `prekey.go` - Pre-key operations
- `session.go` - Session operations
- `store.go` - Store initialization

**internal/libsignal:**
- `callbacks.go`, `error.go`, `memstore.go`, `pointer.go`, `profilekey.go`

### Exported Functions Without Tests

**client.go:** 30 of 33 methods untested:
- `Register()`, `SendSealed()`, `Receive()`, `SyncContacts()`
- `VerifyIdentityKey()`, `UpdateAttributes()`, `UpdateAccountSettings()`
- `GetServerProfile()`, `SetProfile()`, `RefreshPreKeys()`

### Priority Test Targets
1. `primary_registration.go` - Complex multi-step flow
2. `internal/store/*.go` - All CRUD operations
3. Client high-level methods

---

## 5. Non-Idiomatic Go Code

### 5.1 Happy Path Not Left-Aligned — ACCEPTABLE AS-IS
**sender.go:56-61:** Intentionally continues without PNI signature on error (documented in comment).
Not a typical error-return pattern.

**sender.go session handling:** Genuine either-or logic (has session vs doesn't have session),
not an error-handling pattern that should use early return.

### 5.2 Manual UUID Parsing ✅ FIXED
~~**sender.go:** Manual hex parsing loop instead of `encoding/hex` package.~~

**Fixed:** Replaced with `strings.ReplaceAll()` + `hex.DecodeString()`:
```go
func uuidToBytes(uuidStr string) ([]byte, error) {
    hexStr := strings.ReplaceAll(uuidStr, "-", "")
    if len(hexStr) != 32 {
        return nil, fmt.Errorf("invalid UUID length: %d", len(hexStr))
    }
    return hex.DecodeString(hexStr)
}
```

---

## 6. Missing Modern Go Idioms

### 6.1 Old-Style For Loops — PARTIALLY FIXED
**sender.go:142-151:** Fixed via hex.DecodeString() refactor (item 5.2).

**padding_test.go:9:** ✅ Fixed: `for i := range 79` instead of `for i := 0; i < 79; i++`.
Other loops (lines 20, 28, 37) cannot be converted (don't start at 0).

### 6.2 No Usage of cmp.Or for Defaults — LOW PRIORITY
Could use `cmp.Or(val, default)` for default value patterns.
No urgent examples found.

### 6.3 sync.WaitGroup.Go Not Used — N/A
No sync.WaitGroup usage found in the codebase.

---

## Summary

| Category | Count | Status |
|----------|-------|--------|
| Duplicate code patterns | 2 | ✅ 1.1 DONE, 1.2 SKIPPED |
| Inconsistent behaviors | 4 | ✅ All RESOLVED/ACCEPTABLE |
| Defensive programming gaps | 4 | ✅ All RESOLVED/ACCEPTABLE |
| Missing test coverage | 15 files, 30+ functions | ⏳ REMAINING (future work) |
| Non-idiomatic code | 2 | ✅ 5.2 FIXED, 5.1 ACCEPTABLE |
| Missing modern idioms | 3 | ✅ 6.1 PARTIALLY FIXED, 6.2/6.3 N/A |

### Completed Improvements (2026-02-05)
1. ✅ HTTP request helper (`doJSON`) - reduced httpclient.go from 848 to 720 lines (~15%)
2. ✅ Manual UUID parsing replaced with `hex.DecodeString()`
3. ✅ Old-style for loops updated to `for range n` where applicable

### Remaining Work
- Add remaining unit tests (section 4) - significant effort, defer to future
- Consider `cmp.Or` for default values when patterns emerge
