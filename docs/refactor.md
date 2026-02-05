# Refactoring Opportunities

This document identifies opportunities for improving the signal-go codebase based on a comprehensive analysis.

## 1. Duplicate Code

### High Priority

#### 1.1 Pre-Key Storage Pattern (client.go:202-272 and 765-835) ✅ FIXED
~~`storePreKeys()` and `storePrimaryPreKeys()` contain ~68 lines of nearly identical code for deserializing and storing ACI/PNI signed and Kyber pre-keys.~~

**Fixed:** Extracted `storeSignedPreKeyFromBytes()` and `storeKyberPreKeyFromBytes()` helpers. Both functions now use these helpers, reducing ~68 lines to ~20 lines.

#### 1.2 HTTP Request Boilerplate (httpclient.go - 13+ occurrences)
Every HTTP method repeats: create request, set headers, set auth, do request, read body, check status.

**Suggestion:** Create a unified request helper:
```go
func (c *HTTPClient) doRequest(ctx context.Context, method, url string, body []byte, auth *BasicAuth) ([]byte, int, error)
```

### Medium Priority

#### 1.3 BasicAuth Creation (client.go - 12 occurrences) ✅ FIXED
~~Identical `BasicAuth{Username: fmt.Sprintf("%s.%d", c.aci, c.deviceID), Password: c.password}` repeated 12 times.~~

**Fixed:** Added method `func (c *Client) auth() BasicAuth`

#### 1.4 HTTPClient Instantiation (client.go - 8 occurrences) ✅ FIXED
~~`signalservice.NewHTTPClient(c.apiURL, c.tlsConfig, c.logger)` repeated throughout.~~

**Fixed:** HTTPClient is now cached in the Client struct (`c.http`) and initialized once in `NewClient()`. This enables HTTP connection pooling and reuse.

#### 1.5 Pre-Key Store Methods (internal/store/prekey.go)
`StorePreKey`, `StoreSignedPreKey`, `StoreKyberPreKey` have identical serialize-insert patterns.

**Suggestion:** Generic store method with table name parameter.

#### 1.6 Profile Field Decryption (client.go:968-990)
Repeated base64 decode + cipher decrypt for Name, About, Emoji fields.

**Suggestion:** Extract `decryptProfileField(encoded string, cipher *ProfileCipher) string`

---

## 2. Inconsistent Behavior

### 2.1 Error Wrapping ✅ FIXED
~~~30% of errors returned raw without context wrapping.~~

**Fixed:** Wrapped errors in `Link()`, `Register()`, `openStore()`, `saveAccount()` with descriptive context. Remaining pass-through errors in pre-key storage are intentionally not double-wrapped (helpers already provide context).

### 2.2 SQL Error Detection (CRITICAL) ✅ FIXED
~~String comparison `err.Error() == "sql: no rows in result set"` instead of `errors.Is(err, sql.ErrNoRows)`.~~

**Fixed:** Changed all 7 occurrences to use `errors.Is(err, sql.ErrNoRows)`.

### 2.3 Logger Parameter Position
Logger appears in different positions across similar functions:
- Last parameter in most `Send*` functions
- 8th of 9 in `ReceiveMessages()`
- Inside struct for `handleEnvelope()`

**Fix:** Standardize logger as last parameter in all exported functions.

### 2.4 Return Values for "Not Found"
Mixed patterns:
- `(nil, nil)` - store/contact.go, store/account.go
- `("", nil)` - client.go:484 (LookupNumber)
- `(nil, error)` - some store methods

**Fix:** Standardize on `(nil, ErrNotFound)` or document the `(nil, nil)` convention.

### 2.5 Resource Cleanup
Inconsistent use of `defer` vs explicit cleanup:
- Some use `defer obj.Destroy()` (preferred)
- Some call `obj.Destroy()` manually in error paths
- Some miss cleanup entirely

**Fix:** Always use `defer` for CGO resource cleanup immediately after creation.

### 2.6 HTTP Success Status Codes
Different endpoints check different combinations:
- `StatusOK` only
- `StatusOK || StatusNoContent`
- `StatusOK || StatusCreated || StatusAccepted || StatusNoContent`

**Fix:** Document expected status codes per endpoint or create endpoint-specific validators.

---

## 3. Defensive Programming Opportunities

### 3.1 Missing Nil Checks

**client.go:**
- Line 507: `acct.ACIIdentityKeyPublic` accessed without nil check after `LoadAccount()`
- Line 562: `acct.RegistrationID` accessed without nil check
- Line 936-949: `acct.ACI` and `acct.ProfileKey` accessed without nil check

**sender.go:**
- Line 288-289: `acct` could be nil when accessed

**Fix:** Add nil checks after all `LoadAccount()` calls before accessing fields.

### 3.2 Ignored Errors

**httpclient.go:**
- Lines 73, 232, 277, 336: `io.ReadAll()` errors discarded with `_`

**client.go:**
- Lines 972, 980, 988: `cipher.DecryptString()` errors silently dropped
- Lines 1045-1047: base64 decode and cipher errors ignored

**Fix:** Log errors even if not returned, or return them wrapped.

### 3.3 Unchecked Slice Access

**sender.go:403:** `preKeyResp.Devices[0]` - should verify slice is non-empty first.

### 3.4 Context Cancellation
- receiver.go:117: `SendResponse()` error ignored
- sender.go:482: Fire-and-forget goroutine with no timeout

**Fix:** Add timeouts to background operations and check context cancellation.

---

## 4. Missing Unit Test Coverage

### Files Without Any Tests (18 files)

**internal/signalservice:**
- `primary_registration.go` - Full registration orchestration
- `profilecipher.go` - AES-GCM encryption (security-critical)
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
1. `profilecipher.go` - Security-critical encryption
2. `primary_registration.go` - Complex multi-step flow
3. `internal/store/*.go` - All CRUD operations
4. Client high-level methods

---

## 5. Non-Idiomatic Go Code

### 5.1 Happy Path Not Left-Aligned

**sender.go:56-61:**
```go
if err != nil {
    logf(...)
} else if pniSig != nil {  // <- should be early return
    content.PniSignatureMessage = pniSig
}
```

**sender.go:418-426:** Else block for session handling.

**Fix:** Use early returns for error cases, keep happy path at lowest indentation.

### 5.2 Custom bytesEqual Instead of bytes.Equal ✅ FIXED
~~**receiver.go:568-577:** Defines custom `bytesEqual()` function.~~

~~**client.go:525:** Uses `string(serverKey) == string(localKey)` instead of `bytes.Equal()`.~~

**Fixed:** Removed custom `bytesEqual()` and replaced with `bytes.Equal()` from stdlib.

### 5.3 Manual UUID Parsing

**sender.go:144-151:** Manual hex parsing loop instead of `encoding/hex` package.

**Fix:** Use `hex.DecodeString()` or `uuid.Parse()`.

---

## 6. Missing Modern Go Idioms

### 6.1 Old-Style For Loops

**sender.go:144-151:** C-style `for i := 0; i < 16; i++` for hex parsing.

**padding_test.go:9:** Could use `for range`.

**Fix:** Use `for i := range n` or `for range n` where applicable.

### 6.2 No Usage of cmp.Or for Defaults

Could use `cmp.Or(val, default)` for default value patterns.

### 6.3 sync.WaitGroup.Go Not Used

Traditional `wg.Add(1); go func() { defer wg.Done(); ... }()` pattern used instead of `wg.Go()`.

---

## Summary

| Category | Count | Priority |
|----------|-------|----------|
| Duplicate code patterns | 10 | High |
| Inconsistent behaviors | 6 | Medium |
| Defensive programming gaps | 15+ | Medium |
| Missing test coverage | 18 files, 30+ functions | High |
| Non-idiomatic code | 5 | Low |
| Missing modern idioms | 3 | Low |

### Recommended Order of Fixes
1. ✅ SQL error handling (`errors.Is`) - quick win, prevents bugs - **DONE**
2. ✅ Nil checks after `LoadAccount()` - prevents panics - **DONE**
3. ✅ Replace custom `bytesEqual` with `bytes.Equal` - **DONE**
4. ✅ Test coverage for `profilecipher.go` - security critical - **DONE**
5. ✅ Extract `auth()` helper - reduces 10 duplicates - **DONE**
6. HTTP request helper - reduces ~200 lines
7. ✅ Pre-key storage consolidation - reduces ~70 lines - **DONE**
8. ✅ Standardize error wrapping - **DONE**
9. Add remaining unit tests
