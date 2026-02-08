# Task 25: FFI Leak Detection

## Context

We eliminated FFI pointer leaks by switching store interfaces from FFI types to `[]byte`. To prevent future regressions and catch any remaining leaks, we want a build-tag-gated leak detection system that logs when FFI objects are not properly `Destroy()`ed.

CLAUDE.md has been updated with FFI lifecycle rules to prevent future leaks.

## Investigation Summary

Audited all ~40 FFI allocation sites and their callers across `sender.go`, `groupsender.go`, `receiver.go`, `retryreceipt.go`, `registration.go`, `keygen.go`, and `trustroot.go`. **All current callers properly Destroy FFI objects.** No active leaks found.

The risk is future regressions — a missed `Destroy()` is a silent leak with no diagnostic.

## Design

Two-file approach with build tag `ffitrack`:

- **`ffitrack_noop.go`** (`//go:build !ffitrack`) — empty stubs, zero overhead in production
- **`ffitrack.go`** (`//go:build ffitrack`) — global registry tracking alloc/free with caller site info

### API

```go
func ffiTrackAlloc(typeName string, ptr unsafe.Pointer)  // register allocation + caller site
func ffiTrackFree(ptr unsafe.Pointer)                     // deregister on Destroy
func FFIReportLeaks() int                                  // log all unreleased objects, return count
```

When `ffitrack` is enabled:
- `ffiTrackAlloc` records `typeName` + `runtime.Caller(2)` (the caller of the constructor) in a `sync.Mutex`-protected `map[uintptr]string`
- `ffiTrackFree` removes the entry
- `FFIReportLeaks` iterates the map and logs via `callbackErrf`, returns count

### Instrumentation Points

**Constructors** (add `ffiTrackAlloc` after successful creation) — ~41 sites across 12 files:

| File | Functions |
|------|-----------|
| `privatekey.go` | `GeneratePrivateKey`, `DeserializePrivateKey`, `NewPrivateKey` |
| `publickey.go` | `DeserializePublicKey`, `PrivateKey.PublicKey()` |
| `session.go` | `DeserializeSessionRecord` |
| `address.go` | `NewAddress` |
| `prekey.go` | `NewPreKeyRecord`, `DeserializePreKeyRecord`, `PreKeyRecord.PublicKey()`, `NewSignedPreKeyRecord`, `DeserializeSignedPreKeyRecord`, `SignedPreKeyRecord.PublicKey()` |
| `kyberprekey.go` | `GenerateKyberKeyPair`, `KyberKeyPair.PublicKey()`, `DeserializeKyberPublicKey`, `NewKyberPreKeyRecord`, `DeserializeKyberPreKeyRecord`, `KyberPreKeyRecord.PublicKey()` |
| `prekeybundle.go` | `NewPreKeyBundle` |
| `message.go` | `DeserializePreKeySignalMessage`, `DeserializeSignalMessage`, `PreKeySignalMessage.IdentityKey()` |
| `protocol.go` | `Encrypt` |
| `sealedsender.go` | `SealedSenderDecryptToUSMC`, `NewUnidentifiedSenderMessageContent`, `NewUnidentifiedSenderMessageContentFromType`, `USMC.GetSenderCert()`, `NewServerCertificate`, `DeserializeSenderCertificate`, `NewSenderCertificate` |
| `senderkey.go` | `DeserializeSenderKeyRecord`, `DeserializeSenderKeyDistributionMessage`, `CreateSenderKeyDistributionMessage`, `GroupEncryptMessage` |
| `decryptionerror.go` | `NewDecryptionErrorMessage`, `DeserializeDecryptionErrorMessage`, `ExtractDecryptionErrorFromContent`, `DecryptionErrorMessage.RatchetKey()` |
| `plaintextcontent.go` | `DeserializePlaintextContent`, `NewPlaintextContentFromDecryptionError` |
| `authcredential.go` | `NewServerPublicParams` |

**Destroy methods** (add `ffiTrackFree` before setting ptr to nil) — ~21 types:

All types with `Destroy()` or `Close()`: PrivateKey, PublicKey, SessionRecord, Address, PreKeyRecord, SignedPreKeyRecord, KyberPublicKey, KyberKeyPair, KyberPreKeyRecord, PreKeyBundle, CiphertextMessage, PreKeySignalMessage, SignalMessage, UnidentifiedSenderMessageContent, SenderCertificate, ServerCertificate, SenderKeyRecord, SenderKeyDistributionMessage, DecryptionErrorMessage, PlaintextContent, ServerPublicParams.

**CGO callbacks** (add `ffiTrackFree` + nil ptr after ownership transfer to Rust) — 7 sites in `callbacks.go`:

`goLoadSession`, `goGetIdentityKeyPair`, `goGetIdentityKey`, `goLoadPreKey`, `goLoadSignedPreKey`, `goLoadKyberPreKey`, `goLoadSenderKey` — after setting `recordp.raw = rec.ptr`, add:
```go
ffiTrackFree(unsafe.Pointer(rec.ptr))
rec.ptr = nil  // ownership transferred to Rust
```

### Usage

```bash
# Run tests with leak detection:
make test GOFLAGS="-tags=ffitrack"

# In test code:
defer func() {
    if n := libsignal.FFIReportLeaks(); n > 0 {
        t.Errorf("%d FFI leaks detected", n)
    }
}()
```

## Implementation Order

1. Create `internal/libsignal/ffitrack_noop.go` and `internal/libsignal/ffitrack.go`
2. Add `ffiTrackFree` calls to all 21 Destroy/Close methods
3. Add `ffiTrackAlloc` calls to all ~41 constructors
4. Add ownership-transfer tracking to 7 CGO callbacks in `callbacks.go`
5. Add a `TestFFILeakDetection` test that verifies: (a) creating an object without Destroy shows up in ReportLeaks, (b) creating and Destroying does not
6. Add leak check to existing `protocol_test.go` roundtrip tests

## Verification

```bash
make test GOFLAGS="-tags=ffitrack"
```

All existing tests must pass. The new `TestFFILeakDetection` test validates the tracking works. No changes to production behavior (build tag disabled by default).
