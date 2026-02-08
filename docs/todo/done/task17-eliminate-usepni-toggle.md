# Task 17: Eliminate UsePNI toggle (mutable shared state)

## Status: DONE

## Problem

`Store.usePNI` was a mutable boolean toggled by `UsePNI(true)`/`UsePNI(false)` with defer patterns. It was read by `GetIdentityKeyPair()` and `GetLocalRegistrationID()` during concurrent CGO callbacks, creating a data race risk.

## Solution

Replaced the mutable toggle with a `PNIIdentityStore` wrapper type:

1. `Store` fields changed from `*libsignal.PrivateKey` to `[]byte` (serialized) — no FFI pointers to manage
2. `SetIdentity`/`SetPNIIdentity` now serialize internally and return `error`
3. `GetIdentityKeyPair()`/`GetLocalRegistrationID()` always return ACI identity
4. New `GetPNIIdentityKeyPair()`/`GetPNIRegistrationID()` for explicit PNI access
5. New `PNIIdentityStore` wrapper (in `internal/store/pni.go`) overrides identity methods to return PNI
6. `Store.PNI()` returns the wrapper — satisfies `libsignal.IdentityKeyStore` interface
7. Removed `usePNI` field and `UsePNI()` method entirely

### Callers updated
- `createPniSignatureMessage()` — uses `GetPNIIdentityKeyPair()` directly
- `handleEnvelope()` — passes `st.PNI()` as `identityStore` for PNI-addressed messages
- `decryptSealedSender()`/`decryptCiphertextOrPreKey()` — accept `identityStore` parameter
- `encryptAndSendWithIdentity()` — new inner function accepting identity store
- `SendTextMessageWithIdentity()` — new public method for PNI sends
- `client.sendInternal()` — passes `c.store.PNI()` instead of toggling flag
