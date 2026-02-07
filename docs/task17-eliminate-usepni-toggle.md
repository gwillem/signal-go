# Task 17: Eliminate UsePNI toggle (mutable shared state)

## Status: TODO

## Problem

`Store.usePNI` is a mutable boolean toggled by `UsePNI(true)`/`UsePNI(false)` with defer patterns. It is read by `GetIdentityKeyPair()` and `GetLocalRegistrationID()` during concurrent CGO callbacks, creating a data race risk.

Affected locations:
- `internal/store/store.go:17-24` — `usePNI` field and `UsePNI()` method
- `client.go:472-485` — `sendInternal()` toggles UsePNI with defer
- `internal/signalservice/sender.go` — `createPniSignatureMessage()` toggles UsePNI
- `internal/signalservice/receiver.go` — `handleEnvelope()` toggles UsePNI for PNI-addressed messages

## Proposed Solution

Replace the mutable toggle with an explicit `IdentityContext` parameter:

1. Define `type IdentityContext int` with constants `IdentityACI` and `IdentityPNI`
2. Change `GetIdentityKeyPair()` → `GetIdentityKeyPair(ctx IdentityContext)`
3. Change `GetLocalRegistrationID()` → `GetLocalRegistrationID(ctx IdentityContext)`
4. Remove `UsePNI()` method and `usePNI` field
5. Update all callers to pass the appropriate context
6. Update CGO callback wrappers to thread identity context through

## Review References

- REVIEW.md Important #1 (data race on Store.usePNI)
- REVIEW.md Important #9 (sendInternal UsePNI toggle anti-pattern)
- REVIEW.md Important #10 (createPniSignatureMessage does 3 things with UsePNI toggle)
