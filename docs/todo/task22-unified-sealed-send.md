# Task 22: Unified Send with Automatic Sealed Sender Fallback

## Status: Planned

## Problem

We expose separate `Send()` and `SendSealed()` methods, forcing callers to choose. Signal-Android always attempts sealed sender first and falls back transparently. Our split is an artificial distinction that doesn't match the reference implementation.

## Current behavior

- `Send()` — always unsealed, sender identity visible to server
- `SendSealed()` — sealed only, hard-fails on missing profile key or 401

## Desired behavior

A single `Send()` that:

1. If recipient profile key is available → try sealed sender (derived access key)
2. If no profile key → try sealed sender with `UNRESTRICTED_KEY` (16 zero bytes)
3. On 401 (access key rejected) → staged fallback:
   - Derived key → retry with unrestricted key
   - Unrestricted key → retry unsealed
4. On other sealed sender errors (InvalidKey) → fall back to unsealed

This matches Signal-Android's `SignalServiceMessageSender` behavior.

## Design

### Staged fallback (from Signal-Android's `SealedSenderAccess.switchToFallback`)

```
attempt 1: sealed with derived access key (if profile key available)
    ↓ 401
attempt 2: sealed with UNRESTRICTED_KEY
    ↓ 401
attempt 3: unsealed (regular send)
```

If no profile key exists, start at attempt 2.

### Key changes

| File                                | Change                                                                                    |
| ----------------------------------- | ----------------------------------------------------------------------------------------- |
| `internal/signalservice/sender.go`  | Merge `SendTextMessage` and `SendSealedSenderMessage` into single path with fallback loop |
| `internal/signalservice/service.go` | Single `SendTextMessage` that tries sealed first                                          |
| `client.go`                         | Remove `SendSealed()`, `Send()` uses unified path                                         |
| `cmd/sgnl/send.go`                  | Remove `--sealed` flag                                                                    |

### Access key resolution order

```go
func (s *Service) resolveAccessKey(recipientACI string) ([]byte, error) {
    // 1. Try derived key from profile key
    contact, _ := s.store.GetContactByACI(recipientACI)
    if contact != nil && len(contact.ProfileKey) > 0 {
        return DeriveAccessKey(contact.ProfileKey)
    }
    // 2. Fall back to unrestricted key
    return unrestrictedKey, nil
}
```

### Fallback on 401

Detect `AuthorizationFailedException` (HTTP 401 on sealed sender send) and retry:

```go
func (s *Service) sendWithFallback(ctx context.Context, recipient, text string) error {
    accessKey, _ := s.resolveAccessKey(recipient)

    // Try sealed with derived/unrestricted key
    err := s.trySendSealed(ctx, recipient, text, accessKey)
    if err == nil {
        return nil
    }
    if !isAccessKeyRejected(err) {
        return err // non-recoverable error
    }

    // If was derived key, try unrestricted
    if !bytes.Equal(accessKey, unrestrictedKey) {
        err = s.trySendSealed(ctx, recipient, text, unrestrictedKey)
        if err == nil {
            return nil
        }
        if !isAccessKeyRejected(err) {
            return err
        }
    }

    // Final fallback: unsealed
    return s.sendUnsealed(ctx, recipient, text)
}
```

## What to remove

- `Client.SendSealed()` method
- `Client.SendWithPNI()` method (PNI identity switching was a workaround; sealed sender handles this properly)
- `--sealed` and `--pni` flags from CLI
- Separate `SendSealedSenderMessage` in service layer

## Reference

- `Signal-Android/.../SignalServiceMessageSender.java` — retry loop with `sealedSenderAccess.switchToFallback()`
- `Signal-Android/.../SealedSenderAccessUtil.java` — access mode resolution (ENABLED/DISABLED/UNKNOWN/UNRESTRICTED)
- `Signal-Android/.../SealedSenderAccess.java` — staged fallback state machine
