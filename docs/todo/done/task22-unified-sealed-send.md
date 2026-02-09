# Task 22: Unified Send with Automatic Sealed Sender Fallback

## Status: Complete

## Problem

We exposed separate `Send()` and `SendSealed()` methods, forcing callers to choose. Signal-Android always attempts sealed sender first and falls back transparently. Our split was an artificial distinction that didn't match the reference implementation.

## Solution

Merged into a single `Send()` with automatic sealed sender fallback, matching Signal-Android's `SealedSenderAccess.switchToFallback` behavior.

### Fallback chain

```
sealed with derived key → 401 → sealed with unrestricted key → 401 → unsealed
```

If no profile key exists, start at unrestricted key. If sender certificate is unavailable or recipient is self, go directly to unsealed.

### Timestamp fix (critical)

Signal Desktop validates that the envelope timestamp matches the DataMessage timestamp exactly. Previously, `sendTextMessage` created the DataMessage timestamp, but the envelope functions (`trySendSealed`, `encryptAndSend`) each generated their own `time.Now()` ~300ms later, causing desktop to reject every message:

```
Error: Timestamp X in DataMessage did not match envelope timestamp Y
```

Fix: the DataMessage timestamp is now threaded through `sendWithSealedFallback` → `sendSealedEncryptedWithTimestamp` → `trySendSealed`, and via `sendEncryptedMessageWithTimestamp` for the unsealed fallback paths.

### Changes made

| File | Change |
|------|--------|
| `internal/signalservice/accesskey.go` | Added `accessKeyRejectedError`, `unrestrictedKey`, `resolveAccessKey`, `isAccessKeyRejected` |
| `internal/signalservice/sender.go` | Replaced `sendTextMessage` to call `sendWithSealedFallback`; added `sendSealedEncryptedWithTimestamp`; removed `sendSealedSenderMessage` and `sendTextMessageWithIdentity` |
| `internal/signalservice/service.go` | Removed `SendSealedSenderMessage` and `SendTextMessageWithIdentity`; 401 returns typed `accessKeyRejectedError` |
| `internal/signalservice/sender_test.go` | Added `TestSendUnifiedSealedFallbackOnCertError` and `TestSendUnifiedSkipsSealedForSelf` |
| `client.go` | Removed `SendSealed()`, `SendWithPNI()`, `sendInternal()`; simplified `Send()` |
| `cmd/sgnl/send.go` | Removed `--sealed` and `--pni` flags |
| `client_test.go` | Updated mock servers to handle `/v1/certificate/delivery` endpoint |

### Key design decisions

1. **Nil callback check**: If `getSenderCertificate` is nil, fall straight to unsealed. Keeps existing tests working without mock sender certificates.
2. **Send-to-self**: Always unsealed (matching Signal-Android `sealedSenderAccess = NONE` for self).
3. **Each fallback stage has its own device retry**: `sendSealedEncrypted` and `sendEncryptedMessage` each contain `withDeviceRetry`.
4. **Kept `deriveAccessKeyForRecipient`**: Still used by GroupSender with its own fallback logic.
5. **Timestamp threading**: The DataMessage timestamp must equal the envelope timestamp. Both sealed and unsealed fallback paths use `WithTimestamp` variants.

## Verified

- Sealed sender message delivered successfully to Signal Desktop and iPhone.
- All tests pass with `make test`.

## Reference

- `Signal-Android/.../SignalServiceMessageSender.java` — retry loop with `sealedSenderAccess.switchToFallback()`
- `Signal-Android/.../SealedSenderAccessUtil.java` — access mode resolution
- `Signal-Android/.../SealedSenderAccess.java` — staged fallback state machine
