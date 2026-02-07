# Task 04: Sealed Sender Investigation & Fix

## Status: Complete ✅

## Problem Statement

All sealed sender messages failed with:
```
decrypting sealed sender message (version byte=0x11, len=2060)
Error: receiver: sealed sender decrypt outer (sender unknown, cannot send retry receipt): libsignal error 10: protobuf encoding was invalid
```

After upgrading to libsignal v0.87.0, the error changed to:
```
Error: receiver: sealed sender: invalid sender certificate
```

## Root Cause

**The sender certificate validation was failing because we only used one trust root.**

Signal uses two trust roots for sealed sender certificates:
1. `BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF` - older production trust root
2. `BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6` - current production trust root (server cert ID 3)

Our `loadTrustRoot()` function only loaded the first one, but the current Signal production server uses certificates signed by the second trust root.

## Solution

1. **Added `ValidateWithTrustRoots()`** in `sealedsender.go` to validate against multiple trust roots (the v0.87.0 FFI already supports this via `SignalBorrowedSliceOfConstPointerPublicKey`)

2. **Changed `loadTrustRoot()` → `loadTrustRoots()`** in `trustroot.go` to return all configured trust roots

3. **Updated `receiver.go`** to pass all trust roots to validation

## Files Modified

| File | Change |
|------|--------|
| `internal/libsignal/sealedsender.go` | Added `ValidateWithTrustRoots()` for multiple trust roots |
| `internal/signalservice/trustroot.go` | Changed to load all trust roots, not just the first |
| `internal/signalservice/receiver.go` | Use `ValidateWithTrustRoots()` with all trust roots |

## PNI Fallback Removed

During investigation, we added a PNI identity fallback for sealed sender decryption. After verifying against Signal-Android, this was **incorrect** and has been removed.

**Signal-Android's approach** (MessageDecryptor.kt):
- Uses `envelope.destinationServiceId` to select the right identity store (ACI or PNI) upfront
- For sealed sender to PNI, explicitly ignores: "Got a sealed sender message to our PNI? Invalid message, ignoring."
- Does NOT do fallback between identities

**Our corrected approach**:
- Use destination service ID to select identity (lines 148-155 in receiver.go) - correct for non-sealed-sender
- For sealed sender, use the selected identity without fallback
- Matches Signal-Android behavior

## Investigation Timeline

### Phase 1: Initial Error (Error 10)
- All sealed sender messages failed with "protobuf encoding was invalid"
- Added diagnostic logging, verified identity keys match server
- Created unit tests for sealed sender encrypt/decrypt

### Phase 2: After libsignal v0.87.0 Upgrade
- Error changed to "invalid sender certificate"
- Certificate validation was returning `false`

### Phase 3: Root Cause Found
- Discovered we only used first trust root
- Signal production uses certificates signed by second trust root
- Fixed by validating against all configured trust roots

## Verification

1. Sealed sender messages now decrypt successfully
2. Sender certificate validation passes with correct trust root
3. Unit tests pass: `make test`

## Technical Notes

### Trust Roots (from Signal-Android build.gradle.kts)
```kotlin
// Production
"BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF"  // older
"BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6"  // current (server cert ID 3)

// Staging
"BYhU6tPjqP46KGZEzRs1OL4U39V5dlPJ/X09ha4rErkm"  // server cert ID 2
```

### libsignal KNOWN_SERVER_CERTIFICATES
libsignal v0.87.0 has pre-embedded server certificates for IDs 2 and 3 in `sealed_sender.rs`. When a sender certificate uses a reference ID instead of embedding the full server certificate, libsignal looks it up internally.

### SSv1 Decryption Flow
```
1. Parse ephemeral_public, encrypted_static, encrypted_message
2. ECDH: ephemeral_public × recipient_identity_private → shared_secret
3. HKDF: shared_secret → chain_key, cipher_key, mac_key
4. Verify MAC + AES decrypt → UnidentifiedSenderMessageContent
5. Validate sender certificate against trust roots
6. Decrypt inner message using session cipher
```

## Sealed Sender v2 (Multi-Recipient)

Signal uses **Sealed Sender v2** for group messages. Version is indicated by the first byte:
- `0x11` → v1 (single recipient, used for 1:1 messages)
- `0x22`/`0x23` → v2 (multi-recipient, used for groups)

**Decryption**: Both versions are handled automatically by libsignal's `sealed_sender_decrypt`. No changes needed.

**Sending**: v2 requires `sealed_sender_multi_recipient_encrypt` which is not yet bound. See [task14-group-support.md](task14-group-support.md#sealed-sender-v1-vs-v2) for details on implementing group send with v2.
