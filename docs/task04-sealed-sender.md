# Phase 4: Sealed Sender Investigation & Tests

## Problem Statement

All sealed sender messages fail with:
```
decrypting sealed sender message (version byte=0x11, len=2060)
Error: receiver: sealed sender decrypt outer (sender unknown, cannot send retry receipt): libsignal error 10: protobuf encoding was invalid
```

- ALL sealed sender messages fail (not just some)
- ALL senders affected (not sender-specific)
- Error persists after re-linking device 2 days ago

## Root Cause Analysis

### What the Error Means

Error code 10 = `SignalErrorCodeProtobufError` in libsignal. This occurs during sealed sender outer layer decryption:

1. ECDH between sender's ephemeral key and our identity private key
2. Derive symmetric keys from ECDH shared secret
3. AES decrypt the message
4. Parse decrypted bytes as `UnidentifiedSenderMessageContent` protobuf

If ECDH uses the **wrong identity key**, the derived keys are wrong, AES "decrypts" to garbage, and protobuf parsing fails.

### Why ALL Messages Fail

Since ALL messages from ALL senders fail, this points to a **fundamental identity key issue**:

1. **Most likely**: The identity key being used by signal-go doesn't match what senders expect
2. **During provisioning**: Identity keys come FROM the primary device
3. **But**: If the old linked device had registered different sealed sender data, senders may have cached that

### Sealed Sender v1 Flow (`receiver.go:179`)

```go
usmc, err := libsignal.SealedSenderDecryptToUSMC(content, st)  // st = store implementing IdentityKeyStore
```

The store provides `GetIdentityKeyPair()` which returns the local ACI identity private key for ECDH.

## Implementation Plan

### Task 1: Add Sealed Sender Unit Tests

The current tests (`sealedsender_test.go`) only verify error handling for invalid input. We need tests that verify the full encrypt → decrypt flow.

#### Required FFI Bindings to Add

Add bindings for sealed sender encryption in `internal/libsignal/sealedsender.go`:

```go
// SealedSenderEncrypt encrypts a message using sealed sender (SSv1).
func SealedSenderEncrypt(
    destination *Address,
    content *UnidentifiedSenderMessageContent,
    identityStore IdentityKeyStore,
) ([]byte, error)
```

#### Additional FFI Bindings Needed

| Function | FFI Symbol |
|----------|-----------|
| ServerCertificate | `signal_server_certificate_new` |
| SenderCertificate | `signal_sender_certificate_new` |
| UnidentifiedSenderMessageContent | `signal_unidentified_sender_message_content_new` |
| SealedSenderEncrypt | `signal_sealed_session_cipher_encrypt` |

These are already available in `libsignal-ffi.h` and just need Go wrappers.

#### Test Implementation

**File: `internal/libsignal/sealedsender_test.go`**

Reference: `libsignal/rust/protocol/tests/sealed_sender.rs:136-217`

```go
func TestSealedSenderEncryptDecrypt(t *testing.T) {
    // 1. Create sender (alice) and recipient (bob)
    alice := newParty(t, 1)
    bob := newParty(t, 2)

    // 2. Create trust root and server certificate
    trustRootPriv, _ := GeneratePrivateKey()
    trustRootPub, _ := trustRootPriv.PublicKey()
    serverPriv, _ := GeneratePrivateKey()
    serverCert := NewServerCertificate(1, serverPriv.PublicKey(), trustRootPriv)

    // 3. Create sender certificate for alice
    alicePub, _ := alice.identityStore.GetIdentityKeyPair().PublicKey()
    expires := uint64(time.Now().Add(time.Hour).UnixMilli())
    senderCert := NewSenderCertificate("alice-uuid", "+1111", alicePub, 1, expires, serverCert, serverPriv)

    // 4. Establish session: alice processes bob's pre-key bundle
    bobBundle := createPreKeyBundle(t, bob)
    bobAddr, _ := NewAddress("bob-uuid", 2)
    ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now())

    // 5. Create inner encrypted message
    plaintext := []byte("sealed sender test")
    ciphertext, _ := Encrypt(plaintext, bobAddr, alice.sessionStore, alice.identityStore, time.Now())

    // 6. Create UnidentifiedSenderMessageContent wrapping the ciphertext
    usmc := NewUnidentifiedSenderMessageContent(ciphertext, senderCert, ContentHintDefault, nil)

    // 7. Encrypt with sealed sender (uses bob's identity for ECDH)
    sealed, _ := SealedSenderEncrypt(bobAddr, usmc, alice.identityStore)

    // 8. Decrypt outer layer on bob's side
    decryptedUSMC, err := SealedSenderDecryptToUSMC(sealed, bob.identityStore)
    if err != nil {
        t.Fatalf("SealedSenderDecryptToUSMC failed: %v", err)
    }
    defer decryptedUSMC.Destroy()

    // 9. Verify sender certificate
    cert, _ := decryptedUSMC.GetSenderCert()
    valid, _ := cert.Validate(trustRootPub, uint64(time.Now().UnixMilli()))
    if !valid {
        t.Fatal("sender certificate invalid")
    }

    // 10. Decrypt inner message
    msgType, _ := decryptedUSMC.MsgType()
    innerContent, _ := decryptedUSMC.Contents()

    aliceAddr, _ := NewAddress("alice-uuid", 1)
    var decrypted []byte
    if msgType == CiphertextMessageTypePreKey {
        preKeyMsg, _ := DeserializePreKeySignalMessage(innerContent)
        decrypted, _ = DecryptPreKeyMessage(preKeyMsg, aliceAddr, bob.sessionStore,
            bob.identityStore, bob.preKeyStore, bob.signedPreKeyStore, bob.kyberPreKeyStore)
    }

    // 11. Verify plaintext matches
    if !bytes.Equal(decrypted, plaintext) {
        t.Errorf("mismatch: got %x, want %x", decrypted, plaintext)
    }
}
```

### Task 2: Add Diagnostic Logging

Add identity key fingerprint logging to verify what key is being used.

**File: `internal/signalservice/receiver.go`**

Before calling `SealedSenderDecryptToUSMC`, log the identity key fingerprint:

```go
// Log identity key being used for sealed sender decryption
if identityKey, err := st.GetIdentityKeyPair(); err == nil {
    if pub, err := identityKey.PublicKey(); err == nil {
        if data, err := pub.Serialize(); err == nil {
            logf(logger, "sealed sender: using identity key fingerprint=%x", data[:8])
        }
        pub.Destroy()
    }
    identityKey.Destroy()
}
```

**File: `client.go`**

During Load(), log the loaded identity key:

```go
// After SetIdentity, log the fingerprint
if pub, err := identityPriv.PublicKey(); err == nil {
    if data, err := pub.Serialize(); err == nil {
        if logger != nil {
            logger.Printf("loaded identity key fingerprint=%x", data[:8])
        }
    }
    pub.Destroy()
}
```

### Task 3: Verify Against Primary Device

Compare the identity key fingerprint with Signal-Android:
- Open Signal Android → Settings → Account → Privacy → Safety Number
- The safety number is derived from identity keys
- Or use `signal-cli` to dump identity: `signal-cli -a +1234567890 listIdentities`

### Task 4: Potential Fix - Re-register Pre-Keys

If identity keys match but decryption still fails:
1. Delete old sessions: `DELETE FROM sessions`
2. Re-upload pre-keys to server
3. This forces senders to establish fresh sessions

## Files to Modify

| File | Change |
|------|--------|
| `internal/libsignal/sealedsender.go` | Add FFI bindings for encrypt, certificates |
| `internal/libsignal/sealedsender_test.go` | Add end-to-end encrypt/decrypt test |
| `internal/signalservice/receiver.go:172` | Add identity key fingerprint logging |
| `client.go:175-180` | Add identity key fingerprint logging on load |

## Verification Steps

1. Run `make test` to verify new sealed sender tests pass
2. Run with `-v` flag to enable logging
3. Check identity key fingerprint in logs
4. Compare with Signal-Android identity for same account
5. If mismatch found: investigate provisioning data
6. If match: problem is with senders' cached data (wait for refresh or re-link primary)

## Alternative: Force Identity Key Refresh

If senders have stale keys, options:
1. **Wait**: Signal refreshes profiles within ~12-24 hours
2. **Change profile**: Update profile picture/name to trigger push
3. **Safety number change**: Primary device could regenerate identity (drastic)

## Status

- [x] Task 1: Add sealed sender unit tests ✅
- [x] Task 2: Add diagnostic logging ✅
- [x] Task 3: Verify against primary device ✅ (identity keys match)
- [ ] Task 4: Re-register pre-keys if needed

## Completed Work

### FFI Bindings Added (sealedsender.go)

New functions added to `internal/libsignal/sealedsender.go`:

| Function | Purpose |
|----------|---------|
| `NewServerCertificate` | Create server cert signed by trust root |
| `NewSenderCertificate` | Create sender cert for sealed sender |
| `NewUnidentifiedSenderMessageContent` | Wrap encrypted message with sender cert |
| `SealedSenderEncrypt` | Encrypt USMC using sealed sender v1 |
| `ContentHintDefault/Resendable/Implicit` | Constants for content hints |

### Tests Added (sealedsender_test.go)

| Test | Purpose |
|------|---------|
| `TestSealedSenderEncryptDecrypt` | Full round-trip: encrypt→seal→decrypt→verify |
| `TestSealedSenderWrongIdentityKey` | Verifies wrong identity key fails with error 30 |

### Diagnostic Logging Added

- `receiver.go:174-182`: Log identity key fingerprint before sealed sender decrypt
- `client.go:183-190`: Log identity key fingerprint on Load()

### Key Findings from Tests

The error for wrong identity key is **error 30**: "invalid sealed sender message: failed to decrypt sealed sender v1 message key"

This is different from the user's error (error 10: "protobuf encoding was invalid"). Error 30 indicates the ECDH step failed (MAC check failure), while error 10 suggests corrupted protobuf parsing (potentially wrong envelope version or completely different format issue).

### New CLI Tools Added

| Command | File | Purpose |
|---------|------|---------|
| `sgnl verify-identity` | `cmd/sgnl/verifyidentity.go` | Compare local identity key with server |
| `sgnl check-all-keys` | `cmd/sgnl/checkallkeys.go` | Check identity key for all devices on server |

## Investigation Results

### Identity Key Verification (Task 3)

Ran `sgnl verify-identity` and `sgnl check-all-keys` to compare identity keys:

```
$ sgnl verify-identity
Local identity key:  058c28030a0cf5c8534e1d9b01c282e14bb33d4819e2ab663b9b3c9f4644d4fd55
Server identity key: 058c28030a0cf5c8534e1d9b01c282e14bb33d4819e2ab663b9b3c9f4644d4fd55

✓ MATCH: Server has the same identity key
```

```
$ sgnl check-all-keys
Checking identity key for each device on server...

Device 1: 058c28030a0cf5c8534e1d9b01c282e14bb33d4819e2ab663b9b3c9f4644d4fd55
Device 2: 058c28030a0cf5c8534e1d9b01c282e14bb33d4819e2ab663b9b3c9f4644d4fd55
Device 4: 058c28030a0cf5c8534e1d9b01c282e14bb33d4819e2ab663b9b3c9f4644d4fd55
```

**Result**: All 3 devices (1=iPhone primary, 2=signal-go, 4=unknown) share the same identity key `058c28030a0cf5c8...`. The local identity key matches what the server has registered.

### The Mystery: Error 10 vs Error 30

Our tests prove:
- **Wrong identity key → Error 30** ("failed to decrypt sealed sender v1 message key" - MAC check fails)
- **User's error → Error 10** ("protobuf encoding was invalid" - parsing fails)

Error 10 should only occur if:
1. The AES decryption "succeeds" (MAC passes) but produces garbage
2. The garbage bytes fail to parse as `UnidentifiedSenderMessageContent` protobuf

This is paradoxical because:
- If the identity key is wrong, ECDH produces wrong keys, MAC fails, we get error 30
- If the identity key is correct, decryption should work
- Getting error 10 suggests MAC passed but content is invalid

**Possible explanations:**
1. **Envelope format issue**: The envelope may not be SSv1 despite version byte 0x11
2. **libsignal version mismatch**: Sender uses newer/older protocol variant
3. **Corrupted messages**: Network or server corruption
4. **Account state issue**: Something wrong with how the account was provisioned

### Debug Envelope Analysis

Examined a captured envelope (`debug/1770112832577_UNIDENTIFIED_SENDER_sealed_0.bin`):

- **Version byte**: 0x11 (SSv1, correct)
- **Total length**: 2060 bytes (reasonable)
- **Structure**: Valid protobuf envelope with type=6 (UNIDENTIFIED_SENDER)
- **Content field**: 1954 bytes (sealed sender payload)

The envelope structure appears valid, ruling out format issues.

### Key Pair Validation

Ran `TestDebugRealSealedSender` to verify key pair integrity:

```
Stored public key:  058c28030a0cf5c8534e1d9b01c282e14bb33d4819e2ab663b9b3c9f4644d4fd55
Derived public key: 058c28030a0cf5c8534e1d9b01c282e14bb33d4819e2ab663b9b3c9f4644d4fd55
Key pair is valid (public key correctly derived from private key)
```

The key pair in the database is valid and consistent.

## Unsolved Mystery

All diagnostic checks pass:
- ✅ Identity key pair is valid
- ✅ Local key matches server
- ✅ All devices have same identity key
- ✅ Envelope format is valid SSv1
- ✅ Round-trip tests pass with test keys

Yet decryption fails with error 10 (protobuf invalid) instead of error 30 (MAC failure).

This suggests the issue may be:
1. **Sender-side**: Senders are encrypting for a different key than what's on the server
2. **Caching**: Senders have cached stale identity data from before re-link
3. **Protocol variant**: A subtle difference in how messages are encrypted

## Recommended Resolution

### Option 1: Wait for Cache Expiry
Signal clients refresh identity data periodically (~12-24 hours). If senders have stale cached keys, waiting may resolve it.

### Option 2: Clean Re-link (Nuclear Option)
1. Unlink the signal-go device from primary
2. Delete the local database: `rm ~/.signal-go.db`
3. Re-link with `sgnl link`
4. This ensures clean state on both client and server

### Option 3: Profile Update Trigger
Update profile picture or name on primary device to trigger identity data refresh for contacts.

## New Findings: Outer Structure is Valid

### Analysis Tool Results

Created `sgnl analyze-sealed` command to parse captured envelopes. Results:

```
=== Sealed Sender Content ===
Version byte: 0x11
Version (major): 1
Format: Sealed Sender v1

Protobuf parse: SUCCESS
  ephemeral_public: 33 bytes
  encrypted_static: 43 bytes
  encrypted_message: 1976 bytes

Ephemeral public key:
  First byte 0x05 = valid Curve25519 public key prefix
```

The outer `UnidentifiedSenderMessage` protobuf parses correctly in Go, which means libsignal should also be able to parse it.

### Corrected Size Analysis

The phase 4 doc previously said `encrypted_static` should be 48 bytes (32 key + 16 MAC). This was **incorrect**.

From `libsignal/rust/protocol/src/crypto.rs:61`:
```rust
ctext.extend_from_slice(&mac[..10]);  // Only first 10 bytes of HMAC
```

So the correct size is: 33 bytes (ciphertext) + 10 bytes (truncated MAC) = **43 bytes** ✓

### Error Location Narrowed Down

For error 10 (`InvalidProtobufEncoding`) to occur, the flow must be:

1. **Parse outer UnidentifiedSenderMessage** → SUCCESS (verified with Go parser)
2. **Decrypt encrypted_static** → SUCCESS (else we'd get `InvalidSealedSenderMessage`)
3. **Decrypt encrypted_message** → SUCCESS (else we'd get `InvalidSealedSenderMessage`)
4. **Parse decrypted bytes as USMC** → FAILS with error 10

This means decryption "succeeds" (MAC passes) but the result isn't valid `UnidentifiedSenderMessageContent` protobuf.

### Possible Explanations

1. **ECDH produces wrong key but MAC still passes** - Cryptographically unlikely
2. **libsignal version mismatch** - Sender uses newer/older USMC format
3. **Account state issue** - Something corrupted during provisioning

### Fix Implemented: Try Both ACI and PNI Identities

**Root Cause Hypothesis**: Sender encrypted for our PNI identity key (discovered us via phone number), but we were only trying ACI identity key for decryption.

**Solution** (`internal/signalservice/receiver.go`): For sealed sender messages, try ACI identity first, then PNI identity as fallback.

```go
usmc, err := libsignal.SealedSenderDecryptToUSMC(content, st)
if err != nil {
    // Try PNI identity as fallback
    st.UsePNI(true)
    usmc, err = libsignal.SealedSenderDecryptToUSMC(content, st)
    st.UsePNI(false)
}
```

### Next Steps

1. Test the PNI fallback fix with real sealed sender messages
2. If still failing, enable libsignal debug logging
3. Consider checking if PNI identity key is properly loaded during provisioning

## Technical Notes

### libsignal Version
Using libsignal v0.68.0 (local build from `../libsignal`).

### SSv1 Decryption Flow
```
Sealed Sender v1 (version byte 0x11):
1. Parse ephemeral_public (33 bytes), encrypted_static (48 bytes), encrypted_message (rest)
2. ECDH: ephemeral_public × recipient_identity_private → shared_secret
3. HKDF: shared_secret → chain_key, cipher_key, mac_key
4. Verify MAC: HMAC-SHA256(mac_key, encrypted_message)
5. AES-256-CTR decrypt: cipher_key + encrypted_static → static_key_bytes
6. Second ECDH: static_public × recipient_identity_private → shared_secret2
7. More HKDF + AES decrypt to get UnidentifiedSenderMessageContent
```

If step 2 uses wrong identity key, step 4 (MAC verify) should fail with error 30.
