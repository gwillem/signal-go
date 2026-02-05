# Phase 10: iPhone Message Visibility Investigation

## Problem Statement

Messages sent from signal-go are delivered to iPhone (server returns 200 OK, SERVER_DELIVERY_RECEIPT received), but do not appear in the iPhone Signal app.

**Symptoms:**
- `sgnl send <aci> "test message"` returns success
- Server returns 200 OK
- SERVER_DELIVERY_RECEIPT received for both iPhone devices (1 and 2)
- Message never appears on iPhone or Signal Desktop
- signal-cli works correctly (no sealed sender)

## Related Issues

When iPhone/Desktop tries to send delivery receipts back to signal-go, they use sealed sender which fails:
```
sealed sender decrypt outer (sender unknown, cannot send retry receipt): libsignal error 10: protobuf encoding was invalid
```
This is tracked separately in [Task 04](task04-sealed-sender.md).

## Root Cause Analysis

### Key Observation

When sending from signal-go account A to signal-go account B (which is linked to iPhone):
- **signal-go linked device DOES receive the message**
- **iPhone and Desktop do NOT receive the message**

This rules out:
- Content protobuf structure issues (signal-go decrypts it fine)
- Padding issues (same)
- Basic session encryption issues (same)

The issue is **iPhone/Desktop-specific**.

### Hypothesis 1: Session State Mismatch

Each device has its own session with the sender. iPhone may have:
- No session yet (would trigger prekey message flow)
- A stale/different session
- A session established with different identity key

If iPhone's session state differs from signal-go's linked device, decryption could fail silently.

### Hypothesis 2: Decryption Failure → Silent Drop

If iPhone fails to decrypt:
1. It should send a retry receipt (DecryptionErrorMessage)
2. But retry receipts use sealed sender
3. signal-go can't decrypt sealed sender receipts yet
4. We never see the retry request

This creates a silent failure loop: iPhone can't decrypt, signal-go can't receive the retry.

### Hypothesis 3: Unknown Sender Handling

When iPhone receives a message from an unknown ACI:
- It needs to create a new conversation
- It may require certain fields (profile key, etc.)
- It may have stricter validation than signal-go

### Original Hypothesis: ACI vs PNI Identity Problem

Signal has two identities per account:
- **ACI (Account Identity)**: Primary identity, stable over account lifetime
- **PNI (Phone Number Identity)**: Identity tied to phone number, may change if number changes

**Discovery flow:**
1. iPhone user adds signal-go's **phone number** to contacts
2. Signal performs CDSI lookup, gets signal-go's **PNI**
3. iPhone creates a conversation associated with the **PNI**
4. When signal-go replies, it sends from its **ACI**
5. iPhone doesn't recognize the ACI → message doesn't appear in the conversation

**Note:** This hypothesis may not fully explain the issue if the iPhone has never contacted the sender before.

### The PniSignatureMessage Solution

Signal-Android includes a `PniSignatureMessage` when the recipient discovered you via phone number. From `SignalServiceMessageSender.java:909-915`:

```java
private PniSignatureMessage createPniSignatureMessage() {
    byte[] signature = localPniIdentity.signAlternateIdentity(aciStore.getIdentityKeyPair().getPublicKey());

    return new PniSignatureMessage.Builder()
                                  .pni(UuidUtil.toByteString(localPni.getRawUuid()))
                                  .signature(ByteString.of(signature))
                                  .build();
}
```

The `PniSignatureMessage` contains:
- `pni`: The sender's PNI UUID as bytes
- `signature`: A signature *by* the PNI identity private key *of* the ACI identity public key

This proves to the recipient that the ACI and PNI belong to the same person, allowing them to merge the identities.

### The Protobuf Structure

From `SignalService.proto:890-894`:
```protobuf
message PniSignatureMessage {
  optional bytes pni = 1;
  // Signature *by* the PNI identity key *of* the ACI identity key
  optional bytes signature = 2;
}
```

This is included in `Content` as field 10:
```protobuf
message Content {
  optional DataMessage dataMessage = 1;
  // ...
  optional PniSignatureMessage pniSignatureMessage = 10;
}
```

## Implementation Plan

### Task 1: Add `SignAlternateIdentity` to libsignal bindings

Need to add a CGO binding for the libsignal function that signs the ACI public key with the PNI private key.

**File:** `internal/libsignal/identitykey.go`

```go
// SignAlternateIdentity creates a signature over another identity key's public key.
// Used to prove that two identities (ACI and PNI) belong to the same account.
func (ikp *IdentityKeyPair) SignAlternateIdentity(otherPublicKey *PublicKey) ([]byte, error)
```

### Task 2: Create PniSignatureMessage in sender

Modify `internal/signalservice/sender.go` to include `PniSignatureMessage` when sending.

```go
func createPniSignatureMessage(st *store.Store) (*proto.PniSignatureMessage, error) {
    // Get PNI UUID
    acct, err := st.LoadAccount()
    if err != nil {
        return nil, err
    }
    pni := acct.PNI

    // Get PNI identity key pair
    st.UsePNI(true)
    pniIdentity, err := st.GetIdentityKeyPair()
    st.UsePNI(false)

    // Get ACI identity public key
    aciIdentity, err := st.GetIdentityKeyPair()
    aciPublic, err := aciIdentity.PublicKey()

    // Sign ACI public key with PNI private key
    signature, err := pniIdentity.SignAlternateIdentity(aciPublic)

    return &proto.PniSignatureMessage{
        Pni:       uuidToBytes(pni),
        Signature: signature,
    }, nil
}
```

### Task 3: Add --pni-signature flag or auto-detect

Either:
- Add a flag to explicitly include PNI signature
- Detect when recipient only knows us via PNI (based on how they discovered us)

For now, always including the PNI signature should be safe - it's just extra data.

## Verification Steps

1. Add the libsignal binding for `SignAlternateIdentity`
2. Modify sender to include `PniSignatureMessage` in Content
3. Send test message to iPhone
4. Verify message appears on iPhone

## Status

- [x] Problem identified: ACI/PNI identity mismatch
- [x] Solution identified: PniSignatureMessage
- [x] Task 1: Add SignAlternateIdentity binding (`internal/libsignal/identitykey.go`)
- [x] Task 2: Modify sender to include PniSignatureMessage (`internal/signalservice/sender.go`)
- [ ] Task 3: Test with iPhone

## Technical Notes

### How Signal-Android tracks PNI signature needs

Signal-Android has a `needsPniSignature` flag on recipients:
- Set when you discover someone via phone number (CDSI) before they've sent you a message
- Cleared after successful session establishment with PNI signature included
- Stored in `pendingPniSignatureMessages` database table

### Why signal-cli works

signal-cli may work because:
1. The contact was already established with ACI (not just PNI)
2. signal-cli may be including PNI signatures
3. The conversation already had session state

### Alternative: Send as PNI

Instead of including a PNI signature, we could send the message as if we were the PNI identity. However, this is not recommended because:
1. Auth header must still use ACI (server requirement)
2. It would create session confusion on the recipient side
3. It doesn't match Signal-Android behavior

## Files to Modify

| File | Change |
|------|--------|
| `internal/libsignal/identitykey.go` | Add SignAlternateIdentity binding |
| `internal/signalservice/sender.go` | Create and include PniSignatureMessage |
| `client.go` | Optionally add method to check if PNI signature needed |

## Next Investigation Steps

### 1. Verify Sealed Sender Retry Loop

Check if iPhone is sending retry receipts that signal-go can't process:
- Enable verbose logging on signal-go receiver
- Look for incoming sealed sender envelopes after sending a message
- If retry receipts are being sent, fixing sealed sender decryption (Phase 4) may reveal the actual error

### 2. Compare Session State

When signal-go sends to recipient with multiple devices:
- Each device should have its own session established
- Check if prekey messages are sent to each device
- Verify that iPhone's device is in the device list

### 3. Test with signal-cli as Baseline

Send the same message using signal-cli to the same recipient:
- Does iPhone receive it?
- Compare the Content protobuf structure
- Compare envelope fields

### 4. Capture and Compare Raw Messages

On signal-go linked device (which receives successfully):
- Dump the raw envelope before decryption
- Compare with what iPhone should receive

### 5. Check iPhone Console Logs

If possible, check iPhone's Signal logs (requires jailbreak or debug build):
- Look for decryption errors
- Look for message filtering logs

## Signal-Desktop Message Filtering Points

When debugging why messages don't appear on Desktop, these are the key locations where incoming messages can be discarded:

### Message Receiver (`ts/textsecure/MessageReceiver.preload.ts`)

| Line | Condition | Description |
|------|-----------|-------------|
| ~1330 | `sourceServiceId` is PNI + sealed sender | **Drops non-receipt envelopes from PNI** - most likely culprit for ACI/PNI mismatch |
| ~1345 | Envelope destined for PNI | Drops normal messages addressed to PNI identity |
| ~1603-1605 | Sender is blocked | Drops messages from blocked contacts |
| ~2483-2486 | Group is blocked | Drops messages from blocked groups |
| ~2765-2766 | Calling message from blocked sender | Drops call-related messages |

### PniSignatureMessage Handler (`ts/textsecure/MessageReceiver.preload.ts:~2706`)

```typescript
#handlePniSignatureMessage(envelope, pniSignatureMessage)
```
- Verifies PNI signature using `window.ConversationController.maybeMergeContacts()`
- Merges ACI and PNI identities if signature is valid
- Does NOT block message processing - allows DataMessage to continue

### Data Message Handler (`ts/messages/handleDataMessage.preload.ts`)

| Line | Condition | Description |
|------|-----------|-------------|
| ~313-324 | Sender e164 or serviceId is blocked | Drops from blocked sender |
| ~330-341 | Not a member of GroupV2 | Drops if sender not in group |
| ~349-360 | Not a member of GroupV1 | Drops if sender not in group |
| ~363-369 | Non-admin in announcement-only group | Drops non-admin messages |
| ~431-441 | Story reply without matching story | Drops orphaned story replies |

### Background Event Handler (`ts/background.preload.ts`)

- Line ~619-733: Event listeners registered for `messageReceiver.addEventListener('message', ...)`
- Line ~2391: `onMessageReceived()` - main entry point for message processing

### Message Flow Summary

```
WebSocket → MessageReceiver.handleRequest()
         → decryptEnvelope() / unsealEnvelope()
         → #handleContent()
            ├── #handlePniSignatureMessage() [merges identities]
            └── #handleDataMessage()
                → handleDataMessage.preload.ts
                   → saveAndNotify()
                      → conversation.onNewMessage()
```

### Key Investigation Points

1. **PNI filtering (line ~1330)**: If signal-go sends with ACI but recipient only knows PNI, the envelope's `sourceServiceId` won't match any known conversation
2. **Identity merge**: Even with `PniSignatureMessage`, the merge must happen *before* the message is routed to a conversation
3. **Conversation lookup**: Desktop may fail to find the conversation if ACI isn't linked to PNI yet

### Debug Strategy

To add debug logging in Signal-Desktop:

1. In `MessageReceiver.preload.ts`, log at line ~384 (all incoming requests)
2. Log envelope `sourceServiceId` and `destinationServiceId` after decryption
3. Log before each "dropping" statement to see which filter triggers
4. In `handleDataMessage.preload.ts`, log at line ~809 before `saveAndNotify()`

## Signal-Android vs signal-go Sending Comparison

### Encryption Paths (from EnvelopeContent.java)

**Signal-Android with Sealed Sender:**
```
Content → pad → sessionCipher.encrypt() → UnidentifiedSenderMessageContent
        → sealedSessionCipher.encrypt() → UNIDENTIFIED_SENDER envelope
```

**Signal-Android without Sealed Sender (and signal-go):**
```
Content → pad → sessionCipher.encrypt() → PREKEY_BUNDLE/CIPHERTEXT envelope
```

Both paths use identical inner encryption. The difference is:
- Sealed sender wraps ciphertext with sender identity encrypted
- Unsealed sender exposes sender identity in envelope metadata

**signal-go uses unsealed sender**, which is valid. Recipients should handle both.

### When Signal-Android Uses Sealed Sender

From `MessageApi.kt`:
- If `SealedSenderAccess` is provided → use unauthenticated WebSocket with sealed sender
- Falls back to authenticated (unsealed) on 401 error
- `SealedSenderAccess` requires: sender certificate + recipient's unidentified access key

signal-go doesn't have sender certificates or unidentified access keys implemented, so it correctly uses unsealed sender.

## References

- `Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/SignalServiceMessageSender.java:909-915` - createPniSignatureMessage
- `Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/crypto/EnvelopeContent.java` - Sealed vs unsealed sender encryption paths
- `Signal-Android/lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/message/MessageApi.kt` - Message sending with fallback
- `Signal-Android/app/src/main/java/org/thoughtcrime/securesms/jobs/IndividualSendJob.java:368` - includePniSignature usage
- `Signal-Desktop/ts/textsecure/MessageReceiver.preload.ts` - Main message processing pipeline
- `Signal-Desktop/ts/messages/handleDataMessage.preload.ts` - Data message filtering and persistence
