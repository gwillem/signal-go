# Phase 5: Session Decryption Failure Investigation

## Problem Statement

Regular CIPHERTEXT messages fail with session decryption error:
```
envelope type=CIPHERTEXT sender=25e3d605-ee4a-4f48-b24e-a12afa2cb328 device=2 timestamp=1770107873372 contentLen=371
decrypting ciphertext message
Error: receiver: decrypt message: libsignal error 30: invalid Whisper message: decryption failed
```

This is separate from the sealed sender issue (error 10) - this affects the inner session layer.

## Error Analysis

### What Error 30 Means for Whisper Messages

Error 30 in `DecryptMessage` (not sealed sender) indicates:
- MAC verification failed on the message
- The message couldn't be decrypted with the current session ratchet state
- Session chain keys are out of sync between sender and receiver

### Signal Message Decryption Flow

```
SignalMessage → SessionRecord → Chain Key → Decrypt → MAC Verify → Plaintext
                    ↑
            If chain key wrong → MAC fails → Error 30
```

### Common Causes

1. **Session Desync**: Missed messages caused ratchet to diverge
2. **Stale Session**: Sender re-established session, receiver has old one
3. **Database Corruption**: Session record corrupted or partially written
4. **Device Replacement**: Re-linked device has no session, but sender thinks one exists

## Relationship to Sealed Sender Issue

These may be connected:

| Scenario | Sealed Sender | Regular CIPHERTEXT |
|----------|--------------|-------------------|
| Identity key mismatch | Fails at outer layer (error 10/30) | N/A (no identity ECDH) |
| Session mismatch | Fails at inner layer | Fails at session layer (error 30) |
| No session exists | Inner decrypt fails | `LoadSession` returns nil |

If the device was re-linked:
1. **Identity key**: Comes from primary device (should be correct)
2. **Sessions**: Start empty after re-link (no sessions)
3. **Senders**: May still have old sessions cached

When sender sends:
- **With sealed sender**: Outer layer uses identity key → may fail if stale
- **Without sealed sender**: Uses session directly → fails if no matching session

## Investigation Steps

### Step 1: Check Session State

Query the sessions table for this sender:
```sql
SELECT address, device_id, length(record) as record_len
FROM session
WHERE address = '25e3d605-ee4a-4f48-b24e-a12afa2cb328';
```

### Step 2: Check if Session Exists

If no session exists, the sender is using an old session that was deleted when you re-linked.

### Step 3: Add Diagnostic Logging

**File: `internal/signalservice/receiver.go`**

Before DecryptMessage, log session state:
```go
session, err := st.LoadSession(addr)
if err != nil {
    logf(logger, "session load error: %v", err)
} else if session == nil {
    logf(logger, "no session exists for sender=%s device=%d", senderACI, senderDevice)
} else {
    logf(logger, "session exists for sender=%s device=%d", senderACI, senderDevice)
}
```

### Step 4: Protocol-Level Fix

The proper fix is to send a **retry receipt** (DecryptionErrorMessage) back to the sender. This tells them:
- "I couldn't decrypt your message"
- "Please re-establish session and resend"

Current code only sends retry receipts for sealed sender inner failures, not for regular CIPHERTEXT failures.

## Proposed Solution

### Option A: Add Retry Receipt for CIPHERTEXT Failures

Modify `receiver.go` to send retry receipt when CIPHERTEXT decrypt fails:

```go
case proto.Envelope_CIPHERTEXT:
    logf(logger, "decrypting ciphertext message")
    sigMsg, err := libsignal.DeserializeSignalMessage(content)
    if err != nil {
        return nil, fmt.Errorf("deserialize signal message: %w", err)
    }
    defer sigMsg.Destroy()

    plaintext, err = libsignal.DecryptMessage(sigMsg, addr, st, st)
    if err != nil {
        // NEW: Send retry receipt for CIPHERTEXT failures
        sendRetryReceiptAsync(ctx, rc, senderACI, senderDevice, content,
            libsignal.CiphertextMessageTypeWhisper, env.GetTimestamp())
        return nil, fmt.Errorf("decrypt message: %w", err)
    }
```

### Option B: Archive Session and Request Re-establishment

When decrypt fails, archive the broken session and send a null message to trigger re-key:

```go
if err != nil {
    // Archive broken session
    st.ArchiveSession(addr)
    // Send null message to trigger session re-establishment
    go SendNullMessage(ctx, apiURL, st, auth, tlsConf, senderACI, senderDevice, logger)
    return nil, fmt.Errorf("decrypt message: %w", err)
}
```

## Files to Modify

| File | Change |
|------|--------|
| `internal/signalservice/receiver.go` | Add retry receipt for CIPHERTEXT failures |
| `internal/signalservice/receiver.go` | Add session state logging |

## Status

- [ ] Add session state diagnostic logging
- [ ] Add retry receipt for CIPHERTEXT decrypt failures
- [ ] Test with real failing messages
- [ ] Verify sender re-establishes session after retry receipt

## Related

- [Task 04: Sealed Sender Investigation](task04-sealed-sender.md) - Outer layer failures
- Signal Protocol retry receipt flow in `retryreceipt.go`
