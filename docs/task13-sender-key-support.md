# Task 13: Sender Key Support (Group Message Decryption)

## Status: Complete

## Problem

When receiving group messages, the receiver fails with:
```
Error: receiver: sealed sender: unsupported inner message type 7
```

Message type 7 is `CiphertextMessageTypeSenderKey` - used for group messages encrypted with sender keys. Signal uses sender keys for efficient group messaging: instead of encrypting a message N times for N recipients, the sender encrypts once with a symmetric sender key that all group members share.

## Background

### Sender Key Protocol

1. **Distribution**: Before sending to a group, the sender creates a `SenderKeyDistributionMessage` and sends it to all group members via regular 1:1 encryption
2. **Storage**: Recipients process the distribution message and store the sender key record keyed by `(sender_address, distribution_id)`
3. **Encryption**: Group messages are encrypted with the sender key (type 7)
4. **Decryption**: Recipients decrypt using `signal_group_decrypt_message` with the stored sender key

### Current State

- `receiver.go:251-283` handles types 2 (Whisper) and 3 (PreKey), but not type 7 (SenderKey)
- No `SenderKeyStore` interface exists
- No CGO bindings for `signal_group_decrypt_message`
- No SQLite storage for sender key records

## Solution

Implement sender key support in four layers:

### 1. CGO Bindings (`internal/libsignal/senderkey.go`)

Add bindings for:
- `SenderKeyRecord` - wrapper for sender key state
- `SenderKeyDistributionMessage` - wrapper for distribution messages
- `GroupDecryptMessage()` - calls `signal_group_decrypt_message`
- `ProcessSenderKeyDistributionMessage()` - calls `signal_process_sender_key_distribution_message`
- `DeserializeSenderKeyDistributionMessage()` - deserialize from bytes

FFI signatures from `libsignal-ffi.h`:
```c
SignalFfiError *signal_group_decrypt_message(
    SignalOwnedBuffer *out,
    SignalConstPointerProtocolAddress sender,
    SignalBorrowedBuffer message,
    SignalConstPointerFfiSenderKeyStoreStruct store
);

SignalFfiError *signal_process_sender_key_distribution_message(
    SignalConstPointerProtocolAddress sender,
    SignalConstPointerSenderKeyDistributionMessage sender_key_distribution_message,
    SignalConstPointerFfiSenderKeyStoreStruct store
);

SignalFfiError *signal_sender_key_distribution_message_deserialize(
    SignalMutPointerSenderKeyDistributionMessage *out,
    SignalBorrowedBuffer data
);
```

### 2. Store Interface (`internal/libsignal/store.go`)

Add `SenderKeyStore` interface:
```go
// SenderKeyStore stores sender key records for group messaging.
type SenderKeyStore interface {
    LoadSenderKey(sender *Address, distributionID [16]byte) (*SenderKeyRecord, error)
    StoreSenderKey(sender *Address, distributionID [16]byte, record *SenderKeyRecord) error
}
```

### 3. CGO Callbacks (`internal/libsignal/callbacks.go`)

Add callback wrappers for `SenderKeyStore`:
- `bridge_load_sender_key` - C callback that invokes Go's `LoadSenderKey`
- `bridge_store_sender_key` - C callback that invokes Go's `StoreSenderKey`
- `wrapSenderKeyStore()` - creates `SignalSenderKeyStore` struct with pinned callbacks

Callback signatures from FFI:
```c
typedef int (*SignalFfiBridgeSenderKeyStoreLoadSenderKey)(
    void *ctx,
    SignalMutPointerSenderKeyRecord *out,
    SignalMutPointerProtocolAddress sender,
    SignalUuid distribution_id
);

typedef int (*SignalFfiBridgeSenderKeyStoreStoreSenderKey)(
    void *ctx,
    SignalMutPointerProtocolAddress sender,
    SignalUuid distribution_id,
    SignalMutPointerSenderKeyRecord record
);
```

### 4. SQLite Storage (`internal/store/senderkey.go`)

Add `sender_keys` table and implement `SenderKeyStore`:
```sql
CREATE TABLE IF NOT EXISTS sender_keys (
    sender_aci TEXT NOT NULL,
    sender_device INTEGER NOT NULL,
    distribution_id BLOB NOT NULL,
    record BLOB NOT NULL,
    updated_at INTEGER NOT NULL,
    PRIMARY KEY (sender_aci, sender_device, distribution_id)
);
```

### 5. Receiver Integration (`internal/signalservice/receiver.go`)

#### Handle Type 7 Messages

Add case in `decryptEnvelope()`:
```go
case libsignal.CiphertextMessageTypeSenderKey:
    logf(logger, "sealed sender: decrypting inner sender key message")
    plaintext, err = libsignal.GroupDecryptMessage(innerContent, addr, st)
    if err != nil {
        sendRetryReceiptAsync(ctx, rc, senderACI, senderDevice, innerContent, msgType, env.GetTimestamp())
        return nil, fmt.Errorf("sealed sender decrypt sender key: %w", err)
    }
```

#### Process Distribution Messages

After decrypting any message, check for `Content.SenderKeyDistributionMessage`:
```go
if skdm := content.GetSenderKeyDistributionMessage(); len(skdm) > 0 {
    if err := processSenderKeyDistribution(senderACI, senderDevice, skdm, st); err != nil {
        logf(logger, "failed to process sender key distribution: %v", err)
        // Don't fail the message - distribution can be retried
    }
}
```

## Implementation Order

1. **`internal/libsignal/senderkey.go`** - SenderKeyRecord, SenderKeyDistributionMessage wrappers
2. **`internal/libsignal/store.go`** - Add SenderKeyStore interface
3. **`internal/libsignal/callbacks.go`** - Add wrapSenderKeyStore and C bridge functions
4. **`internal/libsignal/bridge.c`** - Add bridge_load_sender_key, bridge_store_sender_key
5. **`internal/libsignal/memstore.go`** - Add in-memory SenderKeyStore for testing
6. **`internal/libsignal/senderkey_test.go`** - Test CGO bindings
7. **`internal/store/senderkey.go`** - SQLite implementation
8. **`internal/store/store.go`** - Add migration for sender_keys table
9. **`internal/signalservice/receiver.go`** - Handle type 7 and distribution messages

## Testing

1. **Unit tests** for CGO bindings (create, serialize, deserialize sender key records)
2. **Unit tests** for SQLite store (load, store, update sender keys)
3. **Integration test** with captured type 7 message from `debug-me/` dumps

## Files Changed

| File | Changes |
|------|---------|
| `internal/libsignal/senderkey.go` | New - SenderKeyRecord, SenderKeyDistributionMessage, GroupDecryptMessage |
| `internal/libsignal/store.go` | Add SenderKeyStore interface |
| `internal/libsignal/callbacks.go` | Add wrapSenderKeyStore, bridge callbacks |
| `internal/libsignal/bridge.c` | Add bridge_load_sender_key, bridge_store_sender_key |
| `internal/libsignal/memstore.go` | Add MemSenderKeyStore |
| `internal/libsignal/senderkey_test.go` | New - CGO binding tests |
| `internal/store/senderkey.go` | New - SQLite SenderKeyStore |
| `internal/store/store.go` | Add sender_keys table migration |
| `internal/signalservice/receiver.go` | Handle type 7, process distribution messages |

## Signal-Android Reference

- `app/src/main/java/org/thoughtcrime/securesms/database/SenderKeyDatabase.java` - SQLite storage
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/crypto/SignalGroupCipher.java` - GroupCipher wrapper
- `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/crypto/SignalGroupSessionBuilder.java` - Distribution message processing

## Notes

- Distribution ID is a UUID (16 bytes) that identifies the sender key session
- Sender keys are rotated periodically; old keys may be kept for decrypting delayed messages
- If decryption fails due to missing sender key, a retry receipt should trigger re-distribution

## Implementation Summary

### Files Created

- `internal/libsignal/senderkey.go` - CGO bindings for:
  - `SenderKeyRecord` - wrapper with Serialize/Deserialize
  - `SenderKeyDistributionMessage` - wrapper with Serialize/Deserialize
  - `GroupDecryptMessage()` - decrypts sender key messages
  - `ProcessSenderKeyDistributionMessage()` - processes distribution messages
- `internal/libsignal/senderkey_test.go` - Unit tests
- `internal/store/senderkey.go` - SQLite `SenderKeyStore` implementation
- `internal/store/senderkey_test.go` - Storage tests

### Files Modified

- `internal/libsignal/store.go` - Added `SenderKeyStore` interface
- `internal/libsignal/callbacks.go` - Added sender key store callbacks (`goLoadSenderKey`, `goStoreSenderKey`, `wrapSenderKeyStore`)
- `internal/libsignal/bridge.c` - Added C bridge functions (`bridge_load_sender_key`, `bridge_store_sender_key`)
- `internal/libsignal/memstore.go` - Added `MemorySenderKeyStore`
- `internal/store/store.go` - Added `sender_key` table to schema and interface check
- `internal/signalservice/receiver.go` - Added:
  - Type 7 (SenderKey) handling in `decryptEnvelope()`
  - `processSenderKeyDistribution()` function
  - Processing of `Content.SenderKeyDistributionMessage`

### Behavior

1. **Receiving distribution messages**: When a message contains `SenderKeyDistributionMessage`, it's processed via `ProcessSenderKeyDistributionMessage()` which stores the sender key in the database.

2. **Decrypting group messages**: When a sealed sender message has inner type 7 (SenderKey), it's decrypted via `GroupDecryptMessage()` using the stored sender key.

3. **Error handling**: If decryption fails (e.g., missing sender key), a retry receipt is sent to trigger re-distribution.
