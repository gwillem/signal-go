# Task 15: Sealed Sender v2 (Multi-Recipient Encrypt) + Group Send Endorsements

## Status: In Progress

## Goal

Replace per-recipient sealed sender v1 fanout for group messages with:
1. Multi-recipient encrypt (SSv2) — single `PUT /v1/messages/multi_recipient` with binary MRM
2. Group send endorsements — `Group-Send-Token` header instead of per-recipient `Unidentified-Access-Key`
3. SKDM tracking — only send sender key distribution to new/unknown members
4. Fix ContentHint to IMPLICIT (2) for group messages (Signal-Android parity)
5. Increase max retry attempts from 3 to 4 (Signal-Android parity)

## v1 vs v2 — Both Kept

- **v1** (`sealed_session_cipher_encrypt`): 1:1 messages, per-recipient `PUT /v1/messages/{uuid}` (JSON)
- **v2** (`multi_recipient_encrypt`): Group messages, single `PUT /v1/messages/multi_recipient` (binary MRM)

Signal-Android uses v1 for all 1:1 sends. No fallback from v2 to v1 for groups.

## Signal-Android Parity Fixes

| Current signal-go | Signal-Android | Fix |
|---|---|---|
| ContentHint = RESENDABLE (1) for group messages | ContentHint = IMPLICIT (2) for all group + SKDM | Change in `createSenderKeyUSMC` and SKDM send |
| SKDM sent to ALL members every time | SKDM tracked per distributionId, only sent to new/unknown | Add SKDM tracking (sender_key_shared table) |
| Max 3 retry attempts on 409/410 | Max 4 retry attempts (`RETRY_COUNT = 4`) | Change constant |
| Per-recipient v1 sealed sender fanout | Single multi_recipient_encrypt + `PUT /v1/messages/multi_recipient` | This task |
| `Unidentified-Access-Key` header | `Group-Send-Token` header (group send endorsements) | This task |

## Architecture Overview

```
FetchGroupDetails (existing, modified)
  └→ GET /v2/groups/ → GroupResponse { Group, GroupSendEndorsementsResponse }
       └→ Store raw endorsements_response + expiration on Group

SendGroupMessage (rewritten)
  1. Check/refresh endorsements if expired
  2. Compute needsSenderKey targets (destinations NOT in sharedWith OR no session)
  3. Send SKDM only to needsSenderKey targets
  4. receive_and_combine_with_service_ids() → per-member endorsements
  5. combine(recipientEndorsements) → combined endorsement
  6. endorsement_to_token → token_to_full_token → Group-Send-Token header
  7. multi_recipient_encrypt(recipients, sessions, usmc, identityStore) → MRM blob
  8. PUT /v1/messages/multi_recipient (binary, Group-Send-Token header)
  9. On 409: archive extra devices, fetch prekeys for missing → retry (up to 4x)
  10. On 410: archive stale devices → retry (up to 4x)
  11. archiveSession also clears SKDM sharedWith tracking for that address
```

## Implementation Steps

### Step 1: CGO bindings for multi-recipient encrypt

**File**: `internal/libsignal/sealedsender.go`

```go
func SealedSenderMultiRecipientEncrypt(
    recipients []*Address,
    sessions []*SessionRecord,
    content *UnidentifiedSenderMessageContent,
    identityStore IdentityKeyStore,
) ([]byte, error)
```

FFI: `signal_sealed_sender_multi_recipient_encrypt`

Also:
```go
func SealedSenderMultiRecipientMessageForSingleRecipient(encoded []byte) ([]byte, error)
```

**Signal-Android ref**: `SignalSealedSessionCipher.multiRecipientEncrypt()`

### Step 2: CGO bindings for Group Send Endorsements

**File**: `internal/libsignal/endorsement.go` (new)

4 FFI functions:
- `ReceiveEndorsements` — validates server response, returns per-member endorsement blobs
- `EndorsementExpiration` — gets expiration from response
- `CombineEndorsements` — combines per-member endorsements into one
- `EndorsementToFullToken` — converts endorsement to Group-Send-Token

**Signal-Android ref**: `GroupsV2Operations.receiveGroupSendEndorsements()`, `GroupSendEndorsements.serialize()`

### Step 3: Store endorsements + SKDM tracking

- Add `endorsements_response BLOB` and `endorsements_expiry INTEGER` to groups table (migration)
- Create `sender_key_shared` table for SKDM tracking
- Add `GetSenderKeySharedWith`, `MarkSenderKeySharedWith`, `ClearSenderKeySharedWith` to store
- `ArchiveSession` also clears SKDM tracking

### Step 4: Capture endorsements during group fetch

Modify `FetchGroupDetails` to store `GroupSendEndorsementsResponse` and compute expiration.

### Step 5: HTTP transport for multi_recipient endpoint

- Add `PutBinary` to Transport (raw binary body with custom headers)
- Add `SendMultiRecipientMessage` to Service
- Add group-level error/response types to httptypes.go

### Step 6: Group-level device retry

Add `withGroupDeviceRetry` to `deviceretry.go` — handles multi-recipient 409/410 errors with multiple UUIDs.

### Step 7: Refactor SendGroupMessage for v2

Rewrite group send flow:
1. Check/refresh endorsements
2. Send SKDM only to new members (tracked)
3. Compute Group-Send-Token from endorsements
4. Multi-recipient encrypt → MRM blob
5. Single PUT to `/v1/messages/multi_recipient`
6. Fix ContentHint to IMPLICIT (2)

## Files Summary

| File | Change |
|------|--------|
| `internal/libsignal/sealedsender.go` | Add `SealedSenderMultiRecipientEncrypt`, `...ForSingleRecipient` |
| `internal/libsignal/endorsement.go` | **New**: endorsement FFI bindings |
| `internal/libsignal/endorsement_test.go` | **New**: endorsement tests |
| `internal/libsignal/sealedsender_test.go` | Add multi-recipient encrypt tests |
| `internal/store/store.go` | Add migrations |
| `internal/store/group.go` | Add endorsement fields, update Save/Get |
| `internal/store/senderkey.go` | Add SKDM shared-with tracking |
| `internal/store/senderkey_test.go` | Tests for SKDM tracking |
| `internal/store/session.go` | `ArchiveSession` clears SKDM tracking |
| `internal/signalservice/groupsv2.go` | Capture endorsements in `FetchGroupDetails` |
| `internal/signalservice/groupsender.go` | Rewrite for v2 multi-recipient + endorsements |
| `internal/signalservice/groupsender_test.go` | v2 send flow tests |
| `internal/signalservice/deviceretry.go` | Add `withGroupDeviceRetry` |
| `internal/signalservice/service.go` | Add `SendMultiRecipientMessage` |
| `internal/signalservice/transport.go` | Add `PutBinary` method |
| `internal/signalservice/httptypes.go` | Add group-level error/response types |

## Existing Code to Reuse

| What | Where |
|------|-------|
| `ServerPublicParams`, `GetSignalServerPublicParams()` | `internal/libsignal/authcredential.go` |
| `GroupSecretParams`, `DeriveGroupSecretParams` | `internal/libsignal/zkgroup.go` |
| `GroupResponse.GroupSendEndorsementsResponse` | `internal/proto/Groups.proto:64` |
| `FetchGroupDetails` → `fetchGroup` | `internal/signalservice/groupsv2.go` |
| `wrapIdentityKeyStore` | `internal/libsignal/callbacks.go` |
| `borrowedBuffer`, `freeOwnedBuffer`, `wrapError` | `internal/libsignal/error.go` |
| `parseUUID` | `internal/signalservice/groupsv2.go` |
| `ContentHintImplicit = 2` | `internal/libsignal/sealedsender.go` |

## Known Issues

### Endorsement expiry shows 1970 timestamp — FIXED

`signal_group_send_endorsements_response_get_expiration` returns **seconds** since epoch, not milliseconds. Was using `time.UnixMilli()` instead of `time.Unix()`. Fixed in `groupsv2.go`. This caused endorsements to appear always-expired, triggering a full group fetch on every send.

### Desktop doesn't receive group messages — FIXED

Desktop received the MRM but couldn't decrypt because it didn't have the sender key. Three issues:

1. **SKDM tracking was premature**: We marked SKDM as "shared" after the HTTP send succeeded, but that only means the server accepted it — not that the recipient stored it. Fixed by always re-sending SKDM on every group send (no tracking). A persistent connection can add proper delivery-confirmed tracking later.

2. **Sealed sender retry receipts weren't processed**: When a retry receipt arrived via sealed sender (inner type `CiphertextMessageTypePlaintext`), the code set `plaintext = innerContent` and fell through to `pb.Unmarshal` as a `Content` protobuf. But `innerContent` is a `PlaintextContent` wrapper — so it parsed as empty and the retry was silently dropped. Fixed by routing to `handlePlaintextContent` instead.

3. **Stale sessions caused SKDM decryption failure**: Without a persistent receive loop, the CLI tool can't process retry receipts that would fix broken sessions. If the Double Ratchet state between signal-go and a recipient device is out of sync, the SKDM (encrypted via the session) can't be decrypted, so the sender key is never received. Fixed by archiving all recipient sessions before SKDM send, forcing fresh PreKey establishment. This consumes one-time pre-keys but guarantees the SKDM is decryptable.

### Desktop rejects SKDM with "Stringified UUID is invalid" — FIXED

Desktop's sender key store callback validates UUID format. The distribution ID was derived from `groupIdentifier[:16]` (first 16 bytes of the 32-byte group identifier), producing a UUID with invalid version bits (e.g. version nibble 0xC instead of 0x4). Signal-Android uses a **random UUID v4** per group, stored in the database — not derived from the group identifier.

Fix: Added `distribution_id` column to groups table, generate a random UUID v4 on first use via `GenerateDistributionID()`, persist it, and use it for all sender key operations. Desktop now receives a valid UUID and can store/lookup the sender key correctly.

## Verification

1. `make test` — all existing + new tests pass
2. Integration: `go run ./cmd/sgnl -v -a +31626439999 send-group <group-id> "test v2"`
   - Logs show `PUT /v1/messages/multi_recipient` (not per-recipient sends)
   - Logs show `Group-Send-Token` header (not `Unidentified-Access-Key`)
   - ContentHint = IMPLICIT in USMC
   - SKDM only sent to members who haven't received it
3. Verify sync message still works
4. Verify second send to same group does NOT re-send SKDM
