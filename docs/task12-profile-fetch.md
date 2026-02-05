# Phase 12: Automatic Profile Fetching for Unknown Senders

## Status: Complete

## Problem

When receiving messages, the CLI displays sender ACIs (UUIDs) instead of human-readable names:

```
[2026-02-05 12:33:48] d7931635-28d9-49f3-b3d6-246245652744: Hello!
```

Names are only available if the sender is in the local contact store (populated via `sgnl synccontacts`). However, many senders include their **profile key** in messages, which allows us to fetch their profile (including their display name) from Signal's servers.

## Current Behavior

1. Message envelope contains only sender ACI (UUID)
2. `populateContactInfo()` looks up contact by ACI in local store
3. If contact exists and has a name, it's used; otherwise ACI is displayed
4. Profile keys from incoming messages ARE saved (`saveContactProfileKey()`)
5. Profile fetching capability exists (`GetProfile()` + `ProfileCipher`)

## Solution

When receiving a message from a sender without a cached name, but with a stored profile key:

1. Fetch their profile from Signal servers using `GetProfile()`
2. Decrypt the profile name using `ProfileCipher`
3. Cache the name in the contact store
4. Populate the message's `SenderName` field

### Implementation Steps

1. **Add helper function** `fetchAndCacheProfileName()` in `receiver.go`:
   - Takes ACI and store
   - Checks if we have a profile key but no name
   - Fetches profile from server
   - Decrypts and caches name
   - Returns the name (or empty string on failure)

2. **Update `populateContactInfo()`** to call the helper when name is missing

3. **Rate limiting consideration**: Profile fetches are network calls; avoid hammering the server for the same unknown sender

## Signal-Android Reference

Signal-Android fetches profiles in `RecipientDatabaseTable.java` and `ProfileService.java`. The profile fetch uses:
- Endpoint: `GET /v1/profile/{aci}/{version}`
- Authentication: Standard auth headers
- Response: Encrypted profile fields (name, about, avatar, etc.)

## Data Flow

```
Message received
    │
    ▼
populateContactInfo(msg, st)
    │
    ├─ Contact exists with name? → Use cached name
    │
    ├─ Contact has profile key but no name?
    │       │
    │       ▼
    │   fetchAndCacheProfileName(ctx, aci, st, service)
    │       │
    │       ├─ Fetch profile from server
    │       ├─ Decrypt name with ProfileCipher
    │       ├─ Save name to contact store
    │       └─ Return name
    │
    └─ No profile key? → Display ACI (fallback)
```

## API Details

### GetProfile Response

```json
{
  "name": "base64-encrypted-name",
  "about": "base64-encrypted-about",
  "aboutEmoji": "base64-encrypted-emoji",
  "avatar": "cdn-path-or-empty"
}
```

### Decryption

Profile fields are AES-GCM encrypted with the profile key:
- Format: `[12-byte nonce][ciphertext][16-byte tag]`
- Name is null-padded to 53 or 257 bytes

## Testing

- Unit test for profile fetch + decrypt flow (mock HTTP)
- Integration test with real contact store

## Files Changed

- `internal/signalservice/receiver.go` - Add fetchAndCacheProfileName, update populateContactInfo
- `internal/signalservice/receiver_test.go` - Add tests

## Implementation Summary

### Changes to `receiver.go`

1. **Updated `populateContactInfo()`** to take additional parameters (`ctx`, `service`) and check for profile fetch:
   ```go
   func populateContactInfo(ctx context.Context, msg *Message, st *store.Store, service *Service)
   ```

2. **Added `fetchAndCacheProfileName()`** that:
   - Fetches profile from Signal servers using `GetProfile()`
   - Decrypts the name using `ProfileCipher`
   - Caches the name in the contact store
   - Returns the name (empty string on any failure)

### New Tests

- `TestPopulateContactInfoFetchesProfile` - Verifies profile is fetched and name is cached
- `TestPopulateContactInfoSkipsWhenNameExists` - Verifies no fetch when name already exists
- `TestPopulateContactInfoNoProfileKeyNoFetch` - Verifies no fetch when profile key is missing

### Behavior

When receiving a message from an unknown sender:
1. If contact has `Name` cached → use it
2. If contact has `ProfileKey` but no `Name` → fetch profile, decrypt name, cache it
3. If contact has neither → display ACI (fallback)

Profile names are cached, so subsequent messages from the same sender won't trigger additional fetches.
