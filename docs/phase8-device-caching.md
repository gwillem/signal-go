# Phase 8: Recipient Device Caching

## Status: Complete

## Problem

Currently, every message send starts with only device 1 and relies on the server's 409 (Mismatched Devices) response to discover additional devices:

```
attempt 1: devices=[1] → 409 missing=[2,3,4]
attempt 2: devices=[1,2,3,4] → 200
```

This is inefficient because:
1. **Extra round-trips**: Each send requires at least 2 HTTP requests
2. **Pre-key waste**: Failed attempts still fetch and consume pre-keys
3. **Rate limiting risk**: Repeated pre-key fetches trigger 429 errors (10-minute cooldown)
4. **Latency**: Messages take longer to deliver

Signal-Android maintains a per-recipient device list and updates it based on server responses.

## Goal

Cache known devices per recipient to reduce round-trips and pre-key consumption.

## Design

### Storage Schema

Add a `recipient_devices` table to the SQLite store:

```sql
CREATE TABLE recipient_devices (
    aci TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,  -- Unix timestamp
    PRIMARY KEY (aci, device_id)
);
```

### API

Add methods to `store.Store`:

```go
// GetDevices returns known device IDs for a recipient, ordered by device_id.
// Returns [1] if no devices are cached (primary device fallback).
func (s *Store) GetDevices(aci string) ([]int, error)

// SetDevices replaces the device list for a recipient.
func (s *Store) SetDevices(aci string, deviceIDs []int) error

// AddDevice adds a device to a recipient's list (from 409 missing).
func (s *Store) AddDevice(aci string, deviceID int) error

// RemoveDevice removes a device from a recipient's list (from 410 stale).
func (s *Store) RemoveDevice(aci string, deviceID int) error
```

### Integration Points

1. **sendEncryptedMessage**: Start with cached devices instead of `[1]`
   ```go
   deviceIDs, _ := st.GetDevices(recipient)
   if len(deviceIDs) == 0 {
       deviceIDs = []int{1}
   }
   ```

2. **409 handler**: Add missing devices to cache
   ```go
   for _, deviceID := range mismatchErr.MissingDevices {
       _ = st.AddDevice(recipient, deviceID)
       deviceIDs = append(deviceIDs, deviceID)
   }
   ```

3. **410 handler**: Remove stale devices from cache
   ```go
   for _, deviceID := range staleErr.StaleDevices {
       _ = st.RemoveDevice(recipient, deviceID)
   }
   ```

4. **Successful send (200)**: Persist the working device list
   ```go
   if err == nil {
       _ = st.SetDevices(recipient, deviceIDs)
       return nil
   }
   ```

### Cache Invalidation

Devices can become stale over time (user unlinks device, re-registers, etc.). Options:

1. **Passive invalidation**: Only update on 409/410 responses (simple, current plan)
2. **TTL-based refresh**: Periodically re-discover devices after N days
3. **Full refresh on errors**: Clear cache if send fails after all retries

Start with passive invalidation; add TTL later if needed.

## Signal-Android 409/410 Handling

**Reference:** `SignalServiceMessageSender.java:2791-2838` in `../Signal-Android/lib/libsignal-service/`

Signal-Android's actual behavior is simpler than initially expected:

### 410 Stale Devices

When the server returns 410, it indicates sessions are stale (pre-keys expired or keys rotated):

```java
// From SignalServiceMessageSender.java
for (int staleDeviceId : staleDevices.getStaleDevices()) {
    store.archiveSession(recipient, staleDeviceId);
}
```

**Key insight:** Signal-Android does NOT remove devices from any cache on 410. It only archives the sessions (deletes them from the session store), which forces a fresh pre-key bundle fetch on retry. The device list remains unchanged.

### 409 Mismatched Devices

When the server returns 409, the device list is out of sync:

```java
// Extra devices: archive sessions and remove from send list
for (int extraDeviceId : mismatchedDevices.getExtraDevices()) {
    store.archiveSession(recipient, extraDeviceId);
}

// Missing devices: add to send list (will fetch pre-keys on retry)
for (int missingDeviceId : mismatchedDevices.getMissingDevices()) {
    deviceIds.add(missingDeviceId);
}
```

**Key insight:** For `extra` devices, Signal-Android archives their sessions but also removes them from the current send's device list. For `missing` devices, it adds them to the list.

### Retry Strategy

Signal-Android uses a simple retry loop with no special tracking:

```java
// From SignalServiceMessageSender.java
int retryCount = 0;
while (retryCount < 4) {
    try {
        // ... send message ...
        return;
    } catch (StaleDevicesException e) {
        // Archive sessions, retry
    } catch (MismatchedDevicesException e) {
        // Adjust device list, retry
    }
    retryCount++;
}
```

**No staleSeen tracking:** Signal-Android does NOT track which devices returned 410 to break cycles. It simply retries up to 4 times. If a pathological server keeps returning 410/409, it will exhaust retries and fail.

### Our Implementation

Our implementation in `retryreceipt.go` matches Signal-Android's behavior:

- **410:** Archive sessions for stale devices, do NOT remove from device cache
- **409 extra:** Archive sessions, remove from device list
- **409 missing:** Add to device list
- **After 409:** Persist complete device list via `SetDevices` (ensures cache consistency even if send is cancelled mid-retry)
- **Retry:** Up to 5 attempts, no special cycle detection

**Important:** We persist the device list immediately after handling 409, not just on successful send. This ensures that if the user cancels mid-retry (Ctrl+C) or the send fails for other reasons, the cache still contains the complete updated device list including any default device 1 that was never explicitly cached.

## Implementation Tasks

1. [x] Add `recipient_devices` table migration in `store/store.go`
2. [x] Implement `GetDevices`, `SetDevices`, `AddDevice`, `RemoveDevice`
3. [x] Update `sendEncryptedMessage` to use cached devices
4. [x] Update `sendEncryptedMessageWithDevices` to persist working list
5. [x] Update 409/410 handlers to maintain cache
6. [x] Add tests for device caching
7. [x] Remove debug println statements from `prekeybundle.go` and `sender.go` (done in earlier commit)

## Testing

- Unit tests for store methods
- Integration test: send to multi-device recipient, verify cache populated
- Integration test: simulate 410, verify device removed from cache
- Integration test: subsequent send uses cached devices (no 409 on first attempt)

## Future Considerations

- **Sync from primary**: When linking, could fetch device list from primary device
- **Proactive refresh**: Fetch `/v2/keys/{aci}/*` to get all devices upfront
- **Device metadata**: Store registration IDs to detect re-registrations
