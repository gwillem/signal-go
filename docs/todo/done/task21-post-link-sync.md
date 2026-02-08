# Task 21: Auto-sync contacts and groups after Link/Register

## Status: Done

## Problem

After `Link()` or `Register()` completes, the local store has no contacts or groups. The user must manually run `sync-contacts` and `sync-groups` before phone number sending works. This is a footgun — Signal-Android auto-syncs after provisioning.

## Solution

Fire-and-forget: trigger contact sync request and group sync from Storage Service at the end of `Link()` and `Register()`. The contact sync response arrives asynchronously via the WebSocket when the user starts `Receive()`. Group sync from Storage Service is synchronous (HTTP calls).

## Design Decisions

- **Fire-and-forget for contacts**: `RequestContactSync` sends a sync request message; the actual contact data arrives later via WebSocket. This is fine — by the time the user wants to send, they'll have started `Receive()`.
- **Synchronous for groups**: `SyncGroupsFromStorage` fetches from Storage Service via HTTP and can complete inline.
- **Best-effort**: Sync failures are logged but don't fail `Link()`/`Register()`. The user can always manually sync later.
- **Skip BLOCKED/CONFIGURATION**: Not critical for basic functionality; we don't act on these settings yet.

## Implementation

### 1. Call `initService()` at end of `Link()` (`client.go`)

Currently `Link()` does not call `initService()`, so `c.service` is nil after linking. Add `c.initService()` before the sync calls.

### 2. Add `postLinkSync()` helper (`client.go`)

```go
// postLinkSync triggers contact and group sync after linking or registration.
// Errors are logged but not returned — sync can be retried manually.
func (c *Client) postLinkSync(ctx context.Context) {
    if err := c.service.RequestContactSync(ctx); err != nil {
        logf(c.logger, "post-link contact sync request failed: %v", err)
    }
    if n, err := c.service.SyncGroupsFromStorage(ctx); err != nil {
        logf(c.logger, "post-link group sync failed: %v", err)
    } else {
        logf(c.logger, "post-link group sync: %d groups", n)
    }
}
```

### 3. Call from `Link()` and `Register()` (`client.go`)

At the end of both methods, after `saveAccount()`:

```go
c.initService()
c.postLinkSync(ctx)
return nil
```

For `Link()`, this replaces the current `return c.saveAccount()` — save first, then init service, then sync.

For `Register()`, `initService()` is already called; just add `c.postLinkSync(ctx)` after it.

## Files to modify

| File | Action |
|------|--------|
| `client.go` | Add `postLinkSync()`, call `initService()` + `postLinkSync()` at end of `Link()` and `Register()` |

## Test plan

1. `TestLink_TriggersSyncRequests` — mock service, verify `RequestContactSync` and `SyncGroupsFromStorage` are called after `Link()`
2. `TestLink_SyncFailureDoesNotFailLink` — sync errors are swallowed, `Link()` still succeeds
3. Manual: link device, start receive loop, verify contacts and groups populate without manual sync
