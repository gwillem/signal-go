# Task 19: Decompose Service God Object

## Status: IN PROGRESS (Phases 1-3.5 complete, Phase 4 next)

## Completed

- **Phase 1**: Extracted `internal/signalcrypto/` (stateless crypto utilities)
- **Phase 2**: Changed `Store.PNI()` return type to `libsignal.IdentityKeyStore`
- **Phase 3**: Extracted `Receiver` struct with `receiverDataStore`, `cryptoStore`, `wsConn` interfaces and callback functions. Interfaces in `interfaces.go`. Tests updated.
- **Phase 3.5**: Simplified receiver tests with mocks. `mockDataStore` (in-memory maps) replaces SQLite for data store. Profile tests use callback stubs instead of `httptest.Server` + `NewService`. Envelope tests use mock data store + real crypto store. WebSocket integration tests kept as-is.

## Key Design Insight: Separate Crypto Passthrough from Business Data

Crypto operations need all 6 libsignal store interfaces simultaneously, but Go business logic only calls a few data methods. Solution: hold `cryptoStore` as an opaque passthrough for FFI calls, and `receiverDataStore` (7 methods) for business logic. `*store.Store` satisfies both, but tests can mock each independently.

## Remaining Phases

### Phase 4: Extract Sender type

New `Sender` struct with:
- `dataStore senderDataStore` — LoadAccount, ArchiveSession, GetDevices, SetDevices, GetContactByACI, GetPNIIdentityKeyPair
- `cryptoStore` — SessionStore + IdentityKeyStore passthrough

### Phase 5: Extract GroupSender (extends Sender)

Adds group-specific data methods (GetGroup, SaveGroup, GetSenderKeySharedWith, MarkSenderKeySharedWith) plus SenderKeyStore.

### Phase 6: Slim Service to coordinator

Service becomes thin facade delegating to Receiver/Sender/GroupSender.
