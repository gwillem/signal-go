# Task 19: Decompose Service God Object

## Status: COMPLETE

## Completed

- **Phase 1**: Extracted `internal/signalcrypto/` (stateless crypto utilities)
- **Phase 2**: Changed `Store.PNI()` return type to `libsignal.IdentityKeyStore`
- **Phase 3**: Extracted `Receiver` struct with `receiverDataStore`, `cryptoStore`, `wsConn` interfaces and callback functions. Interfaces in `interfaces.go`. Tests updated.
- **Phase 3.5**: Simplified receiver tests with mocks. `mockDataStore` (in-memory maps) replaces SQLite for data store. Profile tests use callback stubs instead of `httptest.Server` + `NewService`. Envelope tests use mock data store + real crypto store. WebSocket integration tests kept as-is.
- **Phase 4**: Extracted `Sender` struct with `senderDataStore`, `senderCryptoStore` interfaces and HTTP callback functions. Moved `sendTextMessage`, `buildDataMessageContent`, `createPniSignatureMessage`, `sendSealedSenderMessage`, `sendSealedEncrypted`, `trySendSealed` from Service to Sender. Moved `sendRetryReceipt`, `handleRetryReceipt`, `sendNullMessageWithDevices`, `prepareSendDevices`, `sendEncryptedMessage`, `sendEncryptedMessageWithTimestamp`, `sendEncryptedMessageWithDevices`, `encryptAndSend`, `encryptAndSendWithTimestamp`, `encryptAndSendWithIdentity` from Service to Sender. Moved `initialDevices`, `withDeviceRetry` from Service to Sender. Added `sendTextMessageWithIdentity` on Sender. Changed `deriveAccessKeyForRecipient` to use `contactLookup` interface. Service delegates to Sender via proxy methods for backward compatibility with groupsender/contactsync code.
- **Phase 5**: Extracted `GroupSender` struct with `groupSenderDataStore` interface (10 methods) and full `cryptoStore`. Moved all group messaging methods from Service to GroupSender: `sendGroupMessage`, `ensureSession`, `trySendMultiRecipient`, `endorsementsExpired`, `computeGroupSendToken`, `sendGroupV1Fallback`, `sendSenderKeyDistribution`, `sendGroupSealedMessage`, `trySendGroupSealed`, `sendGroupSyncMessage`. Moved `withGroupDeviceRetry` from Service to GroupSender. Service delegates `SendGroupMessage` to GroupSender. GroupSender uses callbacks for HTTP operations (`getPreKeys`, `getSenderCertificate`, `sendSealedHTTPMsg`, `sendMultiRecipientHTTPMsg`, `fetchGroupDetails`) and Sender operations (`sendEncryptedMessage`, `sendSealedEncrypted`, `sendEncryptedMessageWithTimestamp`, `initialDevices`, `withDeviceRetry`). Removed 4 Service proxy methods that were only needed by groupsender code. Fixed `LoadSession` leak: moved from `groupSenderDataStore` to `cryptoStore` (it takes `*libsignal.Address`, a crypto type).
- **Phase 5.5**: Simplified sender tests. Replaced `httptest.Server` + `NewService` with direct `Sender` construction and callback stubs. Added `newTestSender` and `makeTestPreKeys` test helpers. 8 tests rewritten, file reduced from 1287 to 902 lines. Removed 6 unused imports (net/http, httptest, io, json, strings, signalcrypto).

## Key Design Insight: Separate Crypto Passthrough from Business Data

Crypto operations need all 6 libsignal store interfaces simultaneously, but Go business logic only calls a few data methods. Solution: hold `cryptoStore` as an opaque passthrough for FFI calls, and `receiverDataStore` (7 methods) / `senderDataStore` (6 methods) / `groupSenderDataStore` (10 methods) for business logic. `*store.Store` satisfies all, but tests can mock each independently.

## Phase 6: Decided not to implement

Service at ~544 lines is already a thin coordinator. The remaining code is HTTP transport methods (naturally tied to Transport + auth), thin one-liner delegations, and subsystems already in separate files. Further decomposition would add callback wiring and interface boilerplate without meaningful benefit.
