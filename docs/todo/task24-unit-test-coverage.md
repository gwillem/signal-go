# Task 24: Add Missing Unit Tests

## Problem

Many packages have significant gaps in unit test coverage. The `internal/libsignal/` package is the worst offender — 14 of 24 source files have no test file at all. Other packages like `internal/store/` (5 of 9 untested) and `internal/signalservice/` (8 of 24 untested) also have gaps.

## Current Coverage

| Package                     | Files with tests | Total files | Coverage |
| --------------------------- | ---------------- | ----------- | -------- |
| `internal/libsignal/`       | 10               | 24          | 40%      |
| `internal/store/`           | 4                | 9           | 44%      |
| `internal/signalservice/`   | 16               | 24          | 67%      |
| `internal/provisioncrypto/` | 7                | 7           | 100%     |

## Priority 1: `internal/libsignal/` — no tests at all

| File                | What to test                                                                                                                                               |
| ------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authcredential.go` | `NewServerPublicParams`, `ReceiveAuthCredentialWithPni`, `CreateAuthCredentialPresentation`                                                                |
| `endorsement.go`    | `ReceiveEndorsements`, `CombineEndorsements`, `EndorsementToFullToken`, `EndorsementExpiration`                                                            |
| `message.go`        | `DeserializePreKeySignalMessage`, `DeserializeSignalMessage`, all field getters (`PreKeyID`, `SignedPreKeyID`, `RegistrationID`, `Version`, `IdentityKey`) |
| `profilekey.go`     | `ProfileKeyGetVersion`, `ProfileKeyGetCommitment`                                                                                                          |
| `memstore.go`       | All 6 in-memory store implementations (currently only exercised indirectly)                                                                                |

Not worth unit-testing directly: `libsignal.go` (CGO preamble), `store.go` (interface definitions), `pointer.go` (thin cgo.Handle wrapper), `error.go` (tested indirectly), `callbacks.go` (tested via protocol_test.go).

## Priority 2: `internal/libsignal/` — tests exist but limited

| File              | Current tests | Missing coverage                                                 |
| ----------------- | ------------- | ---------------------------------------------------------------- |
| `address.go`      | 1 test        | Edge cases: empty name, device ID bounds                         |
| `prekeybundle.go` | 1 test        | Serialize/deserialize roundtrip                                  |
| `senderkey.go`    | 2 tests       | `GroupDecryptMessage`, `NewSenderKeyRecord`                      |
| `session.go`      | 2 tests       | `ArchiveCurrentState`, `RemoteRegistrationID`, `GetAliceBaseKey` |

## Priority 3: `internal/store/` — missing tests

| File          | What to test                                                    |
| ------------- | --------------------------------------------------------------- |
| `account.go`  | `SaveAccount`, `GetAccount`, update credentials                 |
| `group.go`    | `SaveGroup`, `GetGroup`, `GetAllGroups`                         |
| `identity.go` | `GetIdentityKey`, `SaveIdentity`, TOFU behavior                 |
| `prekey.go`   | `LoadPreKey`, `StorePreKey`, `RemovePreKey` for all 3 key types |
| `session.go`  | `LoadSession`, `StoreSession`, `ArchiveSession`                 |

## Priority 4: `internal/signalservice/` — missing tests

| File               | What to test                                      |
| ------------------ | ------------------------------------------------- |
| `deviceretry.go`   | `withDeviceRetry` 409/410 retry logic (mock HTTP) |
| `groupsender.go`   | Group message encryption flow                     |
| `groupsv2.go`      | Groups V2 API request/response parsing            |
| `storagecrypto.go` | AES-256-GCM decrypt, key derivation               |
| `storage.go`       | Storage Service manifest/record parsing           |

## Approach

- Use table-driven tests
- For libsignal CGO functions: generate test data via the protocol roundtrip (encrypt/decrypt cycle produces real serialized messages)
- For store tests: use in-memory SQLite (`Open(":memory:")`)
- For signalservice tests: use `httptest.Server` for HTTP mocking where needed
