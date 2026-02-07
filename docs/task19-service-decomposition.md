# Task 19: Decompose Service God Object

## Problem

`Service` struct in `internal/signalservice/` handles at least 8 distinct concerns:
transport, auth, messages, groups, sync, attachments, storage, profiles, and keys.

## Suggested First Step

Extract standalone crypto utilities that don't need `Service` state into a
new `internal/signalcrypto` sub-package:

- Profile cipher (encrypt/decrypt profile fields)
- Access key derivation
- Storage Service crypto (AES-256-GCM, key derivation)

## Benefits

- Crypto functions become independently testable without SQLite
- Reduces `Service` surface area
- Clearer dependency graph

## Related

- Task 18 (`docs/task18-service-store-interface.md`): Decouple Service from concrete `*store.Store`
