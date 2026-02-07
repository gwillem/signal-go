# Task 18: Decouple Service from concrete *store.Store

## Status: TODO

## Problem

`Service` depends directly on `*store.Store`, requiring a real SQLite database for all tests. This makes unit testing individual service methods slow and brittle.

Similarly, `receiveMessages` depends on concrete `*signalws.PersistentConn`, making the receive loop untestable without a real WebSocket.

## Proposed Solution

1. Define a `ServiceStore` interface in `internal/signalservice/` containing only the methods that `Service` actually calls on the store
2. Accept the interface in `ServiceConfig` instead of `*store.Store`
3. Define a minimal `wsConn` interface (`ReadMessage`, `SendResponse`, `Close`) for the receiver
4. Create mock implementations for testing

## Background

- `Service` depends on concrete `*store.Store` — all tests require a real SQLite database, making them slow and brittle.
- `receiveMessages` depends on concrete `*signalws.PersistentConn` — the receive loop is untestable without a real WebSocket connection.
