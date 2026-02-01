# signal-go

Go library for Signal messenger, replacing the Java signal-cli dependency. Licensed under AGPL-3.0.

## Housekeeping

- Keep `docs/*.md` up to date when completing tasks, learning something new, or making architectural decisions. Update phase status markers, implementation notes, and reference information.

## Architecture

- `client.go` — Public API: `Client` with `Link`, `Number`
- `internal/libsignal/` — CGO bindings to libsignal's Rust C FFI (Phase 1, complete)
- `internal/proto/` — Protobuf definitions and generated Go code (Provisioning, WebSocket)
- `internal/provisioncrypto/` — Provisioning envelope encrypt/decrypt (HKDF, AES-CBC, HMAC, PKCS7)
- `internal/signalws/` — Protobuf-framed WebSocket layer
- `internal/signalservice/` — Provisioning orchestration, device link URI
- `docs/` — Phase plans and architecture docs

## Prerequisites

- Go 1.25+
- Rust nightly toolchain (`rustup install nightly`)
- cbindgen (`cargo install cbindgen`)
- Local libsignal checkout at `../libsignal`

## Building

```
make build    # builds libsignal_ffi.a + generates libsignal-ffi.h
make test     # runs go test ./...
```

## Testing

```
make test     # builds libsignal_ffi.a if needed, then runs go test ./... with correct CGO flags
```

Always use `make test` to run tests — it sets the required `CGO_LDFLAGS_ALLOW` and `CGO_LDFLAGS` flags. Never run `go build` — always use `make test` to verify compilation.

## CGO callback pattern

Store interfaces (SessionStore, IdentityKeyStore, etc.) use CGO callbacks:

1. Go `//export` functions in `callbacks.go` receive raw C pointers
2. C bridge functions in `bridge.c` unwrap by-value wrapper structs to raw pointers
3. `pointer.go` provides a handle map for passing Go interfaces through C `void*`
4. `memstore.go` has in-memory implementations for testing

## Phase status

- **Phase 1 (CGO bindings):** Complete — key generation, session establishment, encrypt/decrypt
- **Phase 2 (service layer):** In progress — device provisioning complete, see `docs/phase2-service-layer.md`

## Key files

| File | Purpose |
|---|---|
| `client.go` | Public API: Client, Link, Number |
| `libsignal.go` | CGO preamble (LDFLAGS, includes) |
| `error.go` | FFI error wrapping, owned buffer handling |
| `privatekey.go` | PrivateKey: generate, serialize, sign, agree |
| `publickey.go` | PublicKey: derive, serialize, verify, compare |
| `identitykey.go` | IdentityKeyPair: serialize/deserialize |
| `address.go` | Protocol address (name + device ID) |
| `prekey.go` | PreKeyRecord, SignedPreKeyRecord |
| `kyberprekey.go` | KyberKeyPair, KyberPreKeyRecord |
| `prekeybundle.go` | PreKeyBundle construction |
| `session.go` | SessionRecord |
| `message.go` | CiphertextMessage, PreKeySignalMessage, SignalMessage |
| `store.go` | Store interfaces (5 types) |
| `callbacks.go` | CGO callback exports + store wrappers |
| `bridge.c` | C bridge functions for callback type conversion |
| `memstore.go` | In-memory store implementations |
| `pointer.go` | Handle map for Go→C→Go pointer passing |
| `protocol.go` | ProcessPreKeyBundle, Encrypt, Decrypt |
