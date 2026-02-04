# signal-go

Go library for [Signal](https://signal.org) messenger:

- CGO bindings to the Rust C FFI
- Partial service implementation of Signal-Android

> **Status:** Early development. Device linking, message sending, and message receiving work.

## Example

```go
package main

import (
	"context"
	"fmt"
	"log"

	signal "github.com/gwillem/signal-go"
)

func main() {
	ctx := context.Background()
	client := signal.NewClient()

	// 1. Link as secondary device (scan QR code with your phone)
	err := client.Link(ctx, func(uri string) {
		fmt.Println("Scan this with Signal on your phone:")
		fmt.Println(uri)
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Linked to", client.Number())

	// 2. Send a message
	err = client.Send(ctx, "recipient-aci-uuid", "Hello from signal-go!")
	if err != nil {
		log.Fatal(err)
	}

	// 3. Receive messages
	for msg, err := range client.Receive(ctx) {
		if err != nil {
			log.Println("Error:", err)
			continue
		}
		fmt.Printf("%s: %s\n", msg.Sender, msg.Body)
	}
}
```

## Prerequisites

- Go 1.25+
- Rust nightly (`rustup install nightly`)
- cbindgen (`cargo install cbindgen`)

## Build & test

```bash
make build   # builds libsignal_ffi.a + generates headers
make test    # builds if needed, then runs tests with correct CGO flags
```

## Architecture

```
client.go                — public API (Client, Link, Send, Receive, Load, Close)
cmd/sig                  — CLI tool (sig link, sig send, sig receive)
internal/signalservice   — provisioning, registration, send, receive orchestration
internal/signalws        — protobuf-framed WebSocket layer with keep-alive
internal/provisioncrypto — provisioning envelope crypto (HKDF, AES-CBC, HMAC)
internal/libsignal       — CGO bindings to libsignal Rust FFI
internal/proto           — protobuf definitions (provisioning, websocket, service)
internal/store           — SQLite persistent storage (sessions, keys, account)
```

## Roadmap

- [x] CGO bindings — key generation, session establishment, encrypt/decrypt
- [x] Device provisioning — link as secondary device via QR code
- [x] Device registration — pre-key upload, complete linking
- [x] Message sending — encrypt and deliver to Signal servers
- [x] Message receiving — authenticated WebSocket, decrypt incoming
- [x] Persistent storage — SQLite-backed key/session stores
- [ ] Sealed sender — UNIDENTIFIED_SENDER envelope decryption
- [ ] Sync messages — request contacts, groups, configuration from primary

## License

[AGPL-3.0](LICENSE) (required by libsignal static linking)
