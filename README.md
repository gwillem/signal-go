# signal-go

Go library for [Signal](https://signal.org) messenger, replacing the Java `signal-cli` dependency.

Uses CGO bindings to the Rust C FFI.

> **Status:** Early development. Device linking works. Message send/receive is not yet implemented.

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

	// 2. Send a message (not yet implemented)
	// err = client.Send(ctx, "+31612345678", "Hello from signal-go!")

	// 3. Receive messages (not yet implemented)
	// for msg := range client.Receive(ctx) {
	// 	fmt.Printf("%s: %s\n", msg.From, msg.Body)
	// }
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
client.go                — public API (Client, Link, Number)
internal/signalservice   — provisioning orchestration, device linking
internal/signalws        — protobuf-framed WebSocket layer
internal/provisioncrypto — provisioning envelope crypto (HKDF, AES-CBC, HMAC)
internal/libsignal       — CGO bindings to libsignal Rust FFI
internal/proto           — protobuf definitions (provisioning, websocket)
```

## Roadmap

- [x] CGO bindings — key generation, session establishment, encrypt/decrypt
- [x] Device provisioning — link as secondary device via QR code
- [ ] Device registration — pre-key upload, complete linking
- [ ] Message sending — encrypt and deliver to Signal servers
- [ ] Message receiving — authenticated WebSocket, decrypt incoming
- [ ] Persistent storage — SQLite-backed key/session stores

## License

[AGPL-3.0](LICENSE) (required by libsignal static linking)
