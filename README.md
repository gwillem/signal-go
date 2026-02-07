# signal-go

Go library for [Signal](https://signal.org) messenger with CGO bindings for the official [libsignal](https://github.com/signalapp/libsignal).

Supported: device linking (secondary device via QR), device registration (primary via SMS/voice), sending and receiving 1:1 messages, group messaging (sender keys, sealed sender v2, multi-recipient encrypt), sealed sender, contact and group sync, profile management, attachment downloading.

Not yet supported: media/attachment sending, voice/video calls, stories, payments, message editing/deletion, read receipts, typing indicators.

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

## Quick start

Requires Go 1.25+.

```bash
make deps-download   # downloads pre-compiled libsignal binaries (~200MB)
make test            # runs tests with correct CGO flags
```

See [docs/building.md](docs/building.md) for building libsignal from source and cross-compilation.

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
- [x] Device registration — primary device via SMS/voice verification
- [x] Message sending — 1:1 encrypted message delivery
- [x] Message receiving — authenticated WebSocket, decrypt incoming
- [x] Sealed sender — unidentified sender for 1:1 and group messages
- [x] Group messaging — sender keys, sealed sender v2, multi-recipient encrypt
- [x] Contact and group sync — Storage Service, Groups V2 API
- [x] Profile management — get/set name, phone number sharing
- [x] Persistent storage — SQLite-backed key/session stores
- [ ] Attachment sending — encrypt and upload media
- [ ] Typing indicators, read receipts
- [ ] Message editing and deletion

## Notes

**Run a receive loop for group messaging.** Group messages use sender keys distributed via 1:1 sessions. The library tracks which recipients have received the sender key and skips re-sending on subsequent messages. If a recipient's session becomes stale (e.g. they re-installed), the server sends a retry receipt that triggers re-distribution. Without a receive loop (`client.Receive`), these retry receipts are never processed and the recipient won't be able to decrypt group messages.

## License

[AGPL-3.0](LICENSE) (required by libsignal static linking)
