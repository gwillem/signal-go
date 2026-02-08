# signal-go

Go library for [Signal](https://signal.org) messenger with CGO bindings for the official [libsignal](https://github.com/signalapp/libsignal).

| Feature                                         | Status             |
| ----------------------------------------------- | ------------------ |
| Device linking (secondary device via QR)        | :white_check_mark: |
| Device registration (primary via SMS/voice)     | :white_check_mark: |
| Sending & receiving 1:1 messages                | :white_check_mark: |
| Group messaging (sender keys, sealed sender v2) | :white_check_mark: |
| Sealed sender                                   | :white_check_mark: |
| Phone number lookup (CDSI)                      | :white_check_mark: |
| Contact & group sync                            | :white_check_mark: |
| Profile management                              | :white_check_mark: |
| Attachments                                     |                    |
| Typing indicators & read receipts               |                    |
| Message editing & deletion                      |                    |
| Voice/video calls                               |                    |
| Stories                                         |                    |

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

	// 2. Send a message (by UUID or phone number)
	err = client.Send(ctx, "+31612345678", "Hello from signal-go!")
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

```bash
make deps-download              # downloads pre-compiled libsignal binaries (~200MB)
go run ./cmd/sgnl link          # link as secondary device (scan QR with phone)
go run ./cmd/sgnl receive       # start receiving messages
```

See [docs/building.md](docs/building.md) for building libsignal from source and cross-compilation.

## Notes

**Run a receive loop for group messaging.** Group messages use sender keys distributed via 1:1 sessions. The library tracks which recipients have received the sender key and skips re-sending on subsequent messages. If a recipient's session becomes stale (e.g. they re-installed), the server sends a retry receipt that triggers re-distribution. Without a receive loop (`client.Receive`), these retry receipts are never processed and the recipient won't be able to decrypt group messages.

## License

[AGPL-3.0](LICENSE) (required by libsignal static linking)
