package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

type analyzeSealedCommand struct {
	Args struct {
		File string `positional-arg-name:"file" required:"true" description:"Path to envelope dump file"`
	} `positional-args:"yes"`
}

func (cmd *analyzeSealedCommand) Execute(args []string) error {
	data, err := os.ReadFile(cmd.Args.File)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	fmt.Printf("File: %s (%d bytes)\n\n", cmd.Args.File, len(data))

	// Parse as envelope
	var env proto.Envelope
	if err := pb.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("unmarshal envelope: %w", err)
	}

	fmt.Printf("=== Envelope ===\n")
	fmt.Printf("Type: %v\n", env.GetType())
	fmt.Printf("Timestamp: %d\n", env.GetTimestamp())
	fmt.Printf("ServerTimestamp: %d\n", env.GetServerTimestamp())
	fmt.Printf("SourceServiceId: %s\n", env.GetSourceServiceId())
	fmt.Printf("SourceDevice: %d\n", env.GetSourceDevice())
	fmt.Printf("DestinationServiceId: %s\n", env.GetDestinationServiceId())

	content := env.GetContent()
	fmt.Printf("Content length: %d bytes\n\n", len(content))

	if env.GetType() != proto.Envelope_UNIDENTIFIED_SENDER {
		fmt.Printf("Not a sealed sender envelope (type=%v), skipping content analysis\n", env.GetType())
		return nil
	}

	if len(content) == 0 {
		return fmt.Errorf("empty content field")
	}

	fmt.Printf("=== Sealed Sender Content ===\n")
	fmt.Printf("Version byte: 0x%02x\n", content[0])

	version := content[0] >> 4
	fmt.Printf("Version (major): %d\n", version)

	switch version {
	case 0, 1:
		fmt.Println("Format: Sealed Sender v1")
		remaining := content[1:]
		fmt.Printf("Remaining bytes after version: %d\n", len(remaining))

		// Parse as UnidentifiedSenderMessage protobuf
		var ssMsg proto.UnidentifiedSenderMessage
		if err := pb.Unmarshal(remaining, &ssMsg); err != nil {
			fmt.Printf("\nProtobuf parse FAILED: %v\n", err)
			fmt.Printf("First 64 bytes after version:\n%s\n", hex.Dump(remaining[:min(64, len(remaining))]))
			return nil
		}

		fmt.Println("\nProtobuf parse: SUCCESS")
		ephPub := ssMsg.GetEphemeralPublic()
		encStatic := ssMsg.GetEncryptedStatic()
		encMsg := ssMsg.GetEncryptedMessage()

		fmt.Printf("  ephemeral_public: %d bytes\n", len(ephPub))
		fmt.Printf("  encrypted_static: %d bytes\n", len(encStatic))
		fmt.Printf("  encrypted_message: %d bytes\n", len(encMsg))

		if len(ephPub) > 0 {
			fmt.Printf("\nEphemeral public key:\n%s", hex.Dump(ephPub))
			if ephPub[0] == 0x05 {
				fmt.Println("  ^ First byte 0x05 = valid Curve25519 public key prefix")
			} else {
				fmt.Printf("  ^ WARNING: First byte 0x%02x is unexpected (should be 0x05 for Curve25519)\n", ephPub[0])
			}
		}

		if len(encStatic) > 0 {
			fmt.Printf("\nEncrypted static (first 48 bytes):\n%s", hex.Dump(encStatic[:min(48, len(encStatic))]))
		}

	case 2:
		fmt.Println("Format: Sealed Sender v2")
		switch content[0] {
		case 0x22:
			fmt.Println("  Variant: UUID (0x22)")
		case 0x23:
			fmt.Println("  Variant: ServiceId (0x23)")
		default:
			fmt.Printf("  Variant: Unknown (0x%02x)\n", content[0])
		}

	default:
		fmt.Printf("Unknown sealed sender version: %d\n", version)
	}

	return nil
}
