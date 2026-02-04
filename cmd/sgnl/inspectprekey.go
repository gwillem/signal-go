package main

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/gwillem/signal-go/internal/libsignal"
)

type inspectPreKeyCommand struct {
	Args struct {
		Base64Content string `positional-arg-name:"base64-content" description:"Base64 encoded pre-key message content"`
	} `positional-args:"yes" required:"yes"`
}

func (c *inspectPreKeyCommand) Execute(args []string) error {
	data, err := base64.StdEncoding.DecodeString(c.Args.Base64Content)
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}

	msg, err := libsignal.DeserializePreKeySignalMessage(data)
	if err != nil {
		return fmt.Errorf("deserialize: %w", err)
	}
	defer msg.Destroy()

	regID, _ := msg.RegistrationID()
	signedPreKeyID, _ := msg.SignedPreKeyID()
	preKeyID, _ := msg.PreKeyID()
	version, _ := msg.Version()

	fmt.Printf("PreKeySignalMessage:\n")
	fmt.Printf("  registration_id: %d\n", regID)
	fmt.Printf("  signed_pre_key_id: %d\n", signedPreKeyID)
	fmt.Printf("  pre_key_id: %d (0xffffffff = none)\n", preKeyID)
	fmt.Printf("  version: %d\n", version)

	// Extract and display the sender's identity key
	identityKey, err := msg.IdentityKey()
	if err != nil {
		fmt.Printf("  identity_key: error: %v\n", err)
	} else {
		defer identityKey.Destroy()
		keyBytes, err := identityKey.Serialize()
		if err != nil {
			fmt.Printf("  identity_key: serialize error: %v\n", err)
		} else {
			fmt.Printf("  identity_key: %s\n", hex.EncodeToString(keyBytes))
		}
	}

	return nil
}
