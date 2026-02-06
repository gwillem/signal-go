package main

import (
	"context"
	"fmt"
)

type verifyIdentityCommand struct{}

func (v *verifyIdentityCommand) Execute(args []string) error {
	c := loadClient()
	defer c.Close()

	serverKey, localKey, match, err := c.VerifyIdentityKey(context.Background())
	if err != nil {
		return fmt.Errorf("verify identity key: %w", err)
	}

	fmt.Printf("Local identity key:  %x\n", localKey)
	fmt.Printf("Server identity key: %x\n", serverKey)
	if match {
		fmt.Println("\n✓ MATCH: Server has the same identity key")
	} else {
		fmt.Println("\n✗ MISMATCH: Server has a DIFFERENT identity key!")
		fmt.Println("  This explains why sealed sender decryption fails.")
		fmt.Println("  The server's identity key is what senders fetch to encrypt messages.")
		fmt.Println("  Solution: Re-link this device to register the correct identity key.")
	}

	return nil
}
