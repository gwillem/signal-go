package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
)

type accountCommand struct {
	DiscoverableByNumber           optionalBool `long:"discoverable-by-number" description:"Enable/disable if the account should be discoverable by phone number {true,false}"`
	UnrestrictedUnidentifiedSender optionalBool `long:"unrestricted-unidentified-sender" description:"Enable if anyone should be able to send you sealed sender messages {true,false}"`
}

func (cmd *accountCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := loadClient()
	defer c.Close()

	// If any options are provided, update settings
	if cmd.DiscoverableByNumber.value != nil || cmd.UnrestrictedUnidentifiedSender.value != nil {
		settings := &client.AccountSettings{
			DiscoverableByPhoneNumber:      cmd.DiscoverableByNumber.value,
			UnrestrictedUnidentifiedAccess: cmd.UnrestrictedUnidentifiedSender.value,
		}

		if err := c.UpdateAccountSettings(ctx, settings); err != nil {
			return fmt.Errorf("update account settings: %w", err)
		}

		fmt.Println("Account settings updated:")
		if cmd.DiscoverableByNumber.value != nil {
			fmt.Printf("  discoverable-by-number: %v\n", *cmd.DiscoverableByNumber.value)
		}
		if cmd.UnrestrictedUnidentifiedSender.value != nil {
			fmt.Printf("  unrestricted-unidentified-sender: %v\n", *cmd.UnrestrictedUnidentifiedSender.value)
		}
		return nil
	}

	// Otherwise, show account info
	info, err := c.ProfileInfo()
	if err != nil {
		return err
	}

	fmt.Println("Account info:")
	fmt.Printf("  Phone:     %s\n", info.Number)
	fmt.Printf("  ACI:       %s\n", info.ACI)
	fmt.Printf("  PNI:       %s\n", info.PNI)
	fmt.Printf("  DeviceID:  %d\n", info.DeviceID)
	if len(info.ProfileKey) > 0 {
		fmt.Printf("  ProfileKey: %s\n", hex.EncodeToString(info.ProfileKey))
	} else {
		fmt.Printf("  ProfileKey: (not set)\n")
	}

	fmt.Println("\nNote: Account settings (discoverable-by-number, unrestricted-unidentified-sender)")
	fmt.Println("      cannot be read from the server, only set.")
	fmt.Println("      Use --discoverable-by-number or --unrestricted-unidentified-sender to update.")

	return nil
}
