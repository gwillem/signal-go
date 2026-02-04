package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
)

type profileCommand struct {
	Name          string       `long:"name" description:"Set profile name"`
	NumberSharing optionalBool `long:"number-sharing" description:"Enable/disable phone number sharing in profile {true,false}"`
}

func (cmd *profileCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	// If any options are provided, update profile
	if cmd.Name != "" || cmd.NumberSharing.value != nil {
		if err := c.SetProfile(ctx, cmd.Name, cmd.NumberSharing.value); err != nil {
			return fmt.Errorf("set profile: %w", err)
		}
		fmt.Println("Profile updated:")
		if cmd.Name != "" {
			fmt.Printf("  name: %q\n", cmd.Name)
		}
		if cmd.NumberSharing.value != nil {
			fmt.Printf("  number-sharing: %v\n", *cmd.NumberSharing.value)
		}
		return nil
	}

	// Otherwise, show current profile info
	info, err := c.ProfileInfo()
	if err != nil {
		return err
	}

	fmt.Println("Local account info:")
	fmt.Printf("  Phone:     %s\n", info.Number)
	fmt.Printf("  ACI:       %s\n", info.ACI)
	fmt.Printf("  PNI:       %s\n", info.PNI)
	fmt.Printf("  DeviceID:  %d\n", info.DeviceID)
	if len(info.ProfileKey) > 0 {
		fmt.Printf("  ProfileKey: %s\n", hex.EncodeToString(info.ProfileKey))
	} else {
		fmt.Printf("  ProfileKey: (not set)\n")
	}

	// Fetch profile from server
	serverProfile, err := c.GetServerProfile(ctx)
	if err != nil {
		fmt.Printf("\nServer profile: (error: %v)\n", err)
		return nil
	}

	fmt.Println("\nServer profile:")
	if serverProfile.Name != "" {
		fmt.Printf("  Name:      %s\n", serverProfile.Name)
	} else {
		fmt.Printf("  Name:      (not set)\n")
	}
	if serverProfile.About != "" {
		fmt.Printf("  About:     %s\n", serverProfile.About)
	}
	if serverProfile.AboutEmoji != "" {
		fmt.Printf("  Emoji:     %s\n", serverProfile.AboutEmoji)
	}
	if serverProfile.Avatar != "" {
		fmt.Printf("  Avatar:    %s\n", serverProfile.Avatar)
	} else {
		fmt.Printf("  Avatar:    (not set)\n")
	}

	return nil
}
