package main

import (
	"context"
	"encoding/base64"
	"fmt"
)

type checkAllKeysCommand struct{}

func (c *checkAllKeysCommand) Execute(args []string) error {
	cl := loadClient()
	defer cl.Close()

	// Get devices
	devices, err := cl.Devices(context.Background())
	if err != nil {
		return fmt.Errorf("get devices: %w", err)
	}

	fmt.Println("Checking identity key for each device on server...")
	fmt.Println()

	// For each device, fetch its identity key from server
	for _, d := range devices {
		key, err := cl.GetDeviceIdentityKey(context.Background(), d.ID)
		if err != nil {
			fmt.Printf("Device %d: ERROR - %v\n", d.ID, err)
			continue
		}
		keyBytes, _ := base64.StdEncoding.DecodeString(key)
		fmt.Printf("Device %d: %x\n", d.ID, keyBytes)
	}

	return nil
}
