// Command signal-link links this device as a secondary Signal device.
//
// Usage:
//
//	signal-link
//
// It displays a QR code in the terminal. Scan it with your primary Signal
// device (Settings → Linked Devices → Link New Device) to complete linking.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	qrterminal "github.com/mdp/qrterminal/v3"

	client "github.com/gwillem/signal-go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "signal-link: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient()

	fmt.Println("Scan this QR code with your primary Signal device:")
	fmt.Println("  Settings → Linked Devices → Link New Device")
	fmt.Println()

	err := c.Link(ctx, func(uri string) {
		qrterminal.GenerateWithConfig(uri, qrterminal.Config{
			Level:     qrterminal.L,
			Writer:    os.Stdout,
			BlackChar: qrterminal.BLACK,
			WhiteChar: qrterminal.WHITE,
		})
		fmt.Println()
		fmt.Println("Waiting for primary device to confirm...")
	})
	if err != nil {
		return err
	}

	fmt.Printf("Linked to %s (device %d)\n", c.Number(), c.DeviceID())
	return nil
}
