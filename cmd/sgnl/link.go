package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	qrterminal "github.com/mdp/qrterminal/v3"

	client "github.com/gwillem/signal-go"
)

type linkCommand struct{}

func (cmd *linkCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

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
