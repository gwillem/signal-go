// Command sig is a CLI for Signal messenger.
//
// Usage:
//
//	sig link          Link this device as a secondary Signal device
//	sig send <to> <msg>  Send a text message
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	flags "github.com/jessevdk/go-flags"
	qrterminal "github.com/mdp/qrterminal/v3"

	client "github.com/gwillem/signal-go"
)

type globalOpts struct {
	DB   string      `long:"db" description:"Path to database file"`
	Link linkCommand `command:"link" description:"Link as a secondary Signal device"`
	Send sendCommand `command:"send" description:"Send a text message"`
}

type linkCommand struct{}

type sendCommand struct {
	Args struct {
		Recipient string `positional-arg-name:"recipient" required:"true" description:"Recipient ACI UUID"`
		Message   string `positional-arg-name:"message" required:"true" description:"Text message to send"`
	} `positional-args:"true" required:"true"`
}

var opts globalOpts

func main() {
	parser := flags.NewParser(&opts, flags.Default)
	parser.SubcommandsOptional = false

	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func clientOpts() []client.Option {
	if opts.DB != "" {
		return []client.Option{client.WithDBPath(opts.DB)}
	}
	return nil
}

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

func (cmd *sendCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	if err := c.Send(ctx, cmd.Args.Recipient, cmd.Args.Message); err != nil {
		return err
	}

	fmt.Printf("Message sent to %s\n", cmd.Args.Recipient)
	return nil
}
