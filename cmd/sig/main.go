// Command sig is a CLI for Signal messenger.
//
// Usage:
//
//	sig link              Link this device as a secondary Signal device
//	sig send <to> <msg>   Send a text message
//	sig receive           Receive and print incoming messages
package main

import (
	"context"
	"fmt"
	"time"
	"log/slog"
	"os"
	"os/signal"

	flags "github.com/jessevdk/go-flags"
	qrterminal "github.com/mdp/qrterminal/v3"

	client "github.com/gwillem/signal-go"
)

type globalOpts struct {
	DB      string          `long:"db" description:"Path to database file"`
	Verbose bool            `short:"v" long:"verbose" description:"Enable verbose logging"`
	Link    linkCommand     `command:"link" description:"Link as a secondary Signal device"`
	Send    sendCommand     `command:"send" description:"Send a text message"`
	Receive receiveCommand  `command:"receive" description:"Receive and print incoming messages"`
	Devices    devicesCommand    `command:"devices" description:"List registered devices for this account"`
	UpdateAttr updateAttrCommand `command:"update-attributes" description:"Update account attributes on server (can fix message delivery)"`
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
	var copts []client.Option
	if opts.DB != "" {
		copts = append(copts, client.WithDBPath(opts.DB))
	}
	if opts.Verbose {
		level := slog.LevelDebug
		copts = append(copts, client.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))))
	}
	return copts
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

type receiveCommand struct{}

func (cmd *receiveCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	fmt.Println("Listening for messages... (Ctrl+C to stop)")

	for msg, err := range c.Receive(ctx) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			continue
		}
		ts := msg.Timestamp.Format("2006-01-02 15:04:05")
		if msg.SyncTo != "" {
			fmt.Printf("[%s] (you) → %s: %s\n", ts, msg.SyncTo, msg.Body)
		} else {
			fmt.Printf("[%s] %s: %s\n", ts, msg.Sender, msg.Body)
		}
	}

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

type devicesCommand struct{}

func (cmd *devicesCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	devices, err := c.Devices(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("Registered devices (%d):\n", len(devices))
	for _, d := range devices {
		created := time.UnixMilli(d.Created).Format("2006-01-02 15:04")
		lastSeen := time.UnixMilli(d.LastSeen).Format("2006-01-02 15:04")
		fmt.Printf("  Device %d: created=%s lastSeen=%s name=%q\n", d.ID, created, lastSeen, d.Name)
	}
	return nil
}

type updateAttrCommand struct{}

func (cmd *updateAttrCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	if err := c.UpdateAttributes(ctx); err != nil {
		return err
	}

	fmt.Println("Account attributes updated successfully.")
	return nil
}
