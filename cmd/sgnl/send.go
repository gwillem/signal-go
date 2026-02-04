package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
)

type sendCommand struct {
	PNI  bool `long:"pni" description:"Use PNI identity (for recipients who discovered you via phone number)"`
	Args struct {
		Recipient string `positional-arg-name:"recipient" required:"true" description:"Recipient ACI UUID"`
		Message   string `positional-arg-name:"message" required:"true" description:"Text message to send"`
	} `positional-args:"true" required:"true"`
}

func (cmd *sendCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	var err error
	if cmd.PNI {
		err = c.SendWithPNI(ctx, cmd.Args.Recipient, cmd.Args.Message)
	} else {
		err = c.Send(ctx, cmd.Args.Recipient, cmd.Args.Message)
	}
	if err != nil {
		return err
	}

	fmt.Printf("Message sent to %s\n", cmd.Args.Recipient)
	return nil
}
