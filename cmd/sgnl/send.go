package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

type sendCommand struct {
	Args struct {
		Recipient string `positional-arg-name:"recipient" required:"true" description:"ACI UUID or E.164 phone number (+31612345678)"`
		Message   string `positional-arg-name:"message" required:"true" description:"Text message to send"`
	} `positional-args:"true" required:"true"`
}

func (cmd *sendCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := loadClient()
	defer c.Close()

	if err := c.Send(ctx, cmd.Args.Recipient, cmd.Args.Message); err != nil {
		return err
	}

	fmt.Printf("Message sent to %s\n", cmd.Args.Recipient)
	return nil
}
