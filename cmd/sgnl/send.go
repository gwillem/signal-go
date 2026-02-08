package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

type sendCommand struct {
	PNI    bool `long:"pni" description:"Use PNI identity (for recipients who discovered you via phone number)"`
	Sealed bool `long:"sealed" description:"Use sealed sender (UNIDENTIFIED_SENDER) to hide sender from server"`
	Args   struct {
		Recipient string `positional-arg-name:"recipient" required:"true" description:"ACI UUID or E.164 phone number (+31612345678)"`
		Message   string `positional-arg-name:"message" required:"true" description:"Text message to send"`
	} `positional-args:"true" required:"true"`
}

func (cmd *sendCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := loadClient()
	defer c.Close()

	var err error
	switch {
	case cmd.Sealed:
		err = c.SendSealed(ctx, cmd.Args.Recipient, cmd.Args.Message)
	case cmd.PNI:
		err = c.SendWithPNI(ctx, cmd.Args.Recipient, cmd.Args.Message)
	default:
		err = c.Send(ctx, cmd.Args.Recipient, cmd.Args.Message)
	}
	if err != nil {
		return err
	}

	mode := "standard"
	if cmd.Sealed {
		mode = "sealed sender"
	} else if cmd.PNI {
		mode = "PNI"
	}
	fmt.Printf("Message sent to %s (%s)\n", cmd.Args.Recipient, mode)
	return nil
}
