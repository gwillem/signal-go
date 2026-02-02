package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
)

type receiveCommand struct {
	N int `short:"n" description:"Maximum number of messages to receive (0 = unlimited)" default:"0"`
}

func (cmd *receiveCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	fmt.Println("Listening for messages... (Ctrl+C to stop)")

	count := 0
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
		count++
		if cmd.N > 0 && count >= cmd.N {
			break
		}
	}

	return nil
}
