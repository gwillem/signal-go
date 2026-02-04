package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
)

type refreshKeysCommand struct{}

func (cmd *refreshKeysCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	if err := c.RefreshPreKeys(ctx); err != nil {
		return err
	}

	fmt.Println("Pre-keys re-uploaded to server successfully.")
	return nil
}
