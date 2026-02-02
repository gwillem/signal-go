package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
)

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
