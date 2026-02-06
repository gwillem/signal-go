package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

type updateAttrCommand struct{}

func (cmd *updateAttrCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := loadClient()
	defer c.Close()

	if err := c.UpdateAttributes(ctx); err != nil {
		return err
	}

	fmt.Println("Account attributes updated successfully.")
	return nil
}
