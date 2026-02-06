package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

type syncContactsCommand struct{}

func (cmd *syncContactsCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := loadClient()
	defer c.Close()

	fmt.Println("Requesting contact sync from primary device...")
	if err := c.SyncContacts(ctx); err != nil {
		return err
	}

	fmt.Println("Contact sync request sent.")
	fmt.Println("Run 'sgnl receive' to process the incoming contact sync response.")
	return nil
}
