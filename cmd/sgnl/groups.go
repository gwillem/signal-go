package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
)

type groupsCommand struct {
	Sync bool `long:"sync" description:"Sync groups from Storage Service before listing"`
}

func (cmd *groupsCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	if cmd.Sync {
		fmt.Println("Syncing groups from Storage Service...")
		n, err := c.SyncGroups(ctx)
		if err != nil {
			return fmt.Errorf("sync groups: %w", err)
		}
		fmt.Printf("Synced %d groups from Storage Service.\n\n", n)
	}

	groups, err := c.Groups()
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}

	if len(groups) == 0 {
		fmt.Println("No groups found.")
		fmt.Println("Groups are discovered from received messages or via --sync.")
		return nil
	}

	fmt.Printf("Found %d group(s):\n\n", len(groups))
	for _, g := range groups {
		name := g.Name
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Printf("  %s\n", name)
		fmt.Printf("    ID:       %s\n", g.GroupID)
		fmt.Printf("    Revision: %d\n", g.Revision)
		if len(g.MemberACIs) > 0 {
			fmt.Printf("    Members:  %d\n", len(g.MemberACIs))
		}
		fmt.Println()
	}

	return nil
}
