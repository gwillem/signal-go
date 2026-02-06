package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

type groupsCommand struct {
	Sync bool `long:"sync" description:"Sync groups from Storage Service before listing"`
}

func (cmd *groupsCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := loadClient()
	defer c.Close()

	if cmd.Sync {
		fmt.Println("Syncing groups from Storage Service...")
		n, err := c.SyncGroups(ctx)
		if err != nil {
			return fmt.Errorf("sync groups: %w", err)
		}
		fmt.Printf("Synced %d groups from Storage Service.\n\n", n)
	}

	// Always fetch group details for groups without names
	if _, err := c.FetchGroupDetails(ctx); err != nil {
		return fmt.Errorf("fetch group details: %w", err)
	}

	groups, err := c.Groups()
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}

	if len(groups) == 0 {
		fmt.Println("No groups found.")
		fmt.Println("Use --sync --fetch to discover groups from Storage Service.")
		return nil
	}

	// Find max name length for alignment
	maxLen := len("(no name)")
	for _, g := range groups {
		if len(g.Name) > maxLen {
			maxLen = len(g.Name)
		}
	}

	for _, g := range groups {
		name := g.Name
		if name == "" {
			name = "(no name)"
		}
		fmt.Printf("%-*s  %s\n", maxLen, name, g.GroupID)
	}

	return nil
}
