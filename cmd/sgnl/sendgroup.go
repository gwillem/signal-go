package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
)

type sendGroupCommand struct {
	Args struct {
		GroupID string `positional-arg-name:"group-id" required:"true" description:"Group ID (hex-encoded GroupIdentifier)"`
		Message string `positional-arg-name:"message" required:"true" description:"Text message to send"`
	} `positional-args:"true" required:"true"`
}

func (cmd *sendGroupCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	// Look up group name for display
	group, err := c.GetGroup(cmd.Args.GroupID)
	if err != nil {
		return fmt.Errorf("get group: %w", err)
	}
	if group == nil {
		return fmt.Errorf("group not found: %s", cmd.Args.GroupID)
	}

	groupName := group.Name
	if groupName == "" {
		groupName = cmd.Args.GroupID[:8] + "..."
	}

	fmt.Printf("Sending to group %q...\n", groupName)

	if err := c.SendGroup(ctx, cmd.Args.GroupID, cmd.Args.Message); err != nil {
		return err
	}

	fmt.Printf("Message sent to group %q (%d members)\n", groupName, len(group.MemberACIs))
	return nil
}
