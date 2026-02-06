package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
)

// displayName returns the best available display string for a contact.
func displayName(name, number, aci string) string {
	if name != "" {
		if number != "" {
			return fmt.Sprintf("%s (%s)", name, number)
		}
		return name
	}
	if number != "" {
		return number
	}
	return aci
}

type receiveCommand struct {
	N int `short:"n" description:"Maximum number of messages to receive (0 = unlimited)" default:"0"`
}

func (cmd *receiveCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := loadClient()
	defer c.Close()

	fmt.Println("Listening for messages... (Ctrl+C to stop)")

	count := 0
	for msg, err := range c.Receive(ctx) {
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			continue
		}
		ts := msg.Timestamp.Format("2006-01-02 15:04:05")
		sender := displayName(msg.SenderName, msg.SenderNumber, msg.Sender)
		if msg.SyncTo != "" {
			recipient := displayName(msg.SyncToName, msg.SyncToNumber, msg.SyncTo)
			if msg.GroupID != "" {
				group := msg.GroupName
				if group == "" {
					group = msg.GroupID[:8] + "..."
				}
				fmt.Printf("[%s] (you) → [%s]: %s\n", ts, group, msg.Body)
			} else {
				fmt.Printf("[%s] (you) → %s: %s\n", ts, recipient, msg.Body)
			}
		} else if msg.GroupID != "" {
			group := msg.GroupName
			if group == "" {
				group = msg.GroupID[:8] + "..."
			}
			fmt.Printf("[%s] [%s] %s: %s\n", ts, group, sender, msg.Body)
		} else {
			fmt.Printf("[%s] %s: %s\n", ts, sender, msg.Body)
		}
		count++
		if cmd.N > 0 && count >= cmd.N {
			break
		}
	}

	return nil
}
