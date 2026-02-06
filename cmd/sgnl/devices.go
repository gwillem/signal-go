package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"time"
)

type devicesCommand struct{}

func (cmd *devicesCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := loadClient()
	defer c.Close()

	devices, err := c.Devices(ctx)
	if err != nil {
		return err
	}

	fmt.Printf("Registered devices (%d):\n", len(devices))
	for _, d := range devices {
		created := time.UnixMilli(d.Created).Format("2006-01-02 15:04")
		lastSeen := time.UnixMilli(d.LastSeen).Format("2006-01-02 15:04")
		fmt.Printf("  Device %d: created=%s lastSeen=%s name=%q\n", d.ID, created, lastSeen, d.Name)
	}
	return nil
}
