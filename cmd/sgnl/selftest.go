package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"os/signal"
	"time"

	client "github.com/gwillem/signal-go"
)

type selftestCommand struct {
	Message string `short:"m" long:"message" default:"selftest" description:"Message to send"`
	Timeout int    `short:"t" long:"timeout" default:"30" description:"Seconds to wait for message to arrive"`
}

func (cmd *selftestCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	// Get our own ACI from the store
	acct, err := c.Store().LoadAccount()
	if err != nil {
		return fmt.Errorf("load account: %w", err)
	}

	fmt.Printf("=== Self-Test Debug ===\n")
	fmt.Printf("Our ACI: %s\n", acct.ACI)
	fmt.Printf("Our Device ID: %d\n", acct.DeviceID)
	fmt.Printf("Our Number: %s\n", acct.Number)

	// Show identity key fingerprint
	if len(acct.ACIIdentityKeyPublic) >= 8 {
		fmt.Printf("Our Identity Key (first 8 bytes): %s\n", hex.EncodeToString(acct.ACIIdentityKeyPublic[:8]))
	}

	// Check what devices exist for our account
	devices, err := c.Devices(ctx)
	if err != nil {
		fmt.Printf("Warning: couldn't list devices: %v\n", err)
	} else {
		fmt.Printf("Devices on account:\n")
		for _, d := range devices {
			created := time.Unix(d.Created/1000, 0).Format("2006-01-02")
			fmt.Printf("  - Device %d: %s (created %s)\n", d.ID, d.Name, created)
		}
	}

	// Unique message to identify
	testMsg := fmt.Sprintf("%s-%d", cmd.Message, time.Now().UnixMilli())
	fmt.Printf("\n=== Sending ===\n")
	fmt.Printf("Message: %q\n", testMsg)
	fmt.Printf("To: %s (self)\n", acct.ACI)

	sendStart := time.Now()
	if err := c.Send(ctx, acct.ACI, testMsg); err != nil {
		return fmt.Errorf("send failed: %w", err)
	}
	fmt.Printf("Send completed in %v\n", time.Since(sendStart))

	// Now receive and look for our message
	fmt.Printf("\n=== Receiving ===\n")
	fmt.Printf("Waiting up to %d seconds for message...\n", cmd.Timeout)

	// Create a timeout context
	receiveCtx, receiveCancel := context.WithTimeout(ctx, time.Duration(cmd.Timeout)*time.Second)
	defer receiveCancel()

	found := false
	msgCount := 0
	for msg, err := range c.Receive(receiveCtx) {
		if err != nil {
			if receiveCtx.Err() != nil {
				fmt.Printf("\nTimeout reached after %d messages\n", msgCount)
				break
			}
			fmt.Printf("Receive error: %v\n", err)
			continue
		}

		msgCount++
		fmt.Printf("\n--- Message %d ---\n", msgCount)
		fmt.Printf("  Type: %s\n", describeMessageType(msg))
		fmt.Printf("  Sender: %s (device %d)\n", msg.Sender, msg.Device)
		fmt.Printf("  Timestamp: %s\n", msg.Timestamp.Format("15:04:05.000"))
		if msg.Body != "" {
			fmt.Printf("  Body: %q\n", msg.Body)
		}
		if msg.SyncTo != "" {
			fmt.Printf("  SyncTo: %s\n", msg.SyncTo)
		}

		// Check if this is our test message
		if msg.Body == testMsg {
			fmt.Printf("  *** FOUND OUR TEST MESSAGE! ***\n")
			found = true
			// Keep receiving a bit more to see if there are retry receipts
			continue
		}
	}

	fmt.Printf("\n=== Result ===\n")
	if found {
		fmt.Printf("SUCCESS: Test message was received!\n")
	} else {
		fmt.Printf("FAILED: Test message was NOT received after %d messages\n", msgCount)
		fmt.Printf("\nPossible issues:\n")
		fmt.Printf("- Message format incompatible with other devices\n")
		fmt.Printf("- Sealed sender required but we're sending plaintext\n")
		fmt.Printf("- Identity key mismatch\n")
		fmt.Printf("- Session establishment failed\n")
	}

	return nil
}

func describeMessageType(msg client.Message) string {
	if msg.SyncTo != "" {
		return "SYNC_MESSAGE (outgoing)"
	}
	if msg.Body != "" {
		return "DATA_MESSAGE"
	}
	return "OTHER"
}
