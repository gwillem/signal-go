// Command sgnl is a CLI for Signal messenger.
//
// Usage:
//
//	sgnl link              Link this device as a secondary Signal device
//	sgnl send <to> <msg>   Send a text message
//	sgnl receive           Receive and print incoming messages
package main

import (
	"fmt"
	"log"
	"os"

	flags "github.com/jessevdk/go-flags"

	client "github.com/gwillem/signal-go"
)

type globalOpts struct {
	Account      string              `short:"a" long:"account" description:"Phone number of account to use (e.g. +1234567890)"`
	Verbose      bool                `short:"v" long:"verbose" description:"Enable verbose logging"`
	DebugDir     string              `long:"debug-dir" description:"Directory for dumping raw envelopes before decryption"`
	Register     registerCommand     `command:"register" description:"Register a new Signal account (primary device)"`
	Link         linkCommand         `command:"link" description:"Link as a secondary Signal device"`
	Send         sendCommand         `command:"send" description:"Send a text message"`
	Receive      receiveCommand      `command:"receive" description:"Receive and print incoming messages"`
	Devices      devicesCommand      `command:"devices" description:"List registered devices for this account"`
	AccountCmd   accountCommand      `command:"account" description:"Show or update account settings"`
	SyncContacts syncContactsCommand `command:"sync-contacts" description:"Request contact sync from primary device"`
	Profile      profileCommand      `command:"profile" description:"Show or set profile information"`
	SafetyNumber safetyNumberCommand `command:"safety-number" description:"Compute safety number with a contact"`
	Groups       groupsCommand       `command:"groups" description:"List groups (use --sync to discover new groups from Storage Service)"`
}

var opts globalOpts

func main() {
	parser := flags.NewParser(&opts, flags.Default)
	parser.SubcommandsOptional = false

	_, err := parser.Parse()
	if err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type == flags.ErrHelp {
			os.Exit(0)
		}
		os.Exit(1)
	}
}

func clientOpts() []client.Option {
	var copts []client.Option
	if opts.Verbose {
		copts = append(copts, client.WithLogger(log.New(os.Stderr, "", log.LstdFlags)))
	}
	if opts.DebugDir != "" {
		copts = append(copts, client.WithDebugDir(opts.DebugDir))
	}
	return copts
}

// loadClient opens an existing account. Uses --account (phone number),
// falling back to auto-discovery if not set.
func loadClient() *client.Client {
	copts := clientOpts()
	if opts.Account != "" {
		c, err := client.Open(opts.Account, copts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return c
	}
	c := client.NewClient(copts...)
	if err := c.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	return c
}
