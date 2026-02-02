// Command sgnl is a CLI for Signal messenger.
//
// Usage:
//
//	sgnl link              Link this device as a secondary Signal device
//	sgnl send <to> <msg>   Send a text message
//	sgnl receive           Receive and print incoming messages
package main

import (
	"log"
	"os"

	flags "github.com/jessevdk/go-flags"

	client "github.com/gwillem/signal-go"
)

type globalOpts struct {
	DB       string          `long:"db" description:"Path to database file"`
	Verbose  bool            `short:"v" long:"verbose" description:"Enable verbose logging"`
	DebugDir string          `long:"debug-dir" description:"Directory for dumping raw envelopes before decryption"`
	Link    linkCommand     `command:"link" description:"Link as a secondary Signal device"`
	Send    sendCommand     `command:"send" description:"Send a text message"`
	Receive receiveCommand  `command:"receive" description:"Receive and print incoming messages"`
	Devices      devicesCommand      `command:"devices" description:"List registered devices for this account"`
	UpdateAttr   updateAttrCommand   `command:"update-attributes" description:"Update account attributes on server (can fix message delivery)"`
	SyncContacts syncContactsCommand `command:"sync-contacts" description:"Request contact sync from primary device"`
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
	if opts.DB != "" {
		copts = append(copts, client.WithDBPath(opts.DB))
	}
	if opts.Verbose {
		copts = append(copts, client.WithLogger(log.New(os.Stderr, "", log.LstdFlags)))
	}
	if opts.DebugDir != "" {
		copts = append(copts, client.WithDebugDir(opts.DebugDir))
	}
	return copts
}
