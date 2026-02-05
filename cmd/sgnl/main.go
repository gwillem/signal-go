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
	DB       string          `long:"db" description:"Path to database file"`
	Account  string          `short:"a" long:"account" description:"Phone number of account to use (e.g. +1234567890)"`
	Verbose  bool            `short:"v" long:"verbose" description:"Enable verbose logging"`
	DebugDir string          `long:"debug-dir" description:"Directory for dumping raw envelopes before decryption"`
	Register       registerCommand       `command:"register" description:"Register a new Signal account (primary device)"`
	Link           linkCommand           `command:"link" description:"Link as a secondary Signal device"`
	Send           sendCommand           `command:"send" description:"Send a text message"`
	Receive        receiveCommand        `command:"receive" description:"Receive and print incoming messages"`
	Devices        devicesCommand        `command:"devices" description:"List registered devices for this account"`
	AccountCmd     accountCommand        `command:"account" description:"Show or update account settings"`
	UpdateAttr     updateAttrCommand     `command:"update-attributes" description:"Update account attributes on server (can fix message delivery)"`
	RefreshKeys    refreshKeysCommand    `command:"refresh-keys" description:"Re-upload local pre-keys to server (fix pre-key mismatch)"`
	CheckPreKeys   checkPreKeysCommand   `command:"check-prekeys" description:"Verify local pre-keys match identity key (debug)"`
	SyncContacts   syncContactsCommand   `command:"sync-contacts" description:"Request contact sync from primary device"`
	VerifyIdentity verifyIdentityCommand `command:"verify-identity" description:"Compare local identity key with server (debug sealed sender)"`
	CheckAllKeys   checkAllKeysCommand   `command:"check-all-keys" description:"Check identity key for all devices on server"`
	SelfTest       selftestCommand       `command:"selftest" description:"Send message to self and verify receipt (debug)"`
	InspectPreKey  inspectPreKeyCommand  `command:"inspect-prekey" description:"Decode and inspect a base64 pre-key message (debug)"`
	Profile        profileCommand        `command:"profile" description:"Show or set profile information"`
	AnalyzeSealed  analyzeSealedCommand  `command:"analyze-sealed" description:"Analyze a captured sealed sender envelope (debug)"`
	DebugSealed    debugSealedCommand    `command:"debug-sealed" description:"Debug sealed sender decryption with detailed output"`
	SafetyNumber   safetyNumberCommand   `command:"safety-number" description:"Compute safety number with a contact"`
	Groups         groupsCommand         `command:"groups" description:"List known groups (use --sync to fetch from Storage Service)"`
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

	// Resolve database path from --db or --account
	dbPath := opts.DB
	if dbPath == "" && opts.Account != "" {
		var err error
		dbPath, err = client.DiscoverDBByNumber(opts.Account)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	}
	if dbPath != "" {
		copts = append(copts, client.WithDBPath(dbPath))
	}

	if opts.Verbose {
		copts = append(copts, client.WithLogger(log.New(os.Stderr, "", log.LstdFlags)))
	}
	if opts.DebugDir != "" {
		copts = append(copts, client.WithDebugDir(opts.DebugDir))
	}
	return copts
}
