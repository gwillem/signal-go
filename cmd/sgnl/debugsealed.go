package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

type debugSealedCommand struct {
	Args struct {
		File string `positional-arg-name:"file" required:"true" description:"Path to envelope dump file"`
	} `positional-args:"yes"`
}

func (cmd *debugSealedCommand) Execute(args []string) error {
	// Load envelope
	data, err := os.ReadFile(cmd.Args.File)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var env proto.Envelope
	if err := pb.Unmarshal(data, &env); err != nil {
		return fmt.Errorf("unmarshal envelope: %w", err)
	}

	content := env.GetContent()
	fmt.Printf("Envelope type: %v\n", env.GetType())
	fmt.Printf("Content length: %d bytes\n", len(content))
	fmt.Printf("Version byte: 0x%02x\n\n", content[0])

	// Parse outer SSv1 structure
	remaining := content[1:]
	var ssMsg proto.UnidentifiedSenderMessage
	if err := pb.Unmarshal(remaining, &ssMsg); err != nil {
		return fmt.Errorf("parse SSv1: %w", err)
	}

	ephPub := ssMsg.GetEphemeralPublic()
	encStatic := ssMsg.GetEncryptedStatic()
	encMessage := ssMsg.GetEncryptedMessage()

	fmt.Printf("Ephemeral public key (%d bytes):\n%s\n", len(ephPub), hex.Dump(ephPub))
	fmt.Printf("Encrypted static (%d bytes):\n%s\n", len(encStatic), hex.Dump(encStatic[:min(64, len(encStatic))]))
	fmt.Printf("Encrypted message: %d bytes\n\n", len(encMessage))

	// Load our identity from store
	dbPath, err := resolveDBPath()
	if err != nil {
		return fmt.Errorf("resolve db path: %w", err)
	}

	st, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	acct, err := st.LoadAccount()
	if err != nil {
		return fmt.Errorf("load account: %w", err)
	}

	// Set ACI identity
	aciPriv, err := libsignal.DeserializePrivateKey(acct.ACIIdentityKeyPrivate)
	if err != nil {
		return fmt.Errorf("deserialize ACI private: %w", err)
	}
	st.SetIdentity(aciPriv, uint32(acct.RegistrationID))

	// Get ACI public key
	aciPub, err := aciPriv.PublicKey()
	if err != nil {
		return fmt.Errorf("derive ACI public: %w", err)
	}
	aciPubBytes, _ := aciPub.Serialize()
	aciPub.Destroy()

	fmt.Printf("Our ACI identity public key:\n%s\n", hex.Dump(aciPubBytes))

	// Set PNI identity if available
	if len(acct.PNIIdentityKeyPrivate) > 0 {
		pniPriv, err := libsignal.DeserializePrivateKey(acct.PNIIdentityKeyPrivate)
		if err != nil {
			return fmt.Errorf("deserialize PNI private: %w", err)
		}
		st.SetPNIIdentity(pniPriv, uint32(acct.PNIRegistrationID))

		pniPub, err := pniPriv.PublicKey()
		if err != nil {
			return fmt.Errorf("derive PNI public: %w", err)
		}
		pniPubBytes, _ := pniPub.Serialize()
		pniPub.Destroy()

		fmt.Printf("Our PNI identity public key:\n%s\n", hex.Dump(pniPubBytes))
	}

	// Try to deserialize the ephemeral public key
	ephKey, err := libsignal.DeserializePublicKey(ephPub)
	if err != nil {
		return fmt.Errorf("deserialize ephemeral key: %w", err)
	}
	defer ephKey.Destroy()
	fmt.Println("Ephemeral key deserialized successfully")

	// Try decryption with ACI
	fmt.Println("\n=== Attempting decryption with ACI identity ===")
	usmc, err := libsignal.SealedSenderDecryptToUSMC(content, st)
	if err != nil {
		fmt.Printf("ACI decryption failed: %v\n", err)
	} else {
		fmt.Println("ACI decryption SUCCEEDED!")
		usmc.Destroy()
	}

	// Try decryption with PNI
	if len(acct.PNIIdentityKeyPrivate) > 0 {
		fmt.Println("\n=== Attempting decryption with PNI identity ===")
		st.UsePNI(true)
		usmc, err = libsignal.SealedSenderDecryptToUSMC(content, st)
		st.UsePNI(false)
		if err != nil {
			fmt.Printf("PNI decryption failed: %v\n", err)
		} else {
			fmt.Println("PNI decryption SUCCEEDED!")
			usmc.Destroy()
		}
	}

	return nil
}

func resolveDBPath() (string, error) {
	if opts.DB != "" {
		return opts.DB, nil
	}
	if opts.Account != "" {
		home, _ := os.UserHomeDir()
		return home + "/.signal-go-" + opts.Account + ".db", nil
	}
	// Try default
	home, _ := os.UserHomeDir()
	matches, _ := filepath.Glob(home + "/.signal-go-*.db")
	if len(matches) == 1 {
		return matches[0], nil
	}
	return "", fmt.Errorf("specify --db or --account")
}
