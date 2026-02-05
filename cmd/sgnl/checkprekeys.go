package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"

	client "github.com/gwillem/signal-go"
	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/signalservice"
)

type checkPreKeysCommand struct{}

func (cmd *checkPreKeysCommand) Execute(args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	c := client.NewClient(clientOpts()...)

	if err := c.Load(); err != nil {
		return err
	}
	defer c.Close()

	s := c.Store()
	if s == nil {
		return fmt.Errorf("store not available")
	}

	acct, err := s.LoadAccount()
	if err != nil {
		return fmt.Errorf("load account: %w", err)
	}

	// Load identity key
	identityPriv, err := libsignal.DeserializePrivateKey(acct.ACIIdentityKeyPrivate)
	if err != nil {
		return fmt.Errorf("deserialize identity private: %w", err)
	}
	defer identityPriv.Destroy()

	identityPub, err := identityPriv.PublicKey()
	if err != nil {
		return fmt.Errorf("get identity public: %w", err)
	}
	defer identityPub.Destroy()

	identityPubBytes, _ := identityPub.Serialize()
	fmt.Printf("=== LOCAL ===\n")
	fmt.Printf("Identity public key: %s\n", hex.EncodeToString(identityPubBytes))

	// Load ACI signed pre-key
	spk, err := s.LoadSignedPreKey(1)
	if err != nil {
		return fmt.Errorf("load signed pre-key: %w", err)
	}
	if spk == nil {
		return fmt.Errorf("ACI signed pre-key not found (ID 1)")
	}
	defer spk.Destroy()

	spkID, _ := spk.ID()
	spkPub, err := spk.PublicKey()
	if err != nil {
		return fmt.Errorf("get spk public: %w", err)
	}
	defer spkPub.Destroy()

	localSPKBytes, _ := spkPub.Serialize()
	fmt.Printf("ACI Signed pre-key ID: %d\n", spkID)
	fmt.Printf("ACI Signed pre-key public: %s\n", hex.EncodeToString(localSPKBytes))

	sig, err := spk.Signature()
	if err != nil {
		return fmt.Errorf("get signature: %w", err)
	}
	fmt.Printf("ACI Signature: %s\n", hex.EncodeToString(sig))

	// Verify signature
	valid, err := identityPub.Verify(localSPKBytes, sig)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}
	fmt.Printf("ACI Signature valid: %v\n", valid)

	// Load ACI Kyber pre-key
	var localKPKBytes []byte
	kpk, err := s.LoadKyberPreKey(1)
	if err != nil {
		return fmt.Errorf("load kyber pre-key: %w", err)
	}
	if kpk == nil {
		fmt.Println("ACI Kyber pre-key not found (ID 1)")
	} else {
		defer kpk.Destroy()
		kpkID, _ := kpk.ID()
		kpkPub, _ := kpk.PublicKey()
		if kpkPub != nil {
			defer kpkPub.Destroy()
			localKPKBytes, _ = kpkPub.Serialize()
			fmt.Printf("ACI Kyber pre-key ID: %d\n", kpkID)
			fmt.Printf("ACI Kyber pre-key public: %s... (%d bytes)\n", hex.EncodeToString(localKPKBytes[:32]), len(localKPKBytes))
		}
	}

	// Fetch server pre-keys
	fmt.Printf("\n=== SERVER ===\n")
	auth := signalservice.BasicAuth{
		Username: fmt.Sprintf("%s.%d", acct.ACI, acct.DeviceID),
		Password: acct.Password,
	}
	transport := signalservice.NewTransport("https://chat.signal.org", signalservice.TLSConfig(), nil)
	path := fmt.Sprintf("/v2/keys/%s/%d", acct.ACI, acct.DeviceID)
	respBody, status, err := transport.Get(ctx, path, &auth)
	if err != nil {
		return fmt.Errorf("get server pre-keys: %w", err)
	}
	if status != http.StatusOK {
		return fmt.Errorf("get server pre-keys: status %d: %s", status, respBody)
	}
	var serverKeys signalservice.PreKeyResponse
	if err := json.Unmarshal(respBody, &serverKeys); err != nil {
		return fmt.Errorf("unmarshal pre-keys: %w", err)
	}

	fmt.Printf("Server identity key: %s\n", serverKeys.IdentityKey)
	for _, dev := range serverKeys.Devices {
		if dev.DeviceID == acct.DeviceID {
			if dev.SignedPreKey != nil {
				serverSPKBytes, _ := base64.RawStdEncoding.DecodeString(dev.SignedPreKey.PublicKey)
				fmt.Printf("Server signed pre-key ID: %d\n", dev.SignedPreKey.KeyID)
				fmt.Printf("Server signed pre-key public: %s\n", hex.EncodeToString(serverSPKBytes))
				if hex.EncodeToString(localSPKBytes) == hex.EncodeToString(serverSPKBytes) {
					fmt.Printf("✓ Signed pre-key MATCH\n")
				} else {
					fmt.Printf("✗ Signed pre-key MISMATCH\n")
				}
			}
			if dev.PqPreKey != nil {
				serverKPKBytes, _ := base64.RawStdEncoding.DecodeString(dev.PqPreKey.PublicKey)
				fmt.Printf("Server Kyber pre-key ID: %d\n", dev.PqPreKey.KeyID)
				fmt.Printf("Server Kyber pre-key public: %s... (%d bytes)\n", hex.EncodeToString(serverKPKBytes[:32]), len(serverKPKBytes))
				if len(localKPKBytes) > 0 && hex.EncodeToString(localKPKBytes) == hex.EncodeToString(serverKPKBytes) {
					fmt.Printf("✓ Kyber pre-key MATCH\n")
				} else {
					fmt.Printf("✗ Kyber pre-key MISMATCH\n")
				}
			}
		}
	}

	return nil
}
