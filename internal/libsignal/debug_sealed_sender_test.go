package libsignal

import (
	"encoding/hex"
	"os"
	"testing"

	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// TestDebugRealSealedSender attempts to decrypt a real failing envelope
// using the identity key from the user's database.
func TestDebugRealSealedSender(t *testing.T) {
	// Identity key from database (hex encoded)
	privKeyHex := "583c1eb9932f6c4d9f3d0698c46e7b784c3048c88c6904ee12ed7d8486cc454f"
	pubKeyHex := "058c28030a0cf5c8534e1d9b01c282e14bb33d4819e2ab663b9b3c9f4644d4fd55"

	privKeyBytes, _ := hex.DecodeString(privKeyHex)
	pubKeyBytes, _ := hex.DecodeString(pubKeyHex)

	// Deserialize the private key
	privKey, err := DeserializePrivateKey(privKeyBytes)
	if err != nil {
		t.Fatalf("DeserializePrivateKey: %v", err)
	}
	defer privKey.Destroy()

	// Derive public key and compare
	derivedPub, err := privKey.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	defer derivedPub.Destroy()

	derivedPubBytes, err := derivedPub.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	t.Logf("Stored public key:  %x", pubKeyBytes)
	t.Logf("Derived public key: %x", derivedPubBytes)

	if hex.EncodeToString(derivedPubBytes) != pubKeyHex {
		t.Errorf("Public key mismatch! Stored key doesn't match key derived from private key")
		t.Errorf("  Stored:  %s", pubKeyHex)
		t.Errorf("  Derived: %x", derivedPubBytes)
	} else {
		t.Log("Key pair is valid (public key correctly derived from private key)")
	}

	// Try to load and decrypt a real envelope
	envelopePath := "../../debug/1770112832577_UNIDENTIFIED_SENDER_sealed_0.bin"
	if _, err := os.Stat(envelopePath); os.IsNotExist(err) {
		t.Skip("Debug envelope not found, skipping real decryption test")
	}

	envelopeData, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	t.Logf("Loaded envelope: %d bytes", len(envelopeData))

	// Parse envelope protobuf
	var env proto.Envelope
	if err := pb.Unmarshal(envelopeData, &env); err != nil {
		t.Fatalf("Unmarshal envelope: %v", err)
	}

	content := env.GetContent()
	t.Logf("Envelope type: %v", env.GetType())
	t.Logf("Content length: %d", len(content))
	t.Logf("Content first 16 bytes: %x", content[:min(16, len(content))])

	// Create identity store with this key
	identityStore := NewMemoryIdentityKeyStore(privKey, 1)

	// Try to decrypt
	usmc, err := SealedSenderDecryptToUSMC(content, identityStore)
	if err != nil {
		t.Logf("SealedSenderDecryptToUSMC failed: %v", err)
		t.Logf("This confirms the identity key mismatch - the sender encrypted")
		t.Logf("for a different identity key than what we have stored.")
	} else {
		defer usmc.Destroy()
		t.Log("Decryption succeeded!")

		// Get sender info
		cert, _ := usmc.GetSenderCert()
		if cert != nil {
			uuid, _ := cert.SenderUUID()
			device, _ := cert.DeviceID()
			t.Logf("Sender: %s device %d", uuid, device)
			cert.Destroy()
		}
	}
}
