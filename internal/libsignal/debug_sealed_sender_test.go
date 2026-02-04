package libsignal

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// AnalyzeSealedSenderPayload parses a sealed sender payload and returns debug info
// without attempting decryption. This helps diagnose whether failures are due to
// malformed outer structure vs decryption issues.
func AnalyzeSealedSenderPayload(payload []byte) (string, error) {
	if len(payload) == 0 {
		return "", fmt.Errorf("empty payload")
	}

	versionByte := payload[0]
	version := versionByte >> 4
	remaining := payload[1:]

	result := fmt.Sprintf("Version byte: 0x%02x (major version %d)\n", versionByte, version)
	result += fmt.Sprintf("Payload length: %d bytes (after version: %d)\n", len(payload), len(remaining))

	switch version {
	case 0, 1:
		// SSv1: parse as UnidentifiedSenderMessage protobuf
		result += "Format: Sealed Sender v1\n"

		// Try parsing as protobuf
		var ssMsg proto.UnidentifiedSenderMessage
		if err := pb.Unmarshal(remaining, &ssMsg); err != nil {
			result += fmt.Sprintf("Protobuf parse FAILED: %v\n", err)
			result += fmt.Sprintf("First 32 bytes after version: %x\n", remaining[:min(32, len(remaining))])
			return result, fmt.Errorf("SSv1 protobuf parse failed: %w", err)
		}

		result += "Protobuf parse: SUCCESS\n"
		result += fmt.Sprintf("  ephemeralPublic: %d bytes\n", len(ssMsg.GetEphemeralPublic()))
		result += fmt.Sprintf("  encryptedStatic: %d bytes\n", len(ssMsg.GetEncryptedStatic()))
		result += fmt.Sprintf("  encryptedMessage: %d bytes\n", len(ssMsg.GetEncryptedMessage()))

		// Validate ephemeral public key format
		ephPub := ssMsg.GetEphemeralPublic()
		if len(ephPub) > 0 {
			result += fmt.Sprintf("  ephemeralPublic first byte: 0x%02x ", ephPub[0])
			if ephPub[0] == 0x05 {
				result += "(valid Curve25519 key prefix)\n"
			} else {
				result += "(UNEXPECTED - should be 0x05 for Curve25519)\n"
			}
		}

	case 2:
		// SSv2
		result += "Format: Sealed Sender v2\n"
		if versionByte == 0x22 {
			result += "  Variant: UUID (0x22)\n"
		} else if versionByte == 0x23 {
			result += "  Variant: ServiceId (0x23)\n"
		}
		// SSv2 uses fixed-size binary format, not protobuf for outer layer
		if len(remaining) < 33+48+16 { // minimum: ephemeral key + encrypted key + auth tag
			return result, fmt.Errorf("SSv2 payload too short: %d bytes", len(remaining))
		}
		result += fmt.Sprintf("  Remaining bytes: %d\n", len(remaining))

	default:
		return result, fmt.Errorf("unknown sealed sender version %d", version)
	}

	return result, nil
}

// TestAnalyzeSealedSenderPayload parses the outer sealed sender structure
// without decryption, to diagnose whether failures are due to malformed
// outer structure vs decryption issues.
func TestAnalyzeSealedSenderPayload(t *testing.T) {
	// Try to load a real envelope
	envelopePath := "../../debug/1770112832577_UNIDENTIFIED_SENDER_sealed_0.bin"
	if _, err := os.Stat(envelopePath); os.IsNotExist(err) {
		t.Skip("Debug envelope not found, skipping analysis test")
	}

	envelopeData, err := os.ReadFile(envelopePath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	// Parse envelope protobuf
	var env proto.Envelope
	if err := pb.Unmarshal(envelopeData, &env); err != nil {
		t.Fatalf("Unmarshal envelope: %v", err)
	}

	content := env.GetContent()
	t.Logf("Envelope type: %v", env.GetType())
	t.Logf("Content length: %d bytes", len(content))

	// Analyze the sealed sender payload
	analysis, err := AnalyzeSealedSenderPayload(content)
	t.Log(analysis)
	if err != nil {
		t.Logf("Analysis error: %v", err)
	}
}

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
