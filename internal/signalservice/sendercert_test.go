package signalservice

import (
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

func TestParseSenderCertificate(t *testing.T) {
	// Real sender certificate from Signal server (148 bytes decoded)
	// Uses the new compact format: uuidBytes (field 7) and signerId (field 8)
	b64 := "ClAKDCszMTYyNjQzOTk5ORABGb/Uk06cAQAAIiEFUObHsiMjD9kLQNfqxx+mlf+WB3JpD/8RCoidACXJMy86EKiJrBAak0xCjqjyuoKVhZdAAxJAZ6hy0QoTWza2xGE6LhdS1/E1k7xPXm8j6XHvbr/bryrRHohuXHZWD5xhG/StRzpZxRTYxcvSZ/Retu/fFFiiCw=="

	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("base64 decode: %v", err)
	}
	t.Logf("Decoded %d bytes", len(data))
	t.Logf("Hex: %s", hex.EncodeToString(data[:min(50, len(data))]))

	// Parse with Go protobuf
	var cert proto.SenderCertificate
	if err := pb.Unmarshal(data, &cert); err != nil {
		t.Fatalf("Unmarshal SenderCertificate: %v", err)
	}

	t.Logf("Certificate field: %d bytes", len(cert.GetCertificate()))
	t.Logf("Signature field: %d bytes", len(cert.GetSignature()))

	if len(cert.GetCertificate()) == 0 {
		t.Fatal("certificate field is empty")
	}
	if len(cert.GetSignature()) == 0 {
		t.Fatal("signature field is empty")
	}

	// Parse inner Certificate
	var inner proto.SenderCertificate_Certificate
	if err := pb.Unmarshal(cert.GetCertificate(), &inner); err != nil {
		t.Fatalf("Unmarshal inner Certificate: %v", err)
	}

	t.Logf("senderE164: %q", inner.GetSenderE164())
	t.Logf("uuidString: %q", inner.GetUuidString())
	t.Logf("uuidBytes: %d bytes, %x", len(inner.GetUuidBytes()), inner.GetUuidBytes())
	t.Logf("senderDevice: %d", inner.GetSenderDevice())
	t.Logf("expires: %d", inner.GetExpires())
	t.Logf("identityKey: %d bytes", len(inner.GetIdentityKey()))
	t.Logf("signerCertificate: %d bytes", len(inner.GetSignerCertificate()))
	t.Logf("signerId: %d", inner.GetSignerId())

	// Check required fields - new format uses uuidBytes and signerId
	senderUUID := inner.GetUuidString()
	if senderUUID == "" && len(inner.GetUuidBytes()) > 0 {
		// Parse UUID from bytes
		u, err := uuid.FromBytes(inner.GetUuidBytes())
		if err != nil {
			t.Errorf("parse uuidBytes: %v", err)
		} else {
			senderUUID = u.String()
			t.Logf("Parsed sender UUID from bytes: %s", senderUUID)
		}
	}
	if senderUUID == "" {
		t.Error("senderUuid is empty (neither uuidString nor uuidBytes present)")
	}

	if inner.GetSenderDevice() == 0 {
		t.Error("senderDevice is 0")
	}
	if inner.GetExpires() == 0 {
		t.Error("expires is 0")
	}
	if len(inner.GetIdentityKey()) == 0 {
		t.Error("identityKey is empty")
	}

	// Check signer - new format uses signerId instead of signerCertificate
	if len(inner.GetSignerCertificate()) == 0 && inner.GetSignerId() == 0 {
		t.Error("signer is missing (neither signerCertificate nor signerId present)")
	}
	if inner.GetSignerId() > 0 {
		t.Logf("Using server certificate ID: %d", inner.GetSignerId())
	}
}
