package proto

import (
	"testing"

	pb "google.golang.org/protobuf/proto"
)

func TestProvisionEnvelopeRoundTrip(t *testing.T) {
	original := &ProvisionEnvelope{
		PublicKey: []byte{0x05, 0x01, 0x02, 0x03},
		Body:     []byte{0xaa, 0xbb, 0xcc},
	}
	data, err := pb.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(ProvisionEnvelope)
	if err := pb.Unmarshal(data, decoded); err != nil {
		t.Fatal(err)
	}
	if string(decoded.GetPublicKey()) != string(original.GetPublicKey()) {
		t.Fatalf("publicKey mismatch: got %x, want %x", decoded.GetPublicKey(), original.GetPublicKey())
	}
	if string(decoded.GetBody()) != string(original.GetBody()) {
		t.Fatalf("body mismatch: got %x, want %x", decoded.GetBody(), original.GetBody())
	}
}

func TestProvisionMessageRoundTrip(t *testing.T) {
	number := "+15551234567"
	code := "abc123"
	version := uint32(1)
	original := &ProvisionMessage{
		Number:              &number,
		ProvisioningCode:    &code,
		ProvisioningVersion: &version,
		AciIdentityKeyPublic:  []byte{0x05, 0x01},
		AciIdentityKeyPrivate: []byte{0x02},
		ProfileKey:            []byte{0xde, 0xad},
	}
	data, err := pb.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(ProvisionMessage)
	if err := pb.Unmarshal(data, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetNumber() != number {
		t.Fatalf("number mismatch: got %q, want %q", decoded.GetNumber(), number)
	}
	if decoded.GetProvisioningCode() != code {
		t.Fatalf("code mismatch: got %q, want %q", decoded.GetProvisioningCode(), code)
	}
	if decoded.GetProvisioningVersion() != version {
		t.Fatalf("version mismatch: got %d, want %d", decoded.GetProvisioningVersion(), version)
	}
}

func TestWebSocketMessageRoundTrip(t *testing.T) {
	typ := WebSocketMessage_REQUEST
	verb := "PUT"
	path := "/v1/messages"
	id := uint64(42)
	original := &WebSocketMessage{
		Type: &typ,
		Request: &WebSocketRequestMessage{
			Verb: &verb,
			Path: &path,
			Id:   &id,
			Body: []byte("hello"),
		},
	}
	data, err := pb.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(WebSocketMessage)
	if err := pb.Unmarshal(data, decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.GetType() != typ {
		t.Fatalf("type mismatch: got %v, want %v", decoded.GetType(), typ)
	}
	if decoded.GetRequest().GetVerb() != verb {
		t.Fatalf("verb mismatch: got %q, want %q", decoded.GetRequest().GetVerb(), verb)
	}
	if decoded.GetRequest().GetId() != id {
		t.Fatalf("id mismatch: got %d, want %d", decoded.GetRequest().GetId(), id)
	}
}
