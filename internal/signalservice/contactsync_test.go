package signalservice

import (
	"encoding/binary"
	"testing"

	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// encodeVarint encodes n as a protobuf varint.
func encodeVarint(n uint64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	l := binary.PutUvarint(buf, n)
	return buf[:l]
}

func buildContactStream(t *testing.T, contacts ...*proto.ContactDetails) []byte {
	t.Helper()
	var out []byte
	for _, c := range contacts {
		data, err := pb.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, encodeVarint(uint64(len(data)))...)
		out = append(out, data...)
	}
	return out
}

func TestParseContactStream(t *testing.T) {
	num1 := "+15551111111"
	aci1 := "aaaa-bbbb-cccc"
	name1 := "Alice"
	num2 := "+15552222222"
	aci2 := "dddd-eeee-ffff"

	stream := buildContactStream(t,
		&proto.ContactDetails{Number: &num1, Aci: &aci1, Name: &name1},
		&proto.ContactDetails{Number: &num2, Aci: &aci2},
	)

	contacts, err := parseContactStream(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 2 {
		t.Fatalf("got %d contacts, want 2", len(contacts))
	}
	if contacts[0].GetNumber() != num1 {
		t.Errorf("contact 0 number = %q, want %q", contacts[0].GetNumber(), num1)
	}
	if contacts[0].GetAci() != aci1 {
		t.Errorf("contact 0 aci = %q, want %q", contacts[0].GetAci(), aci1)
	}
	if contacts[0].GetName() != name1 {
		t.Errorf("contact 0 name = %q, want %q", contacts[0].GetName(), name1)
	}
	if contacts[1].GetNumber() != num2 {
		t.Errorf("contact 1 number = %q, want %q", contacts[1].GetNumber(), num2)
	}
	if contacts[1].GetAci() != aci2 {
		t.Errorf("contact 1 aci = %q, want %q", contacts[1].GetAci(), aci2)
	}
}

func TestParseContactStream_Empty(t *testing.T) {
	contacts, err := parseContactStream(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 0 {
		t.Fatalf("got %d contacts, want 0", len(contacts))
	}
}

func TestParseContactStream_WithAvatar(t *testing.T) {
	num := "+15553333333"
	aci := "xxxx-yyyy"
	avatarContentType := "image/jpeg"
	avatarLen := uint32(100)

	stream := buildContactStream(t,
		&proto.ContactDetails{
			Number: &num,
			Aci:    &aci,
			Avatar: &proto.ContactDetails_Avatar{
				ContentType: &avatarContentType,
				Length:      &avatarLen,
			},
		},
	)
	// Append 100 bytes of fake avatar data after the protobuf.
	stream = append(stream, make([]byte, 100)...)

	contacts, err := parseContactStream(stream)
	if err != nil {
		t.Fatal(err)
	}
	if len(contacts) != 1 {
		t.Fatalf("got %d contacts, want 1", len(contacts))
	}
	if contacts[0].GetNumber() != num {
		t.Errorf("number = %q, want %q", contacts[0].GetNumber(), num)
	}
}
