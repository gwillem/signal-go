package signalservice

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// parseContactStream parses a varint-length-prefixed stream of ContactDetails protobufs.
// After each ContactDetails with an Avatar, the avatar bytes (Avatar.Length) are skipped.
func parseContactStream(data []byte) ([]*proto.ContactDetails, error) {
	var contacts []*proto.ContactDetails
	offset := 0

	for offset < len(data) {
		// Read varint length prefix.
		msgLen, n := binary.Uvarint(data[offset:])
		if n <= 0 {
			return nil, fmt.Errorf("contactsync: invalid varint at offset %d", offset)
		}
		offset += n

		if offset+int(msgLen) > len(data) {
			return nil, fmt.Errorf("contactsync: message overflows data at offset %d", offset)
		}

		var cd proto.ContactDetails
		if err := pb.Unmarshal(data[offset:offset+int(msgLen)], &cd); err != nil {
			return nil, fmt.Errorf("contactsync: unmarshal at offset %d: %w", offset, err)
		}
		offset += int(msgLen)

		// Skip inline avatar bytes if present.
		if av := cd.GetAvatar(); av != nil && av.GetLength() > 0 {
			avatarLen := int(av.GetLength())
			if offset+avatarLen > len(data) {
				// Truncated avatar at end of stream — tolerate.
				break
			}
			offset += avatarLen
		}

		contacts = append(contacts, &cd)
	}

	return contacts, nil
}

// requestContactSync sends a SyncMessage.Request{Type:CONTACTS} to our own
// primary device (device 1) to trigger a contact sync response.
func (s *Service) requestContactSync(ctx context.Context) error {
	reqType := proto.SyncMessage_Request_CONTACTS
	content := &proto.Content{
		SyncMessage: &proto.SyncMessage{
			Request: &proto.SyncMessage_Request{
				Type: &reqType,
			},
		},
	}

	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return fmt.Errorf("contactsync: marshal content: %w", err)
	}

	logf(s.logger, "requesting contact sync from primary device")
	return s.sendEncryptedMessage(ctx, s.localACI, contentBytes)
}
