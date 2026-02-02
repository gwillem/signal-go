package signalservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// ParseContactStream parses a varint-length-prefixed stream of ContactDetails protobufs.
// After each ContactDetails with an Avatar, the avatar bytes (Avatar.Length) are skipped.
func ParseContactStream(data []byte) ([]*proto.ContactDetails, error) {
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

// RequestContactSync sends a SyncMessage.Request{Type:CONTACTS} to our own
// primary device (device 1) to trigger a contact sync response.
func RequestContactSync(ctx context.Context, apiURL string, st *store.Store, auth BasicAuth, localACI string, tlsConf *tls.Config, logger *log.Logger) error {
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

	// Encrypt to self (device 1 = primary).
	addr, err := libsignal.NewAddress(localACI, 1)
	if err != nil {
		return fmt.Errorf("contactsync: create address: %w", err)
	}
	defer addr.Destroy()

	httpClient := NewHTTPClient(apiURL, tlsConf)
	now := time.Now()

	// Check if session exists, if not fetch pre-keys.
	session, err := st.LoadSession(addr)
	if err != nil {
		return fmt.Errorf("contactsync: load session: %w", err)
	}

	var registrationID int
	if session == nil {
		preKeyResp, err := httpClient.GetPreKeys(ctx, localACI, 1, auth)
		if err != nil {
			return fmt.Errorf("contactsync: get pre-keys: %w", err)
		}
		if len(preKeyResp.Devices) == 0 {
			return fmt.Errorf("contactsync: no devices in pre-key response")
		}

		dev := preKeyResp.Devices[0]
		registrationID = dev.RegistrationID

		bundle, err := buildPreKeyBundle(preKeyResp.IdentityKey, dev)
		if err != nil {
			return fmt.Errorf("contactsync: build pre-key bundle: %w", err)
		}
		defer bundle.Destroy()

		if err := libsignal.ProcessPreKeyBundle(bundle, addr, st, st, now); err != nil {
			return fmt.Errorf("contactsync: process pre-key bundle: %w", err)
		}
	} else {
		session.Destroy()
	}

	ciphertext, err := libsignal.Encrypt(contentBytes, addr, st, st, now)
	if err != nil {
		return fmt.Errorf("contactsync: encrypt: %w", err)
	}
	defer ciphertext.Destroy()

	msgType, err := ciphertext.Type()
	if err != nil {
		return fmt.Errorf("contactsync: ciphertext type: %w", err)
	}

	ctBytes, err := ciphertext.Serialize()
	if err != nil {
		return fmt.Errorf("contactsync: serialize ciphertext: %w", err)
	}

	timestamp := uint64(now.UnixMilli())

	msgList := &OutgoingMessageList{
		Destination: localACI,
		Timestamp:   timestamp,
		Messages: []OutgoingMessage{
			{
				Type:                      int(msgType),
				DestinationDeviceID:       1,
				DestinationRegistrationID: registrationID,
				Content:                   base64.StdEncoding.EncodeToString(ctBytes),
			},
		},
		Urgent: true,
	}

	logf(logger, "requesting contact sync from primary device")
	return httpClient.SendMessage(ctx, localACI, msgList, auth)
}
