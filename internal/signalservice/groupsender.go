package signalservice

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// SendGroupMessage sends a text message to a group.
// Uses sender key encryption (type 7) with sealed sender delivery.
func (s *Service) SendGroupMessage(ctx context.Context, groupID string, text string) error {
	timestamp := uint64(time.Now().UnixMilli())

	// Look up group in store
	group, err := s.store.GetGroup(groupID)
	if err != nil {
		return fmt.Errorf("get group: %w", err)
	}
	if group == nil {
		return fmt.Errorf("group not found: %s", groupID)
	}

	// Ensure we have member list
	if len(group.MemberACIs) == 0 {
		// Try to fetch group details
		if err := s.FetchGroupDetails(ctx, group); err != nil {
			return fmt.Errorf("fetch group details: %w", err)
		}
		if err := s.store.SaveGroup(group); err != nil {
			return fmt.Errorf("save group: %w", err)
		}
	}
	if len(group.MemberACIs) == 0 {
		return fmt.Errorf("group has no members")
	}

	// Load account
	acct, err := s.store.LoadAccount()
	if err != nil {
		return fmt.Errorf("load account: %w", err)
	}

	// Derive distribution ID from group master key
	// The distribution ID is the first 16 bytes of the GroupIdentifier
	var masterKey libsignal.GroupMasterKey
	copy(masterKey[:], group.MasterKey)

	secretParams, err := libsignal.DeriveGroupSecretParams(masterKey)
	if err != nil {
		return fmt.Errorf("derive group secret params: %w", err)
	}

	publicParams, err := secretParams.GetPublicParams()
	if err != nil {
		return fmt.Errorf("get public params: %w", err)
	}

	groupIdentifier, err := publicParams.GetGroupIdentifier()
	if err != nil {
		return fmt.Errorf("get group identifier: %w", err)
	}

	// Distribution ID is derived from the group - use first 16 bytes of GroupIdentifier
	var distributionID [16]byte
	copy(distributionID[:], groupIdentifier[:16])

	logf(s.logger, "group send: distributionID=%x groupIdentifier=%x", distributionID, groupIdentifier)

	// Build GroupContextV2 for the message
	revision := uint32(group.Revision)
	groupContext := &proto.GroupContextV2{
		MasterKey: group.MasterKey,
		Revision:  &revision,
	}

	// Build the DataMessage with group context
	expireTimer := uint32(0)
	requiredProtocolVersion := uint32(0)
	expireTimerVersion := uint32(1)

	dm := &proto.DataMessage{
		Body:                    &text,
		Timestamp:               &timestamp,
		GroupV2:                 groupContext,
		ExpireTimer:             &expireTimer,
		RequiredProtocolVersion: &requiredProtocolVersion,
		ExpireTimerVersion:      &expireTimerVersion,
	}

	if acct != nil && len(acct.ProfileKey) > 0 {
		dm.ProfileKey = acct.ProfileKey
	}

	content := &proto.Content{
		DataMessage: dm,
	}

	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return fmt.Errorf("marshal content: %w", err)
	}

	// Add Signal transport padding
	paddedContent := padMessage(contentBytes)

	// Create our local sender address
	localAddr, err := libsignal.NewAddress(acct.ACI, uint32(acct.DeviceID))
	if err != nil {
		return fmt.Errorf("create local address: %w", err)
	}
	defer localAddr.Destroy()

	// Get sender certificate for sealed sender
	senderCertBytes, err := s.GetSenderCertificate(ctx)
	if err != nil {
		return fmt.Errorf("get sender certificate: %w", err)
	}
	senderCert, err := libsignal.DeserializeSenderCertificate(senderCertBytes)
	if err != nil {
		return fmt.Errorf("deserialize sender certificate: %w", err)
	}
	defer senderCert.Destroy()

	// Filter out self from members
	var recipients []string
	for _, aci := range group.MemberACIs {
		if aci != acct.ACI {
			recipients = append(recipients, aci)
		}
	}

	if len(recipients) == 0 {
		return fmt.Errorf("no other members in group")
	}

	logf(s.logger, "group send: sending to %d members in group %s", len(recipients), group.Name)

	// Step 1: Distribute sender keys to members who don't have them
	// Create sender key distribution message
	skdm, err := libsignal.CreateSenderKeyDistributionMessage(localAddr, distributionID, s.store)
	if err != nil {
		return fmt.Errorf("create sender key distribution message: %w", err)
	}
	defer skdm.Destroy()

	skdmBytes, err := skdm.Serialize()
	if err != nil {
		return fmt.Errorf("serialize skdm: %w", err)
	}

	logf(s.logger, "group send: created SKDM (len=%d) for distributionID=%x", len(skdmBytes), distributionID)

	// Send SKDM to each member via regular encrypted message
	// In production, we'd track who has received the SKDM and only send to new members
	for _, recipient := range recipients {
		if err := s.sendSenderKeyDistribution(ctx, recipient, skdmBytes, senderCert); err != nil {
			logf(s.logger, "group send: failed to send SKDM to %s: %v (continuing)", recipient, err)
			// Continue - they may already have our sender key from previous messages
		} else {
			logf(s.logger, "group send: sent SKDM to %s", recipient)
		}
	}

	// Step 2: Encrypt the message once with sender key
	senderKeyMsg, err := libsignal.GroupEncryptMessage(paddedContent, localAddr, distributionID, s.store)
	if err != nil {
		return fmt.Errorf("group encrypt: %w", err)
	}
	defer senderKeyMsg.Destroy()

	senderKeyBytes, err := senderKeyMsg.Serialize()
	if err != nil {
		return fmt.Errorf("serialize sender key message: %w", err)
	}

	logf(s.logger, "group send: encrypted message with sender key (type 7)")

	// Step 3: Wrap in sealed sender and send to each member
	var succeeded, failed int
	for _, recipient := range recipients {
		if err := s.sendGroupSealedMessage(ctx, recipient, senderKeyBytes, senderCert, groupIdentifier[:]); err != nil {
			logf(s.logger, "group send: failed to send to %s: %v", recipient, err)
			failed++
			continue
		}
		logf(s.logger, "group send: sent to %s", recipient)
		succeeded++
	}

	if succeeded == 0 {
		return fmt.Errorf("failed to send to any of %d recipients", len(recipients))
	}

	logf(s.logger, "group send: sent to %d/%d members", succeeded, len(recipients))

	// Step 4: Send sync message to our other devices so they show the sent message
	if err := s.sendGroupSyncMessage(ctx, dm, timestamp, recipients, senderCert); err != nil {
		logf(s.logger, "group send: failed to send sync message: %v", err)
		// Don't fail the whole send - the message was delivered to recipients
	} else {
		logf(s.logger, "group send: sent sync message to self")
	}

	return nil
}

// sendSenderKeyDistribution sends a sender key distribution message to a recipient
// using a regular 1:1 encrypted message.
func (s *Service) sendSenderKeyDistribution(ctx context.Context, recipient string, skdmBytes []byte, senderCert *libsignal.SenderCertificate) error {
	// Build Content with SenderKeyDistributionMessage
	content := &proto.Content{
		SenderKeyDistributionMessage: skdmBytes,
	}

	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return fmt.Errorf("marshal content: %w", err)
	}

	// Get recipient's profile key for access key
	contact, err := s.store.GetContactByACI(recipient)
	if err != nil {
		return fmt.Errorf("get contact: %w", err)
	}

	// If we have a profile key, use sealed sender; otherwise fall back to regular
	if contact != nil && len(contact.ProfileKey) > 0 {
		accessKey, err := DeriveAccessKey(contact.ProfileKey)
		if err != nil {
			return fmt.Errorf("derive access key: %w", err)
		}
		return s.sendSealedEncrypted(ctx, recipient, contentBytes, senderCert, accessKey)
	}

	// Fall back to regular encrypted message
	return s.sendEncryptedMessage(ctx, recipient, contentBytes)
}

// sendGroupSealedMessage wraps a sender key ciphertext in sealed sender and sends it.
// This is different from regular sealed sender because the inner message is already
// encrypted with sender key (type 7), not a session message.
// Handles 409 device mismatch with retry.
func (s *Service) sendGroupSealedMessage(ctx context.Context, recipient string, senderKeyBytes []byte, senderCert *libsignal.SenderCertificate, groupID []byte) error {
	// Get recipient's profile key for access key
	contact, err := s.store.GetContactByACI(recipient)
	if err != nil {
		return fmt.Errorf("get contact: %w", err)
	}
	if contact == nil || len(contact.ProfileKey) == 0 {
		return fmt.Errorf("no profile key (run sync-contacts or receive a message from them first)")
	}

	accessKey, err := DeriveAccessKey(contact.ProfileKey)
	if err != nil {
		return fmt.Errorf("derive access key: %w", err)
	}

	// Get recipient's devices
	deviceIDs, _ := s.store.GetDevices(recipient)
	if len(deviceIDs) == 0 {
		deviceIDs = []int{1}
	}

	// Retry loop for 409 device mismatch
	const maxAttempts = 3
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err := s.trySendGroupSealed(ctx, recipient, senderKeyBytes, senderCert, groupID, accessKey, deviceIDs)
		if err == nil {
			return nil
		}

		// Check for 409 device mismatch
		var mismatch *MismatchedDevicesError
		if errors.As(err, &mismatch) {
			logf(s.logger, "group send 409: missing=%v extra=%v (attempt %d)", mismatch.MissingDevices, mismatch.ExtraDevices, attempt)

			// Update device list
			deviceIDs = updateDeviceList(deviceIDs, mismatch.MissingDevices, mismatch.ExtraDevices)
			s.store.SetDevices(recipient, deviceIDs)

			// Archive sessions for extra devices
			for _, devID := range mismatch.ExtraDevices {
				s.store.ArchiveSession(recipient, uint32(devID))
			}
			continue
		}

		return err
	}

	return fmt.Errorf("failed after %d attempts", maxAttempts)
}

// trySendGroupSealed attempts to send a sender key message to specific devices.
func (s *Service) trySendGroupSealed(ctx context.Context, recipient string, senderKeyBytes []byte, senderCert *libsignal.SenderCertificate, groupID []byte, accessKey []byte, deviceIDs []int) error {
	timestamp := uint64(time.Now().UnixMilli())
	var messages []OutgoingMessage

	for _, deviceID := range deviceIDs {
		addr, err := libsignal.NewAddress(recipient, uint32(deviceID))
		if err != nil {
			return fmt.Errorf("create address: %w", err)
		}

		// Get registration ID for this device
		registrationID := 0
		session, err := s.store.LoadSession(addr)
		if err == nil && session != nil {
			regID, _ := session.RemoteRegistrationID()
			session.Destroy()
			registrationID = int(regID)
		}

		// Create USMC wrapping the sender key message
		usmc, err := createSenderKeyUSMC(senderKeyBytes, senderCert, groupID)
		if err != nil {
			addr.Destroy()
			return fmt.Errorf("create sender key USMC: %w", err)
		}

		// Seal the message
		sealed, err := libsignal.SealedSenderEncrypt(addr, usmc, s.store)
		usmc.Destroy()
		addr.Destroy()
		if err != nil {
			return fmt.Errorf("seal: %w", err)
		}

		messages = append(messages, OutgoingMessage{
			Type:                      proto.Envelope_UNIDENTIFIED_SENDER,
			DestinationDeviceID:       deviceID,
			DestinationRegistrationID: registrationID,
			Content:                   base64.StdEncoding.EncodeToString(sealed),
		})
	}

	msgList := &OutgoingMessageList{
		Destination: recipient,
		Timestamp:   timestamp,
		Messages:    messages,
		Urgent:      true,
	}

	return s.SendSealedMessage(ctx, recipient, msgList, accessKey)
}

// updateDeviceList adds missing devices and removes extra devices.
func updateDeviceList(current []int, missing, extra []int) []int {
	// Remove extra devices
	extraSet := make(map[int]bool)
	for _, d := range extra {
		extraSet[d] = true
	}
	var result []int
	for _, d := range current {
		if !extraSet[d] {
			result = append(result, d)
		}
	}
	// Add missing devices
	result = append(result, missing...)
	return result
}

// createSenderKeyUSMC creates an UnidentifiedSenderMessageContent for a sender key message.
// Sender key messages (type 7) need to be wrapped in USMC differently than session messages.
// sendGroupSyncMessage sends a SyncMessage.Sent to our other devices so they
// display the outgoing group message in the conversation.
func (s *Service) sendGroupSyncMessage(ctx context.Context, dm *proto.DataMessage, timestamp uint64, recipients []string, senderCert *libsignal.SenderCertificate) error {
	acct, err := s.store.LoadAccount()
	if err != nil {
		return fmt.Errorf("load account: %w", err)
	}

	// Build UnidentifiedDeliveryStatus for each recipient
	var statuses []*proto.SyncMessage_Sent_UnidentifiedDeliveryStatus
	for _, recipient := range recipients {
		unidentified := true
		statuses = append(statuses, &proto.SyncMessage_Sent_UnidentifiedDeliveryStatus{
			DestinationServiceId: &recipient,
			Unidentified:         &unidentified,
		})
	}

	// Build SyncMessage.Sent
	sent := &proto.SyncMessage_Sent{
		Timestamp:          &timestamp,
		Message:            dm,
		UnidentifiedStatus: statuses,
	}

	syncMessage := &proto.SyncMessage{
		Sent: sent,
	}

	content := &proto.Content{
		SyncMessage: syncMessage,
	}

	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return fmt.Errorf("marshal sync message: %w", err)
	}

	// Get our devices and exclude the current one
	deviceIDs, _ := s.store.GetDevices(acct.ACI)
	if len(deviceIDs) == 0 {
		// Default to devices 1 and 2 if we don't have device info
		deviceIDs = []int{1, 2}
	}

	// Filter out our own device
	var otherDevices []int
	for _, d := range deviceIDs {
		if d != acct.DeviceID {
			otherDevices = append(otherDevices, d)
		}
	}

	if len(otherDevices) == 0 {
		logf(s.logger, "sync: no other devices to sync to")
		return nil
	}

	// Temporarily set the device list for self to only include other devices
	s.store.SetDevices(acct.ACI, otherDevices)
	defer func() {
		// Restore full device list including our device
		allDevices := append(otherDevices, acct.DeviceID)
		s.store.SetDevices(acct.ACI, allDevices)
	}()

	// For sync messages to self, use regular encrypted messages (not sealed sender)
	// to avoid access key issues with the server's device list validation
	return s.sendEncryptedMessage(ctx, acct.ACI, contentBytes)
}

func createSenderKeyUSMC(senderKeyBytes []byte, senderCert *libsignal.SenderCertificate, groupID []byte) (*libsignal.UnidentifiedSenderMessageContent, error) {
	// Use the type-aware constructor for sender key messages (type 7)
	return libsignal.NewUnidentifiedSenderMessageContentFromType(
		senderKeyBytes,
		libsignal.CiphertextMessageTypeSenderKey,
		senderCert,
		libsignal.ContentHintResendable,
		groupID,
	)
}

// GetGroupByIdentifier looks up a group by its hex-encoded GroupIdentifier.
func (s *Service) GetGroupByIdentifier(groupID string) (*store.Group, error) {
	return s.store.GetGroup(groupID)
}

// parseGroupID converts a hex-encoded group ID to bytes.
func parseGroupID(groupID string) ([]byte, error) {
	return hex.DecodeString(groupID)
}
