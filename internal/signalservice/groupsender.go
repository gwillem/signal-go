package signalservice

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

// GroupSender handles encrypting and delivering Signal group messages. It
// operates against store interfaces and uses callbacks for HTTP operations
// and cross-boundary Sender operations.
type GroupSender struct {
	dataStore   groupSenderDataStore
	cryptoStore cryptoStore
	logger      *log.Logger
	localACI    string
	localDeviceID int

	// Callbacks for HTTP operations (provided by Service).
	getPreKeys                func(ctx context.Context, recipient string, deviceID int) (*PreKeyResponse, error)
	getSenderCertificate      func(ctx context.Context) ([]byte, error)
	sendSealedHTTPMsg         func(ctx context.Context, destination string, msg *outgoingMessageList, accessKey []byte) error
	sendMultiRecipientHTTPMsg func(ctx context.Context, body []byte, groupSendToken []byte, timestamp uint64) error
	fetchGroupDetails         func(ctx context.Context, group *store.Group) error

	// Callbacks for Sender operations.
	sendEncryptedMessage              func(ctx context.Context, recipient string, contentBytes []byte) error
	sendSealedEncrypted               func(ctx context.Context, recipient string, contentBytes []byte, senderCert *libsignal.SenderCertificate, accessKey []byte) error
	sendEncryptedMessageWithTimestamp func(ctx context.Context, recipient string, contentBytes []byte, timestamp uint64) error
	initialDevices                    func(recipient string, sendingToSelf bool) ([]int, int)
	withDeviceRetry                   func(recipient string, deviceIDs []int, skipDevice int, tryFn func([]int) error) error
}

// sendGroupMessage sends a text message to a group.
// Uses sender key encryption (type 7) with sealed sender v2 multi-recipient delivery.
func (gs *GroupSender) sendGroupMessage(ctx context.Context, groupID string, text string) error {
	timestamp := uint64(time.Now().UnixMilli())

	// Look up group in store
	group, err := gs.dataStore.GetGroup(groupID)
	if err != nil {
		return fmt.Errorf("get group: %w", err)
	}
	if group == nil {
		return fmt.Errorf("group not found: %s", groupID)
	}

	// Ensure we have member list and endorsements
	if len(group.MemberACIs) == 0 || gs.endorsementsExpired(group) {
		if err := gs.fetchGroupDetails(ctx, group); err != nil {
			return fmt.Errorf("fetch group details: %w", err)
		}
		if err := gs.dataStore.SaveGroup(group); err != nil {
			return fmt.Errorf("save group: %w", err)
		}
	}
	if len(group.MemberACIs) == 0 {
		return fmt.Errorf("group has no members")
	}

	// Load account
	acct, err := gs.dataStore.LoadAccount()
	if err != nil {
		return fmt.Errorf("load account: %w", err)
	}

	// Derive group crypto params
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

	// Distribution ID is a random UUID per group (matching Signal-Android).
	// Generate one on first use and persist it.
	if group.DistributionID == "" {
		group.DistributionID = generateDistributionID()
		if err := gs.dataStore.SaveGroup(group); err != nil {
			return fmt.Errorf("save group distribution ID: %w", err)
		}
		logf(gs.logger, "group send: generated new distributionID=%s", group.DistributionID)
	}

	distID, err := uuid.Parse(group.DistributionID)
	if err != nil {
		return fmt.Errorf("parse distribution ID %q: %w", group.DistributionID, err)
	}
	distributionID := [16]byte(distID)

	logf(gs.logger, "group send: distributionID=%s groupIdentifier=%x", group.DistributionID, groupIdentifier[:])

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
	senderCertBytes, err := gs.getSenderCertificate(ctx)
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

	logf(gs.logger, "group send: sending to %d members in group %s", len(recipients), group.Name)

	// Step 1: Send SKDM to members who haven't received our sender key yet.
	// Tracking is per distribution ID + "aci.deviceID" address.
	// ArchiveSession clears tracking, so stale sessions trigger re-send.
	sharedWith, _ := gs.dataStore.GetSenderKeySharedWith(distributionID)
	sharedSet := make(map[string]bool, len(sharedWith))
	for _, addr := range sharedWith {
		sharedSet[addr] = true
	}

	// Find recipients that need SKDM (any device not in sharedSet)
	var needsSKDM []string
	for _, recipient := range recipients {
		devices, _ := gs.dataStore.GetDevices(recipient)
		if len(devices) == 0 {
			devices = []int{1}
		}
		for _, deviceID := range devices {
			addr := fmt.Sprintf("%s.%d", recipient, deviceID)
			if !sharedSet[addr] {
				needsSKDM = append(needsSKDM, recipient)
				break
			}
		}
	}

	if len(needsSKDM) > 0 {
		skdm, err := libsignal.CreateSenderKeyDistributionMessage(localAddr, distributionID, gs.cryptoStore)
		if err != nil {
			return fmt.Errorf("create sender key distribution message: %w", err)
		}
		defer skdm.Destroy()

		skdmBytes, err := skdm.Serialize()
		if err != nil {
			return fmt.Errorf("serialize skdm: %w", err)
		}

		logf(gs.logger, "group send: sending SKDM to %d/%d members", len(needsSKDM), len(recipients))
		for _, recipient := range needsSKDM {
			if err := gs.sendSenderKeyDistribution(ctx, recipient, skdmBytes, senderCert); err != nil {
				logf(gs.logger, "group send: failed to send SKDM to %s: %v (continuing)", recipient, err)
			} else {
				// Mark all devices of this recipient as having received the SKDM
				devices, _ := gs.dataStore.GetDevices(recipient)
				if len(devices) == 0 {
					devices = []int{1}
				}
				var addrs []string
				for _, deviceID := range devices {
					addrs = append(addrs, fmt.Sprintf("%s.%d", recipient, deviceID))
				}
				_ = gs.dataStore.MarkSenderKeySharedWith(distributionID, addrs)
				logf(gs.logger, "group send: sent SKDM to %s", recipient)
			}
		}
	} else {
		logf(gs.logger, "group send: SKDM already shared with all %d members", len(recipients))
	}

	// Step 2: Encrypt the message once with sender key
	senderKeyMsg, err := libsignal.GroupEncryptMessage(paddedContent, localAddr, distributionID, gs.cryptoStore)
	if err != nil {
		return fmt.Errorf("group encrypt: %w", err)
	}
	defer senderKeyMsg.Destroy()

	senderKeyBytes, err := senderKeyMsg.Serialize()
	if err != nil {
		return fmt.Errorf("serialize sender key message: %w", err)
	}

	logf(gs.logger, "group send: encrypted message with sender key (type 7)")

	// Step 3: Compute Group-Send-Token from endorsements
	groupSendToken, err := gs.computeGroupSendToken(group, recipients, acct.ACI, secretParams)
	if err != nil {
		logf(gs.logger, "group send: failed to compute group send token: %v", err)
		// Fall back to per-recipient v1 sealed sender
		return gs.sendGroupV1Fallback(ctx, recipients, senderKeyBytes, senderCert, groupIdentifier[:],
			dm, timestamp)
	}

	// Step 4: Multi-recipient encrypt + send with group-level retry
	err = gs.withGroupDeviceRetry(ctx, func() error {
		return gs.trySendMultiRecipient(ctx, recipients, senderKeyBytes, senderCert,
			groupIdentifier[:], groupSendToken, timestamp)
	})
	if err != nil {
		return fmt.Errorf("group send: %w", err)
	}

	logf(gs.logger, "group send: sent via multi_recipient to %d members", len(recipients))

	// Step 5: Send sync message to our other devices
	if err := gs.sendGroupSyncMessage(ctx, dm, timestamp, recipients); err != nil {
		logf(gs.logger, "group send: failed to send sync message: %v", err)
	} else {
		logf(gs.logger, "group send: sent sync message to self")
	}

	return nil
}

// ensureSession loads or establishes a session for the given address.
// Returns the session and a cleanup function. The caller must call cleanup when done.
func (gs *GroupSender) ensureSession(ctx context.Context, addr *libsignal.Address, recipient string, deviceID int) (*libsignal.SessionRecord, error) {
	session, err := gs.cryptoStore.LoadSession(addr)
	if err != nil {
		return nil, fmt.Errorf("load session for %s.%d: %w", recipient, deviceID, err)
	}
	if session != nil {
		return session, nil
	}

	// Fetch pre-keys and establish session.
	preKeyResp, err := gs.getPreKeys(ctx, recipient, deviceID)
	if err != nil {
		return nil, fmt.Errorf("get prekeys for %s.%d: %w", recipient, deviceID, err)
	}
	if len(preKeyResp.Devices) == 0 {
		return nil, fmt.Errorf("no devices in prekey response for %s.%d", recipient, deviceID)
	}
	bundle, err := buildPreKeyBundle(preKeyResp.IdentityKey, preKeyResp.Devices[0])
	if err != nil {
		return nil, fmt.Errorf("build prekey bundle for %s.%d: %w", recipient, deviceID, err)
	}
	if err := libsignal.ProcessPreKeyBundle(bundle, addr, gs.cryptoStore, gs.cryptoStore, time.Now()); err != nil {
		bundle.Destroy()
		return nil, fmt.Errorf("process prekey bundle for %s.%d: %w", recipient, deviceID, err)
	}
	bundle.Destroy()

	// Reload session after establishing.
	session, err = gs.cryptoStore.LoadSession(addr)
	if err != nil || session == nil {
		return nil, fmt.Errorf("session not established for %s.%d", recipient, deviceID)
	}
	return session, nil
}

// trySendMultiRecipient builds the multi-recipient message and sends it.
func (gs *GroupSender) trySendMultiRecipient(
	ctx context.Context,
	recipients []string,
	senderKeyBytes []byte,
	senderCert *libsignal.SenderCertificate,
	groupID []byte,
	groupSendToken []byte,
	timestamp uint64,
) error {
	// Build list of all recipient addresses + sessions.
	var allAddrs []*libsignal.Address
	var allSessions []*libsignal.SessionRecord
	var cleanups []func()

	defer func() {
		for _, fn := range cleanups {
			fn()
		}
	}()

	for _, recipient := range recipients {
		devices, _ := gs.dataStore.GetDevices(recipient)
		if len(devices) == 0 {
			devices = []int{1}
		}

		for _, deviceID := range devices {
			addr, err := libsignal.NewAddress(recipient, uint32(deviceID))
			if err != nil {
				return fmt.Errorf("create address for %s.%d: %w", recipient, deviceID, err)
			}
			cleanups = append(cleanups, addr.Destroy)

			session, err := gs.ensureSession(ctx, addr, recipient, deviceID)
			if err != nil {
				return err
			}

			allAddrs = append(allAddrs, addr)
			allSessions = append(allSessions, session)
			cleanups = append(cleanups, session.Destroy)
		}
	}

	// Create USMC with ContentHint = IMPLICIT (Signal-Android parity).
	usmc, err := createSenderKeyUSMC(senderKeyBytes, senderCert, groupID)
	if err != nil {
		return fmt.Errorf("create sender key USMC: %w", err)
	}
	defer usmc.Destroy()

	// Multi-recipient encrypt.
	mrmBlob, err := libsignal.SealedSenderMultiRecipientEncrypt(allAddrs, allSessions, usmc, gs.cryptoStore)
	if err != nil {
		return fmt.Errorf("multi-recipient encrypt: %w", err)
	}

	logf(gs.logger, "group send: MRM blob size=%d for %d addresses", len(mrmBlob), len(allAddrs))

	// Send via multi_recipient endpoint.
	return gs.sendMultiRecipientHTTPMsg(ctx, mrmBlob, groupSendToken, timestamp)
}

// endorsementsExpired returns true if the group's endorsements are missing or expired.
func (gs *GroupSender) endorsementsExpired(group *store.Group) bool {
	if len(group.EndorsementsResponse) == 0 {
		return true
	}
	return time.Now().After(group.EndorsementsExpiry)
}

// computeGroupSendToken processes endorsements and produces a Group-Send-Token.
func (gs *GroupSender) computeGroupSendToken(
	group *store.Group,
	recipients []string,
	localACI string,
	secretParams libsignal.GroupSecretParams,
) ([]byte, error) {
	if len(group.EndorsementsResponse) == 0 {
		return nil, fmt.Errorf("no endorsements available")
	}

	serverParams, err := libsignal.GetSignalServerPublicParams()
	if err != nil {
		return nil, fmt.Errorf("get server public params: %w", err)
	}
	defer serverParams.Close()

	groupMembersBytes, err := buildGroupMemberBytes(group.MemberACIs)
	if err != nil {
		return nil, err
	}

	localServiceID, err := aciToServiceID(localACI)
	if err != nil {
		return nil, fmt.Errorf("convert local ACI to service ID: %w", err)
	}

	// Receive endorsements: returns N individual + 1 pre-combined (last element),
	// where N = len(allMembers) - 1 (excluding local user).
	now := uint64(time.Now().Unix())
	endorsements, err := libsignal.ReceiveEndorsements(
		group.EndorsementsResponse,
		groupMembersBytes,
		localServiceID,
		now,
		secretParams,
		serverParams,
	)
	if err != nil {
		return nil, fmt.Errorf("receive endorsements: %w", err)
	}

	logf(gs.logger, "group send: endorsements: members=%d recipients=%d received=%d",
		len(group.MemberACIs), len(recipients), len(endorsements))

	// The last element is the pre-combined endorsement for all non-self members.
	if len(endorsements) == 0 {
		return nil, fmt.Errorf("no endorsements received")
	}
	combined := endorsements[len(endorsements)-1]

	expiration, err := libsignal.EndorsementExpiration(group.EndorsementsResponse)
	if err != nil {
		return nil, fmt.Errorf("get endorsement expiration: %w", err)
	}

	logf(gs.logger, "group send: endorsement expiration=%d combined_len=%d", expiration, len(combined))

	fullToken, err := libsignal.EndorsementToFullToken(combined, secretParams, expiration)
	if err != nil {
		return nil, fmt.Errorf("endorsement to full token: %w", err)
	}

	logf(gs.logger, "group send: full_token_len=%d", len(fullToken))
	return fullToken, nil
}

// sendGroupV1Fallback falls back to per-recipient sealed sender v1 when endorsements
// are not available. This is the old behavior.
func (gs *GroupSender) sendGroupV1Fallback(
	ctx context.Context,
	recipients []string,
	senderKeyBytes []byte,
	senderCert *libsignal.SenderCertificate,
	groupID []byte,
	dm *proto.DataMessage,
	timestamp uint64,
) error {
	logf(gs.logger, "group send: falling back to per-recipient v1 sealed sender")

	var succeeded int
	for _, recipient := range recipients {
		if err := gs.sendGroupSealedMessage(ctx, recipient, senderKeyBytes, senderCert, groupID); err != nil {
			logf(gs.logger, "group send: failed to send to %s: %v", recipient, err)
			continue
		}
		succeeded++
	}

	if succeeded == 0 {
		return fmt.Errorf("failed to send to any of %d recipients", len(recipients))
	}

	logf(gs.logger, "group send: sent to %d/%d members (v1 fallback)", succeeded, len(recipients))

	if err := gs.sendGroupSyncMessage(ctx, dm, timestamp, recipients); err != nil {
		logf(gs.logger, "group send: failed to send sync message: %v", err)
	}

	return nil
}

// sendSenderKeyDistribution sends a sender key distribution message to a recipient
// using a regular 1:1 encrypted message.
func (gs *GroupSender) sendSenderKeyDistribution(ctx context.Context, recipient string, skdmBytes []byte, senderCert *libsignal.SenderCertificate) error {
	// Build Content with SenderKeyDistributionMessage
	content := &proto.Content{
		SenderKeyDistributionMessage: skdmBytes,
	}

	contentBytes, err := pb.Marshal(content)
	if err != nil {
		return fmt.Errorf("marshal content: %w", err)
	}

	// If we have a profile key, use sealed sender; otherwise fall back to regular.
	accessKey, err := deriveAccessKeyForRecipient(gs.dataStore, recipient)
	if err != nil {
		return gs.sendEncryptedMessage(ctx, recipient, contentBytes)
	}
	return gs.sendSealedEncrypted(ctx, recipient, contentBytes, senderCert, accessKey)
}

// sendGroupSealedMessage wraps a sender key ciphertext in sealed sender v1 and sends it.
// Used as fallback when endorsements are not available.
func (gs *GroupSender) sendGroupSealedMessage(ctx context.Context, recipient string, senderKeyBytes []byte, senderCert *libsignal.SenderCertificate, groupID []byte) error {
	accessKey, err := deriveAccessKeyForRecipient(gs.dataStore, recipient)
	if err != nil {
		return err
	}

	deviceIDs, _ := gs.initialDevices(recipient, false)

	return gs.withDeviceRetry(recipient, deviceIDs, 0, func(devices []int) error {
		return gs.trySendGroupSealed(ctx, recipient, senderKeyBytes, senderCert, groupID, accessKey, devices)
	})
}

// trySendGroupSealed attempts to send a sender key message to specific devices using v1 sealed sender.
func (gs *GroupSender) trySendGroupSealed(ctx context.Context, recipient string, senderKeyBytes []byte, senderCert *libsignal.SenderCertificate, groupID []byte, accessKey []byte, deviceIDs []int) error {
	timestamp := uint64(time.Now().UnixMilli())
	var messages []outgoingMessage

	for _, deviceID := range deviceIDs {
		addr, err := libsignal.NewAddress(recipient, uint32(deviceID))
		if err != nil {
			return fmt.Errorf("create address: %w", err)
		}

		// Get registration ID for this device
		registrationID := 0
		session, err := gs.cryptoStore.LoadSession(addr)
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
		sealed, err := libsignal.SealedSenderEncrypt(addr, usmc, gs.cryptoStore)
		usmc.Destroy()
		addr.Destroy()
		if err != nil {
			return fmt.Errorf("seal: %w", err)
		}

		messages = append(messages, outgoingMessage{
			Type:                      proto.Envelope_UNIDENTIFIED_SENDER,
			DestinationDeviceID:       deviceID,
			DestinationRegistrationID: registrationID,
			Content:                   base64.StdEncoding.EncodeToString(sealed),
		})
	}

	msgList := &outgoingMessageList{
		Destination: recipient,
		Timestamp:   timestamp,
		Messages:    messages,
		Urgent:      true,
	}

	return gs.sendSealedHTTPMsg(ctx, recipient, msgList, accessKey)
}

// sendGroupSyncMessage sends a SyncMessage.Sent to our other devices so they
// display the outgoing group message in the conversation.
func (gs *GroupSender) sendGroupSyncMessage(ctx context.Context, dm *proto.DataMessage, timestamp uint64, recipients []string) error {
	logf(gs.logger, "sync: sending group sync message timestamp=%d recipients=%d", timestamp, len(recipients))

	acct, err := gs.dataStore.LoadAccount()
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

	logf(gs.logger, "sync: message has GroupV2=%v masterKeyLen=%d statusCount=%d",
		dm.GroupV2 != nil, len(dm.GetGroupV2().GetMasterKey()), len(statuses))

	// sendEncryptedMessageWithTimestamp handles self-send correctly:
	// it calls initialDevices(aci, sendingToSelf=true) which filters out
	// our own device and returns "no other devices" if we're the only one.
	err = gs.sendEncryptedMessageWithTimestamp(ctx, acct.ACI, contentBytes, timestamp)
	if err != nil && (strings.Contains(err.Error(), "no other devices") ||
		strings.Contains(err.Error(), "no reachable devices")) {
		logf(gs.logger, "sync: no other devices to sync to")
		return nil
	}
	return err
}

// withGroupDeviceRetry runs tryFn, retrying on group-level 409/410 errors.
// Unlike withDeviceRetry which handles one recipient, this handles errors
// containing device mismatches for MULTIPLE recipients simultaneously.
// It archives/fetches sessions for each affected recipient and retries.
func (gs *GroupSender) withGroupDeviceRetry(ctx context.Context, tryFn func() error) error {
	return retryOnDeviceError(
		tryFn,
		func(err error) error {
			var groupStaleErr *groupStaleDevicesError
			var groupMismatchErr *groupMismatchedDevicesError

			switch {
			case errors.As(err, &groupStaleErr):
				logf(gs.logger, "group retry: 410 stale for %d recipients", len(groupStaleErr.Entries))
				for _, entry := range groupStaleErr.Entries {
					for _, deviceID := range entry.Devices.StaleDevices {
						_ = gs.dataStore.ArchiveSession(entry.UUID, uint32(deviceID))
					}
				}
			case errors.As(err, &groupMismatchErr):
				logf(gs.logger, "group retry: 409 mismatch for %d recipients", len(groupMismatchErr.Entries))
				for _, entry := range groupMismatchErr.Entries {
					logf(gs.logger, "group retry: %s missing=%v extra=%v",
						entry.UUID[:8], entry.Devices.MissingDevices, entry.Devices.ExtraDevices)

					for _, deviceID := range entry.Devices.ExtraDevices {
						_ = gs.dataStore.ArchiveSession(entry.UUID, uint32(deviceID))
					}

					for _, deviceID := range entry.Devices.MissingDevices {
						if _, fetchErr := gs.getPreKeys(ctx, entry.UUID, deviceID); fetchErr != nil {
							logf(gs.logger, "group retry: failed to fetch prekeys for %s.%d: %v",
								entry.UUID[:8], deviceID, fetchErr)
						}
					}

					currentDevices, _ := gs.dataStore.GetDevices(entry.UUID)
					if len(currentDevices) == 0 {
						currentDevices = []int{1}
					}
					for _, deviceID := range entry.Devices.ExtraDevices {
						currentDevices = slices.DeleteFunc(currentDevices, func(id int) bool { return id == deviceID })
					}
					for _, deviceID := range entry.Devices.MissingDevices {
						if !slices.Contains(currentDevices, deviceID) {
							currentDevices = append(currentDevices, deviceID)
						}
					}
					_ = gs.dataStore.SetDevices(entry.UUID, currentDevices)
				}
			default:
				return err
			}
			return nil
		},
	)
}

// buildGroupMemberBytes builds a concatenated byte slice of 17-byte service IDs
// for all group members, suitable for endorsement verification.
func buildGroupMemberBytes(memberACIs []string) ([]byte, error) {
	buf := make([]byte, 0, len(memberACIs)*17)
	for _, aci := range memberACIs {
		serviceID, err := aciToServiceID(aci)
		if err != nil {
			return nil, fmt.Errorf("convert ACI %s to service ID: %w", aci[:8], err)
		}
		buf = append(buf, serviceID[:]...)
	}
	return buf, nil
}

// aciToServiceID converts an ACI UUID string to a 17-byte ServiceIdFixedWidthBinaryBytes.
// Format: [0x00 (ACI type prefix)] [16 bytes UUID]
func aciToServiceID(aci string) ([17]byte, error) {
	parsed, err := uuid.Parse(aci)
	if err != nil {
		return [17]byte{}, fmt.Errorf("parse UUID: %w", err)
	}
	var serviceID [17]byte
	serviceID[0] = 0x00 // ACI type prefix
	copy(serviceID[1:], parsed[:])
	return serviceID, nil
}

// createSenderKeyUSMC creates an UnidentifiedSenderMessageContent for a sender key message.
// Uses ContentHint = IMPLICIT (2) to match Signal-Android behavior.
func createSenderKeyUSMC(senderKeyBytes []byte, senderCert *libsignal.SenderCertificate, groupID []byte) (*libsignal.UnidentifiedSenderMessageContent, error) {
	return libsignal.NewUnidentifiedSenderMessageContentFromType(
		senderKeyBytes,
		libsignal.CiphertextMessageTypeSenderKey,
		senderCert,
		libsignal.ContentHintImplicit, // Signal-Android parity: IMPLICIT (2) for group messages
		groupID,
	)
}

// parseGroupID converts a hex-encoded group ID to bytes.
func parseGroupID(groupID string) ([]byte, error) {
	return hex.DecodeString(groupID)
}

// generateDistributionID generates a random UUID v4 string for sender key distribution.
func generateDistributionID() string {
	return uuid.New().String()
}
