package signalservice

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	gproto "google.golang.org/protobuf/proto"
)

// temporalCredential represents an auth credential for a specific redemption time.
type temporalCredential struct {
	Credential     []byte `json:"credential"`
	RedemptionTime int64  `json:"redemptionTime"` // seconds since epoch
}

// credentialResponse is the response from /v1/certificate/auth/group
type credentialResponse struct {
	Credentials []temporalCredential `json:"credentials"`
}

// FetchGroupDetails fetches and decrypts group details from the Groups V2 API.
// This populates the group name and member count.
func (s *Service) FetchGroupDetails(ctx context.Context, group *store.Group) error {
	if len(group.MasterKey) != 32 {
		return fmt.Errorf("invalid master key length: %d", len(group.MasterKey))
	}

	// Derive group secret params from master key
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

	// Get auth credential for today
	credential, err := s.getAuthCredentialForToday(ctx)
	if err != nil {
		return fmt.Errorf("get auth credential: %w", err)
	}

	// Create auth presentation
	serverParams, err := libsignal.GetSignalServerPublicParams()
	if err != nil {
		return fmt.Errorf("get server public params: %w", err)
	}
	defer serverParams.Close()

	presentation, err := serverParams.CreateAuthCredentialPresentation(secretParams, credential)
	if err != nil {
		return fmt.Errorf("create auth presentation: %w", err)
	}

	// Build authorization header (HTTP Basic Auth)
	// username = hex(GroupPublicParams)
	// password = hex(AuthCredentialPresentation)
	username := hex.EncodeToString(publicParams[:])
	password := hex.EncodeToString(presentation)

	// Fetch group from API
	groupResp, err := s.fetchGroup(ctx, username, password)
	if err != nil {
		return fmt.Errorf("fetch group: %w", err)
	}
	groupProto := groupResp.Group

	// Capture group send endorsements if present
	if len(groupResp.GroupSendEndorsementsResponse) > 0 {
		group.EndorsementsResponse = groupResp.GroupSendEndorsementsResponse
		expiry, err := libsignal.EndorsementExpiration(groupResp.GroupSendEndorsementsResponse)
		if err != nil {
			logf(s.logger, "failed to get endorsement expiration: %v", err)
		} else {
			group.EndorsementsExpiry = time.Unix(int64(expiry), 0)
			logf(s.logger, "captured group endorsements, expiry=%v", group.EndorsementsExpiry)
		}
	}

	// Decrypt title
	if len(groupProto.Title) > 0 {
		titleBlob, err := secretParams.DecryptBlob(groupProto.Title)
		if err != nil {
			logf(s.logger, "failed to decrypt group title: %v", err)
		} else {
			// Parse GroupAttributeBlob
			var attrBlob proto.GroupAttributeBlob
			if err := gproto.Unmarshal(titleBlob, &attrBlob); err != nil {
				logf(s.logger, "failed to unmarshal title blob: %v", err)
			} else if title := attrBlob.GetTitle(); title != "" {
				group.Name = title
			}
		}
	}

	// Update revision
	group.Revision = int(groupProto.Version)

	// Decrypt member ACIs and profile keys
	var memberACIs []string
	for _, member := range groupProto.Members {
		if len(member.UserId) != 65 { // UUID_CIPHERTEXT_LEN
			continue
		}

		var ciphertext [65]byte
		copy(ciphertext[:], member.UserId)
		serviceID, err := secretParams.DecryptServiceID(ciphertext)
		if err != nil {
			logf(s.logger, "failed to decrypt member service id: %v", err)
			continue
		}

		// serviceID is 17 bytes: 1 byte type prefix + 16 byte UUID
		// Type 0x00 = ACI, 0x01 = PNI
		if serviceID[0] != 0x00 || len(serviceID) < 17 {
			continue
		}

		aci := fmt.Sprintf("%x-%x-%x-%x-%x",
			serviceID[1:5], serviceID[5:7], serviceID[7:9], serviceID[9:11], serviceID[11:17])
		memberACIs = append(memberACIs, aci)

		// Decrypt and save profile key if available
		if len(member.ProfileKey) == 65 { // PROFILE_KEY_CIPHERTEXT_LEN
			var profileKeyCiphertext [65]byte
			copy(profileKeyCiphertext[:], member.ProfileKey)
			profileKey, err := secretParams.DecryptProfileKey(profileKeyCiphertext, serviceID)
			if err != nil {
				logf(s.logger, "failed to decrypt profile key for %s: %v", aci[:8], err)
				continue
			}

			// Save profile key to contact (upsert)
			contact := &store.Contact{
				ACI:        aci,
				ProfileKey: profileKey[:],
			}
			if err := s.store.SaveContact(contact); err != nil {
				logf(s.logger, "failed to save profile key for %s: %v", aci[:8], err)
			} else {
				logf(s.logger, "saved profile key for group member %s", aci[:8])
			}
		}
	}
	group.MemberACIs = memberACIs

	return nil
}

// getAuthCredentialForToday fetches and processes auth credentials, returning one valid for today.
func (s *Service) getAuthCredentialForToday(ctx context.Context) ([]byte, error) {
	// Load account for ACI/PNI
	acct, err := s.store.LoadAccount()
	if err != nil {
		return nil, fmt.Errorf("load account: %w", err)
	}
	if acct == nil {
		return nil, fmt.Errorf("no account found")
	}

	// Calculate today's timestamp (start of day in seconds)
	now := time.Now().UTC()
	todaySeconds := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC).Unix()
	endSeconds := todaySeconds + 7*24*60*60 // 7 days

	// Fetch credentials from server
	path := fmt.Sprintf("/v1/certificate/auth/group?redemptionStartSeconds=%d&redemptionEndSeconds=%d",
		todaySeconds, endSeconds)

	body, status, err := s.transport.Get(ctx, path, &s.auth)
	if err != nil {
		return nil, fmt.Errorf("fetch auth credentials: %w", err)
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("fetch auth credentials: status %d: %s", status, body)
	}

	var credResp credentialResponse
	if err := json.Unmarshal(body, &credResp); err != nil {
		return nil, fmt.Errorf("unmarshal credential response: %w", err)
	}

	if len(credResp.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials returned")
	}

	// Find credential for today
	var todayCredential *temporalCredential
	for i := range credResp.Credentials {
		if credResp.Credentials[i].RedemptionTime == todaySeconds {
			todayCredential = &credResp.Credentials[i]
			break
		}
	}
	if todayCredential == nil {
		// Use first credential as fallback
		todayCredential = &credResp.Credentials[0]
	}

	// Receive (verify) the credential
	serverParams, err := libsignal.GetSignalServerPublicParams()
	if err != nil {
		return nil, fmt.Errorf("get server public params: %w", err)
	}
	defer serverParams.Close()

	// Parse ACI and PNI UUIDs
	var aci, pni [16]byte
	aciBytes, err := parseUUID(acct.ACI)
	if err != nil {
		return nil, fmt.Errorf("parse ACI: %w", err)
	}
	copy(aci[:], aciBytes)

	pniBytes, err := parseUUID(acct.PNI)
	if err != nil {
		return nil, fmt.Errorf("parse PNI: %w", err)
	}
	copy(pni[:], pniBytes)

	credential, err := serverParams.ReceiveAuthCredentialWithPni(
		aci, pni,
		uint64(todayCredential.RedemptionTime),
		todayCredential.Credential,
	)
	if err != nil {
		return nil, fmt.Errorf("receive auth credential: %w", err)
	}

	return credential, nil
}

// fetchGroup fetches the encrypted group from the Groups V2 API.
// Groups V2 API is on storage.signal.org, same as Storage Service.
// Returns the full GroupResponse including endorsements.
func (s *Service) fetchGroup(ctx context.Context, username, password string) (*proto.GroupResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", storageServiceURL+"/v2/groups/", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(username, password)
	req.Header.Set("Accept", "application/x-protobuf")

	resp, err := s.storageHTTPClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	logf(s.logger, "http GET %s/v2/groups/ → %d", storageServiceURL, resp.StatusCode)

	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("not a member of this group (403)")
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	// The response is GroupResponse, not just Group
	var groupResp proto.GroupResponse
	if err := gproto.Unmarshal(data, &groupResp); err != nil {
		// Try parsing as plain Group (older API version)
		var group proto.Group
		if err2 := gproto.Unmarshal(data, &group); err2 != nil {
			return nil, fmt.Errorf("unmarshal group response: %w", err)
		}
		return &proto.GroupResponse{Group: &group}, nil
	}

	return &groupResp, nil
}

// parseUUID parses a UUID string into 16 bytes.
func parseUUID(s string) ([]byte, error) {
	// Remove dashes
	clean := ""
	for _, c := range s {
		if c != '-' {
			clean += string(c)
		}
	}
	if len(clean) != 32 {
		return nil, fmt.Errorf("invalid UUID length: %d", len(clean))
	}
	return hex.DecodeString(clean)
}

// FetchAllGroupDetails fetches details for all groups that don't have names yet.
// Groups returning 403 (not a member) are removed from the local store.
func (s *Service) FetchAllGroupDetails(ctx context.Context) (int, error) {
	groups, err := s.store.GetAllGroups()
	if err != nil {
		return 0, fmt.Errorf("get all groups: %w", err)
	}

	updated := 0
	for _, g := range groups {
		// Skip groups that already have names
		if g.Name != "" {
			continue
		}

		if err := s.FetchGroupDetails(ctx, g); err != nil {
			// Remove groups we're no longer a member of
			if strings.Contains(err.Error(), "403") {
				logf(s.logger, "removing group %s: no longer a member", g.GroupID[:8])
				if delErr := s.store.DeleteGroup(g.GroupID); delErr != nil {
					logf(s.logger, "failed to delete group %s: %v", g.GroupID[:8], delErr)
				}
			} else {
				logf(s.logger, "failed to fetch group %s: %v", g.GroupID[:8], err)
			}
			continue
		}

		if err := s.store.SaveGroup(g); err != nil {
			logf(s.logger, "failed to save group %s: %v", g.GroupID[:8], err)
			continue
		}

		logf(s.logger, "fetched group details: %s (name=%q, %d members)", g.GroupID[:8], g.Name, len(g.MemberACIs))
		updated++
	}

	return updated, nil
}
