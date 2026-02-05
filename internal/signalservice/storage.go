package signalservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
	gproto "google.golang.org/protobuf/proto"
)

// StorageAuthResponse is the response from GET /v1/storage/auth
type StorageAuthResponse struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SyncGroupsFromStorage fetches group master keys from Storage Service and stores them locally.
// This requires the account's master key to be available.
func (s *Service) SyncGroupsFromStorage(ctx context.Context) (int, error) {
	// Load account to get master key
	acct, err := s.store.LoadAccount()
	if err != nil {
		return 0, fmt.Errorf("load account: %w", err)
	}
	if acct == nil {
		return 0, fmt.Errorf("no account found")
	}
	if len(acct.MasterKey) != 32 {
		return 0, fmt.Errorf("no master key available (was this device linked?)")
	}

	// Derive storage key from master key
	storageKey, err := DeriveStorageKey(acct.MasterKey)
	if err != nil {
		return 0, fmt.Errorf("derive storage key: %w", err)
	}

	// Get storage auth credentials
	auth, err := s.getStorageAuth(ctx)
	if err != nil {
		return 0, fmt.Errorf("get storage auth: %w", err)
	}

	// Fetch manifest
	manifest, err := s.getStorageManifest(ctx, auth, storageKey)
	if err != nil {
		return 0, fmt.Errorf("get manifest: %w", err)
	}

	logf(s.logger, "storage manifest version=%d, %d identifiers", manifest.Version, len(manifest.Identifiers))

	// Find GroupV2 record IDs
	var groupIDs [][]byte
	for _, id := range manifest.Identifiers {
		if id.Type == proto.ManifestRecord_Identifier_GROUPV2 {
			groupIDs = append(groupIDs, id.Raw)
		}
	}

	if len(groupIDs) == 0 {
		logf(s.logger, "no GroupV2 records in storage manifest")
		return 0, nil
	}

	logf(s.logger, "found %d GroupV2 records to fetch", len(groupIDs))

	// Read storage records
	groups, err := s.readGroupRecords(ctx, auth, storageKey, groupIDs)
	if err != nil {
		return 0, fmt.Errorf("read group records: %w", err)
	}

	// Store groups locally
	count := 0
	for _, g := range groups {
		if err := s.store.SaveGroup(g); err != nil {
			logf(s.logger, "failed to save group %s: %v", g.GroupID, err)
			continue
		}
		count++
		logf(s.logger, "synced group: %s (name=%q)", g.GroupID, g.Name)
	}

	return count, nil
}

// getStorageAuth fetches authentication credentials for storage service.
func (s *Service) getStorageAuth(ctx context.Context) (*StorageAuthResponse, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.transport.baseURL+"/v1/storage/auth", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(s.auth.Username, s.auth.Password)

	resp, err := s.transport.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage auth failed: %s", resp.Status)
	}

	var auth StorageAuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return nil, fmt.Errorf("decode auth response: %w", err)
	}

	return &auth, nil
}

// getStorageManifest fetches and decrypts the storage manifest.
func (s *Service) getStorageManifest(ctx context.Context, auth *StorageAuthResponse, storageKey StorageKey) (*proto.ManifestRecord, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", s.transport.baseURL+"/v1/storage/manifest", nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(auth.Username, auth.Password)
	req.Header.Set("Accept", "application/x-protobuf")

	resp, err := s.transport.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("no storage manifest found (404)")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get manifest failed: %s", resp.Status)
	}

	// Read raw protobuf
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read manifest body: %w", err)
	}

	// Parse StorageManifest wrapper
	var manifest proto.StorageManifest
	if err := gproto.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}

	// Decrypt the manifest value
	manifestKey := storageKey.DeriveManifestKey(int64(manifest.Version))
	plaintext, err := DecryptStorageManifest(manifestKey, manifest.Value)
	if err != nil {
		return nil, fmt.Errorf("decrypt manifest: %w", err)
	}

	// Parse decrypted ManifestRecord
	var record proto.ManifestRecord
	if err := gproto.Unmarshal(plaintext, &record); err != nil {
		return nil, fmt.Errorf("unmarshal manifest record: %w", err)
	}

	return &record, nil
}

// readGroupRecords fetches and decrypts GroupV2 records from storage.
func (s *Service) readGroupRecords(ctx context.Context, auth *StorageAuthResponse, storageKey StorageKey, recordIDs [][]byte) ([]*store.Group, error) {
	// Build read operation
	readOp := &proto.ReadOperation{
		ReadKey: recordIDs,
	}
	body, err := gproto.Marshal(readOp)
	if err != nil {
		return nil, fmt.Errorf("marshal read operation: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", s.transport.baseURL+"/v1/storage/read", newBytesReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(auth.Username, auth.Password)
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Accept", "application/x-protobuf")

	resp, err := s.transport.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read storage items failed: %s", resp.Status)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	var items proto.StorageItems
	if err := gproto.Unmarshal(data, &items); err != nil {
		return nil, fmt.Errorf("unmarshal storage items: %w", err)
	}

	var groups []*store.Group
	for _, item := range items.Items {
		g, err := s.decryptGroupRecord(storageKey, item)
		if err != nil {
			logf(s.logger, "failed to decrypt group record: %v", err)
			continue
		}
		if g != nil {
			groups = append(groups, g)
		}
	}

	return groups, nil
}

// decryptGroupRecord decrypts a single storage item and extracts the GroupV2Record.
func (s *Service) decryptGroupRecord(storageKey StorageKey, item *proto.StorageItem) (*store.Group, error) {
	// Derive item key from the raw ID
	itemKey := storageKey.DeriveItemKey(item.Key)

	// Decrypt the item value
	plaintext, err := DecryptStorageItem(itemKey, item.Value)
	if err != nil {
		return nil, fmt.Errorf("decrypt item: %w", err)
	}

	// Parse StorageRecord
	var record proto.StorageRecord
	if err := gproto.Unmarshal(plaintext, &record); err != nil {
		return nil, fmt.Errorf("unmarshal storage record: %w", err)
	}

	// Check if this is a GroupV2 record
	gv2 := record.GetGroupV2()
	if gv2 == nil {
		return nil, nil // Not a GroupV2 record
	}

	if len(gv2.MasterKey) != 32 {
		return nil, fmt.Errorf("invalid master key length: %d", len(gv2.MasterKey))
	}

	// Derive group identifier from master key
	var masterKey libsignal.GroupMasterKey
	copy(masterKey[:], gv2.MasterKey)

	groupID, err := libsignal.GroupIdentifierFromMasterKey(masterKey)
	if err != nil {
		return nil, fmt.Errorf("derive group identifier: %w", err)
	}

	return &store.Group{
		GroupID:   groupID.String(),
		MasterKey: gv2.MasterKey,
		// Name will be populated when we fetch from Groups V2 API or receive a message
	}, nil
}

// newBytesReader creates an io.Reader from a byte slice.
func newBytesReader(data []byte) *bytesReaderType {
	return &bytesReaderType{data: data}
}

type bytesReaderType struct {
	data []byte
	off  int
}

func (r *bytesReaderType) Read(p []byte) (n int, err error) {
	if r.off >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.off:])
	r.off += n
	return n, nil
}
