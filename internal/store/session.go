package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// LoadSession loads a session record for the given address.
// Returns nil, nil if no session exists.
func (s *Store) LoadSession(address *libsignal.Address) (*libsignal.SessionRecord, error) {
	name, err := address.Name()
	if err != nil {
		return nil, fmt.Errorf("store: session address name: %w", err)
	}
	devID, err := address.DeviceID()
	if err != nil {
		return nil, fmt.Errorf("store: session address device id: %w", err)
	}

	var record []byte
	err = s.db.QueryRow(
		"SELECT record FROM session WHERE address = ? AND device_id = ?",
		name, devID,
	).Scan(&record)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("store: load session: %w", err)
	}

	return libsignal.DeserializeSessionRecord(record)
}

// StoreSession stores a session record (serialized bytes) for the given address.
func (s *Store) StoreSession(address *libsignal.Address, record []byte) error {
	name, err := address.Name()
	if err != nil {
		return fmt.Errorf("store: session address name: %w", err)
	}
	devID, err := address.DeviceID()
	if err != nil {
		return fmt.Errorf("store: session address device id: %w", err)
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO session (address, device_id, record) VALUES (?, ?, ?)",
		name, devID, record,
	)
	if err != nil {
		return fmt.Errorf("store: store session: %w", err)
	}
	return nil
}

// ArchiveSession deletes the session record for the given address and device ID.
// This forces the next encrypt attempt to establish a new session via pre-key fetch.
// Also clears SKDM distribution tracking for this address so the sender key
// will be re-distributed on next group send.
func (s *Store) ArchiveSession(address string, deviceID uint32) error {
	_, err := s.db.Exec(
		"DELETE FROM session WHERE address = ? AND device_id = ?",
		address, deviceID,
	)
	if err != nil {
		return fmt.Errorf("store: archive session: %w", err)
	}
	// Clear SKDM tracking for this address.device
	addr := fmt.Sprintf("%s.%d", address, deviceID)
	if err := s.ClearSenderKeySharedWith(addr); err != nil {
		return fmt.Errorf("store: clear sender key shared: %w", err)
	}
	return nil
}
