package store

import (
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
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("store: load session: %w", err)
	}

	return libsignal.DeserializeSessionRecord(record)
}

// StoreSession stores a session record for the given address.
func (s *Store) StoreSession(address *libsignal.Address, record *libsignal.SessionRecord) error {
	name, err := address.Name()
	if err != nil {
		return fmt.Errorf("store: session address name: %w", err)
	}
	devID, err := address.DeviceID()
	if err != nil {
		return fmt.Errorf("store: session address device id: %w", err)
	}

	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("store: serialize session: %w", err)
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO session (address, device_id, record) VALUES (?, ?, ?)",
		name, devID, data,
	)
	if err != nil {
		return fmt.Errorf("store: store session: %w", err)
	}
	return nil
}

// ArchiveSession deletes the session record for the given address and device ID.
// This forces the next encrypt attempt to establish a new session via pre-key fetch.
func (s *Store) ArchiveSession(address string, deviceID uint32) error {
	_, err := s.db.Exec(
		"DELETE FROM session WHERE address = ? AND device_id = ?",
		address, deviceID,
	)
	if err != nil {
		return fmt.Errorf("store: archive session: %w", err)
	}
	return nil
}
