package store

import (
	"github.com/gwillem/signal-go/internal/libsignal"
)

// LoadSenderKey loads a sender key record for the given sender and distribution ID.
// Returns nil if not found.
func (s *Store) LoadSenderKey(sender *libsignal.Address, distributionID [16]byte) (*libsignal.SenderKeyRecord, error) {
	senderACI, err := sender.Name()
	if err != nil {
		return nil, err
	}
	senderDevice, err := sender.DeviceID()
	if err != nil {
		return nil, err
	}

	var record []byte
	err = s.db.QueryRow(
		"SELECT record FROM sender_key WHERE sender_aci = ? AND sender_device = ? AND distribution_id = ?",
		senderACI, senderDevice, distributionID[:],
	).Scan(&record)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, err
	}

	return libsignal.DeserializeSenderKeyRecord(record)
}

// GetSenderKeySharedWith returns the list of "aci.deviceID" addresses that
// have received our sender key for the given distribution ID.
func (s *Store) GetSenderKeySharedWith(distributionID [16]byte) ([]string, error) {
	rows, err := s.db.Query(
		"SELECT address FROM sender_key_shared WHERE distribution_id = ?",
		distributionID[:],
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var addresses []string
	for rows.Next() {
		var addr string
		if err := rows.Scan(&addr); err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)
	}
	return addresses, rows.Err()
}

// MarkSenderKeySharedWith records that the given addresses have received
// our sender key for the given distribution ID.
func (s *Store) MarkSenderKeySharedWith(distributionID [16]byte, addresses []string) error {
	for _, addr := range addresses {
		_, err := s.db.Exec(
			"INSERT OR IGNORE INTO sender_key_shared (distribution_id, address) VALUES (?, ?)",
			distributionID[:], addr,
		)
		if err != nil {
			return err
		}
	}
	return nil
}

// ClearSenderKeySharedWith removes SKDM tracking for a specific address
// across all distribution IDs. Called when archiving a session.
func (s *Store) ClearSenderKeySharedWith(address string) error {
	_, err := s.db.Exec(
		"DELETE FROM sender_key_shared WHERE address = ?",
		address,
	)
	return err
}

// StoreSenderKey stores a sender key record (serialized bytes) for the given sender and distribution ID.
func (s *Store) StoreSenderKey(sender *libsignal.Address, distributionID [16]byte, record []byte) error {
	senderACI, err := sender.Name()
	if err != nil {
		return err
	}
	senderDevice, err := sender.DeviceID()
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO sender_key (sender_aci, sender_device, distribution_id, record)
		 VALUES (?, ?, ?, ?)`,
		senderACI, senderDevice, distributionID[:], record,
	)
	return err
}
