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

// StoreSenderKey stores a sender key record for the given sender and distribution ID.
func (s *Store) StoreSenderKey(sender *libsignal.Address, distributionID [16]byte, record *libsignal.SenderKeyRecord) error {
	senderACI, err := sender.Name()
	if err != nil {
		return err
	}
	senderDevice, err := sender.DeviceID()
	if err != nil {
		return err
	}

	data, err := record.Serialize()
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO sender_key (sender_aci, sender_device, distribution_id, record)
		 VALUES (?, ?, ?, ?)`,
		senderACI, senderDevice, distributionID[:], data,
	)
	return err
}
