package store

import (
	"fmt"
	"time"
)

// GetDevices returns known device IDs for a recipient, ordered by device_id.
// Returns an empty slice if no devices are cached.
func (s *Store) GetDevices(aci string) ([]int, error) {
	rows, err := s.db.Query(
		"SELECT device_id FROM recipient_device WHERE aci = ? ORDER BY device_id",
		aci,
	)
	if err != nil {
		return nil, fmt.Errorf("store: get devices: %w", err)
	}
	defer rows.Close()

	var devices []int
	for rows.Next() {
		var deviceID int
		if err := rows.Scan(&deviceID); err != nil {
			return nil, fmt.Errorf("store: scan device: %w", err)
		}
		devices = append(devices, deviceID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate devices: %w", err)
	}
	return devices, nil
}

// SetDevices replaces the device list for a recipient.
func (s *Store) SetDevices(aci string, deviceIDs []int) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete existing devices for this recipient
	if _, err := tx.Exec("DELETE FROM recipient_device WHERE aci = ?", aci); err != nil {
		return fmt.Errorf("store: delete devices: %w", err)
	}

	// Insert new device list
	now := time.Now().Unix()
	stmt, err := tx.Prepare("INSERT INTO recipient_device (aci, device_id, last_seen) VALUES (?, ?, ?)")
	if err != nil {
		return fmt.Errorf("store: prepare: %w", err)
	}
	defer stmt.Close()

	for _, deviceID := range deviceIDs {
		if _, err := stmt.Exec(aci, deviceID, now); err != nil {
			return fmt.Errorf("store: insert device %d: %w", deviceID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store: commit: %w", err)
	}
	return nil
}

// AddDevice adds a device to a recipient's list. Idempotent - no error if already exists.
func (s *Store) AddDevice(aci string, deviceID int) error {
	now := time.Now().Unix()
	_, err := s.db.Exec(
		"INSERT OR REPLACE INTO recipient_device (aci, device_id, last_seen) VALUES (?, ?, ?)",
		aci, deviceID, now,
	)
	if err != nil {
		return fmt.Errorf("store: add device: %w", err)
	}
	return nil
}

// RemoveDevice removes a device from a recipient's list. Idempotent - no error if not found.
func (s *Store) RemoveDevice(aci string, deviceID int) error {
	_, err := s.db.Exec(
		"DELETE FROM recipient_device WHERE aci = ? AND device_id = ?",
		aci, deviceID,
	)
	if err != nil {
		return fmt.Errorf("store: remove device: %w", err)
	}
	return nil
}
