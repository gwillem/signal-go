package store

import (
	"database/sql"
	"errors"
	"fmt"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// LoadPreKey loads a one-time pre-key record by ID.
func (s *Store) LoadPreKey(id uint32) (*libsignal.PreKeyRecord, error) {
	var record []byte
	err := s.db.QueryRow(
		"SELECT record FROM pre_key WHERE id = ?", id,
	).Scan(&record)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("pre-key %d not found", id)
		}
		return nil, fmt.Errorf("store: load pre-key: %w", err)
	}
	return libsignal.DeserializePreKeyRecord(record)
}

// StorePreKey stores a one-time pre-key record.
func (s *Store) StorePreKey(id uint32, record *libsignal.PreKeyRecord) error {
	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("store: serialize pre-key: %w", err)
	}
	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO pre_key (id, record) VALUES (?, ?)",
		id, data,
	)
	if err != nil {
		return fmt.Errorf("store: store pre-key: %w", err)
	}
	return nil
}

// RemovePreKey deletes a one-time pre-key record.
func (s *Store) RemovePreKey(id uint32) error {
	_, err := s.db.Exec("DELETE FROM pre_key WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("store: remove pre-key: %w", err)
	}
	return nil
}

// LoadSignedPreKey loads a signed pre-key record by ID.
func (s *Store) LoadSignedPreKey(id uint32) (*libsignal.SignedPreKeyRecord, error) {
	var record []byte
	err := s.db.QueryRow(
		"SELECT record FROM signed_pre_key WHERE id = ?", id,
	).Scan(&record)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("signed pre-key %d not found", id)
		}
		return nil, fmt.Errorf("store: load signed pre-key: %w", err)
	}
	return libsignal.DeserializeSignedPreKeyRecord(record)
}

// StoreSignedPreKey stores a signed pre-key record.
func (s *Store) StoreSignedPreKey(id uint32, record *libsignal.SignedPreKeyRecord) error {
	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("store: serialize signed pre-key: %w", err)
	}
	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO signed_pre_key (id, record) VALUES (?, ?)",
		id, data,
	)
	if err != nil {
		return fmt.Errorf("store: store signed pre-key: %w", err)
	}
	return nil
}

// LoadKyberPreKey loads a Kyber pre-key record by ID.
func (s *Store) LoadKyberPreKey(id uint32) (*libsignal.KyberPreKeyRecord, error) {
	var record []byte
	err := s.db.QueryRow(
		"SELECT record FROM kyber_pre_key WHERE id = ?", id,
	).Scan(&record)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("kyber pre-key %d not found", id)
		}
		return nil, fmt.Errorf("store: load kyber pre-key: %w", err)
	}
	return libsignal.DeserializeKyberPreKeyRecord(record)
}

// StoreKyberPreKey stores a Kyber pre-key record.
func (s *Store) StoreKyberPreKey(id uint32, record *libsignal.KyberPreKeyRecord) error {
	data, err := record.Serialize()
	if err != nil {
		return fmt.Errorf("store: serialize kyber pre-key: %w", err)
	}
	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO kyber_pre_key (id, record) VALUES (?, ?)",
		id, data,
	)
	if err != nil {
		return fmt.Errorf("store: store kyber pre-key: %w", err)
	}
	return nil
}

// MarkKyberPreKeyUsed marks a Kyber pre-key as used.
// The ecPreKeyID and baseKey parameters are provided for optional reuse tracking
// but are currently ignored (we just mark the key as used).
func (s *Store) MarkKyberPreKeyUsed(id uint32, ecPreKeyID uint32, baseKey *libsignal.PublicKey) error {
	// Note: ecPreKeyID and baseKey could be stored for reuse attack detection,
	// but for now we just mark the key as used.
	_, err := s.db.Exec(
		"UPDATE kyber_pre_key SET used = 1 WHERE id = ?", id,
	)
	if err != nil {
		return fmt.Errorf("store: mark kyber pre-key used: %w", err)
	}
	return nil
}
