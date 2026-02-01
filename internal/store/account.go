package store

import (
	"encoding/json"
	"fmt"
)

// Account holds all post-link credentials needed to authenticate and operate.
type Account struct {
	Number            string `json:"number"`
	ACI               string `json:"aci"`
	PNI               string `json:"pni"`
	Password          string `json:"password"`
	DeviceID          int    `json:"deviceId"`
	RegistrationID    int    `json:"registrationId"`
	PNIRegistrationID int    `json:"pniRegistrationId"`

	ACIIdentityKeyPrivate []byte `json:"aciIdentityKeyPrivate"`
	ACIIdentityKeyPublic  []byte `json:"aciIdentityKeyPublic"`
	PNIIdentityKeyPrivate []byte `json:"pniIdentityKeyPrivate"`
	PNIIdentityKeyPublic  []byte `json:"pniIdentityKeyPublic"`
	ProfileKey            []byte `json:"profileKey"`
	MasterKey             []byte `json:"masterKey"`
}

const accountKey = "account"

// SaveAccount persists the account credentials to the database.
func (s *Store) SaveAccount(acct *Account) error {
	data, err := json.Marshal(acct)
	if err != nil {
		return fmt.Errorf("store: marshal account: %w", err)
	}
	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO account (key, value) VALUES (?, ?)",
		accountKey, data,
	)
	if err != nil {
		return fmt.Errorf("store: save account: %w", err)
	}
	return nil
}

// LoadAccount loads the account credentials from the database.
// Returns nil, nil if no account has been saved.
func (s *Store) LoadAccount() (*Account, error) {
	var data []byte
	err := s.db.QueryRow(
		"SELECT value FROM account WHERE key = ?", accountKey,
	).Scan(&data)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("store: load account: %w", err)
	}

	var acct Account
	if err := json.Unmarshal(data, &acct); err != nil {
		return nil, fmt.Errorf("store: unmarshal account: %w", err)
	}
	return &acct, nil
}
