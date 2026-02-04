package store

import (
	"fmt"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// GetIdentityKeyPair returns the local identity key pair (ACI or PNI based on UsePNI setting).
func (s *Store) GetIdentityKeyPair() (*libsignal.PrivateKey, error) {
	keyPair := s.identityKeyPair
	if s.usePNI {
		keyPair = s.pniKeyPair
	}
	if keyPair == nil {
		if s.usePNI {
			return nil, fmt.Errorf("store: PNI identity key pair not set")
		}
		return nil, fmt.Errorf("store: identity key pair not set")
	}
	// Return a clone via serialize/deserialize.
	data, err := keyPair.Serialize()
	if err != nil {
		return nil, err
	}
	return libsignal.DeserializePrivateKey(data)
}

// GetLocalRegistrationID returns the local registration ID (ACI or PNI based on UsePNI setting).
func (s *Store) GetLocalRegistrationID() (uint32, error) {
	if s.usePNI {
		return s.pniRegID, nil
	}
	return s.registrationID, nil
}

// SaveIdentityKey stores a remote identity key for the given address.
func (s *Store) SaveIdentityKey(address *libsignal.Address, key *libsignal.PublicKey) error {
	name, err := address.Name()
	if err != nil {
		return fmt.Errorf("store: identity address name: %w", err)
	}

	data, err := key.Serialize()
	if err != nil {
		return fmt.Errorf("store: serialize identity key: %w", err)
	}

	_, err = s.db.Exec(
		"INSERT OR REPLACE INTO identity (address, public_key) VALUES (?, ?)",
		name, data,
	)
	if err != nil {
		return fmt.Errorf("store: save identity key: %w", err)
	}
	return nil
}

// GetIdentityKey loads a remote identity key for the given address.
// Returns nil, nil if no identity key exists for this address.
func (s *Store) GetIdentityKey(address *libsignal.Address) (*libsignal.PublicKey, error) {
	name, err := address.Name()
	if err != nil {
		return nil, fmt.Errorf("store: identity address name: %w", err)
	}

	var data []byte
	err = s.db.QueryRow(
		"SELECT public_key FROM identity WHERE address = ?", name,
	).Scan(&data)
	if err != nil {
		if err.Error() == "sql: no rows in result set" {
			return nil, nil
		}
		return nil, fmt.Errorf("store: load identity key: %w", err)
	}

	return libsignal.DeserializePublicKey(data)
}

// IsTrustedIdentity checks whether a remote identity key is trusted.
// Uses trust-on-first-use (TOFU): unknown identities are trusted.
func (s *Store) IsTrustedIdentity(address *libsignal.Address, key *libsignal.PublicKey, direction uint) (bool, error) {
	existing, err := s.GetIdentityKey(address)
	if err != nil {
		return false, err
	}
	if existing == nil {
		// First time seeing this identity — trust on first use.
		return true, nil
	}
	defer existing.Destroy()

	cmp, err := existing.Compare(key)
	if err != nil {
		return false, err
	}
	return cmp == 0, nil
}
