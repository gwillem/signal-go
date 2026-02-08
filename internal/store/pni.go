package store

import "github.com/gwillem/signal-go/internal/libsignal"

// PNIIdentityStore wraps a Store to return PNI identity for
// GetIdentityKeyPair and GetLocalRegistrationID. All other
// IdentityKeyStore methods delegate to the embedded Store.
type PNIIdentityStore struct{ *Store }

// PNI returns a PNIIdentityStore that overrides identity methods
// to return the PNI key pair and registration ID.
func (s *Store) PNI() libsignal.IdentityKeyStore { return &PNIIdentityStore{s} }

// GetIdentityKeyPair returns the PNI identity key pair.
func (p *PNIIdentityStore) GetIdentityKeyPair() (*libsignal.PrivateKey, error) {
	return p.Store.GetPNIIdentityKeyPair()
}

// GetLocalRegistrationID returns the PNI registration ID.
func (p *PNIIdentityStore) GetLocalRegistrationID() (uint32, error) {
	return p.Store.GetPNIRegistrationID()
}
