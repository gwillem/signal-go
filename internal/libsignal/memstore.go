package libsignal

import "fmt"

// addressKey returns a map key for an Address (name + deviceID).
func addressKey(addr *Address) string {
	name, _ := addr.Name()
	devID, _ := addr.DeviceID()
	return fmt.Sprintf("%s:%d", name, devID)
}

// MemorySessionStore is an in-memory SessionStore.
type MemorySessionStore struct {
	sessions map[string]*SessionRecord
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: map[string]*SessionRecord{}}
}

func (s *MemorySessionStore) LoadSession(address *Address) (*SessionRecord, error) {
	rec := s.sessions[addressKey(address)]
	if rec == nil {
		return nil, nil
	}
	// Return a clone so the caller owns it
	data, err := rec.Serialize()
	if err != nil {
		return nil, err
	}
	return DeserializeSessionRecord(data)
}

func (s *MemorySessionStore) StoreSession(address *Address, record *SessionRecord) error {
	key := addressKey(address)
	if old := s.sessions[key]; old != nil {
		old.Destroy()
	}
	s.sessions[key] = record
	return nil
}

// MemoryIdentityKeyStore is an in-memory IdentityKeyStore.
type MemoryIdentityKeyStore struct {
	identityKeyPair *PrivateKey
	registrationID  uint32
	identities      map[string]*PublicKey
}

func NewMemoryIdentityKeyStore(identityKey *PrivateKey, registrationID uint32) *MemoryIdentityKeyStore {
	return &MemoryIdentityKeyStore{
		identityKeyPair: identityKey,
		registrationID:  registrationID,
		identities:      map[string]*PublicKey{},
	}
}

func (s *MemoryIdentityKeyStore) GetIdentityKeyPair() (*PrivateKey, error) {
	// Return a clone via serialize/deserialize
	data, err := s.identityKeyPair.Serialize()
	if err != nil {
		return nil, err
	}
	return DeserializePrivateKey(data)
}

func (s *MemoryIdentityKeyStore) GetLocalRegistrationID() (uint32, error) {
	return s.registrationID, nil
}

func (s *MemoryIdentityKeyStore) SaveIdentityKey(address *Address, key *PublicKey) error {
	k := addressKey(address)
	if old := s.identities[k]; old != nil {
		old.Destroy()
	}
	s.identities[k] = key
	return nil
}

func (s *MemoryIdentityKeyStore) GetIdentityKey(address *Address) (*PublicKey, error) {
	key := s.identities[addressKey(address)]
	if key == nil {
		return nil, nil
	}
	// Return a clone
	data, err := key.Serialize()
	if err != nil {
		return nil, err
	}
	return DeserializePublicKey(data)
}

func (s *MemoryIdentityKeyStore) IsTrustedIdentity(address *Address, key *PublicKey, direction uint) (bool, error) {
	existing := s.identities[addressKey(address)]
	if existing == nil {
		// First time seeing this identity — trust on first use
		return true, nil
	}
	cmp, err := existing.Compare(key)
	if err != nil {
		return false, err
	}
	return cmp == 0, nil
}

// MemoryPreKeyStore is an in-memory PreKeyStore.
type MemoryPreKeyStore struct {
	preKeys map[uint32]*PreKeyRecord
}

func NewMemoryPreKeyStore() *MemoryPreKeyStore {
	return &MemoryPreKeyStore{preKeys: map[uint32]*PreKeyRecord{}}
}

func (s *MemoryPreKeyStore) LoadPreKey(id uint32) (*PreKeyRecord, error) {
	rec := s.preKeys[id]
	if rec == nil {
		return nil, fmt.Errorf("pre-key %d not found", id)
	}
	// Clone
	data, err := rec.Serialize()
	if err != nil {
		return nil, err
	}
	return DeserializePreKeyRecord(data)
}

func (s *MemoryPreKeyStore) StorePreKey(id uint32, record *PreKeyRecord) error {
	s.preKeys[id] = record
	return nil
}

func (s *MemoryPreKeyStore) RemovePreKey(id uint32) error {
	delete(s.preKeys, id)
	return nil
}

// MemorySignedPreKeyStore is an in-memory SignedPreKeyStore.
type MemorySignedPreKeyStore struct {
	signedPreKeys map[uint32]*SignedPreKeyRecord
}

func NewMemorySignedPreKeyStore() *MemorySignedPreKeyStore {
	return &MemorySignedPreKeyStore{signedPreKeys: map[uint32]*SignedPreKeyRecord{}}
}

func (s *MemorySignedPreKeyStore) LoadSignedPreKey(id uint32) (*SignedPreKeyRecord, error) {
	rec := s.signedPreKeys[id]
	if rec == nil {
		return nil, fmt.Errorf("signed pre-key %d not found", id)
	}
	data, err := rec.Serialize()
	if err != nil {
		return nil, err
	}
	return DeserializeSignedPreKeyRecord(data)
}

func (s *MemorySignedPreKeyStore) StoreSignedPreKey(id uint32, record *SignedPreKeyRecord) error {
	s.signedPreKeys[id] = record
	return nil
}

// MemoryKyberPreKeyStore is an in-memory KyberPreKeyStore.
type MemoryKyberPreKeyStore struct {
	kyberPreKeys map[uint32]*KyberPreKeyRecord
	used         map[uint32]bool
}

func NewMemoryKyberPreKeyStore() *MemoryKyberPreKeyStore {
	return &MemoryKyberPreKeyStore{
		kyberPreKeys: map[uint32]*KyberPreKeyRecord{},
		used:         map[uint32]bool{},
	}
}

func (s *MemoryKyberPreKeyStore) LoadKyberPreKey(id uint32) (*KyberPreKeyRecord, error) {
	rec := s.kyberPreKeys[id]
	if rec == nil {
		return nil, fmt.Errorf("kyber pre-key %d not found", id)
	}
	data, err := rec.Serialize()
	if err != nil {
		return nil, err
	}
	return DeserializeKyberPreKeyRecord(data)
}

func (s *MemoryKyberPreKeyStore) StoreKyberPreKey(id uint32, record *KyberPreKeyRecord) error {
	s.kyberPreKeys[id] = record
	return nil
}

func (s *MemoryKyberPreKeyStore) MarkKyberPreKeyUsed(id uint32) error {
	s.used[id] = true
	return nil
}
