package libsignal

import (
	"bytes"
	"fmt"
)

// addressKey returns a map key for an Address (name + deviceID).
func addressKey(addr *Address) string {
	name, _ := addr.Name()
	devID, _ := addr.DeviceID()
	return fmt.Sprintf("%s:%d", name, devID)
}

// MemorySessionStore is an in-memory SessionStore.
type MemorySessionStore struct {
	sessions map[string][]byte
}

func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: map[string][]byte{}}
}

func (s *MemorySessionStore) LoadSession(address *Address) (*SessionRecord, error) {
	data := s.sessions[addressKey(address)]
	if data == nil {
		return nil, nil
	}
	return DeserializeSessionRecord(data)
}

func (s *MemorySessionStore) StoreSession(address *Address, record []byte) error {
	s.sessions[addressKey(address)] = record
	return nil
}

// MemoryIdentityKeyStore is an in-memory IdentityKeyStore.
type MemoryIdentityKeyStore struct {
	identityKeyPair *PrivateKey
	registrationID  uint32
	identities      map[string][]byte
}

func NewMemoryIdentityKeyStore(identityKey *PrivateKey, registrationID uint32) *MemoryIdentityKeyStore {
	return &MemoryIdentityKeyStore{
		identityKeyPair: identityKey,
		registrationID:  registrationID,
		identities:      map[string][]byte{},
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

func (s *MemoryIdentityKeyStore) SaveIdentityKey(address *Address, key []byte) (bool, error) {
	k := addressKey(address)
	replaced := false
	if old := s.identities[k]; old != nil {
		if !bytes.Equal(old, key) {
			replaced = true
		}
	}
	s.identities[k] = key
	return replaced, nil
}

func (s *MemoryIdentityKeyStore) GetIdentityKey(address *Address) (*PublicKey, error) {
	data := s.identities[addressKey(address)]
	if data == nil {
		return nil, nil
	}
	return DeserializePublicKey(data)
}

func (s *MemoryIdentityKeyStore) IsTrustedIdentity(address *Address, key *PublicKey, direction uint) (bool, error) {
	existing := s.identities[addressKey(address)]
	if existing == nil {
		// First time seeing this identity — trust on first use
		return true, nil
	}
	keyData, err := key.Serialize()
	if err != nil {
		return false, err
	}
	return bytes.Equal(existing, keyData), nil
}

// MemoryPreKeyStore is an in-memory PreKeyStore.
type MemoryPreKeyStore struct {
	preKeys map[uint32][]byte
}

func NewMemoryPreKeyStore() *MemoryPreKeyStore {
	return &MemoryPreKeyStore{preKeys: map[uint32][]byte{}}
}

func (s *MemoryPreKeyStore) LoadPreKey(id uint32) (*PreKeyRecord, error) {
	data := s.preKeys[id]
	if data == nil {
		return nil, fmt.Errorf("pre-key %d not found", id)
	}
	return DeserializePreKeyRecord(data)
}

func (s *MemoryPreKeyStore) StorePreKey(id uint32, record []byte) error {
	s.preKeys[id] = record
	return nil
}

func (s *MemoryPreKeyStore) RemovePreKey(id uint32) error {
	delete(s.preKeys, id)
	return nil
}

// MemorySignedPreKeyStore is an in-memory SignedPreKeyStore.
type MemorySignedPreKeyStore struct {
	signedPreKeys map[uint32][]byte
}

func NewMemorySignedPreKeyStore() *MemorySignedPreKeyStore {
	return &MemorySignedPreKeyStore{signedPreKeys: map[uint32][]byte{}}
}

func (s *MemorySignedPreKeyStore) LoadSignedPreKey(id uint32) (*SignedPreKeyRecord, error) {
	data := s.signedPreKeys[id]
	if data == nil {
		return nil, fmt.Errorf("signed pre-key %d not found", id)
	}
	return DeserializeSignedPreKeyRecord(data)
}

func (s *MemorySignedPreKeyStore) StoreSignedPreKey(id uint32, record []byte) error {
	s.signedPreKeys[id] = record
	return nil
}

// MemoryKyberPreKeyStore is an in-memory KyberPreKeyStore.
type MemoryKyberPreKeyStore struct {
	kyberPreKeys map[uint32][]byte
	used         map[uint32]bool
}

func NewMemoryKyberPreKeyStore() *MemoryKyberPreKeyStore {
	return &MemoryKyberPreKeyStore{
		kyberPreKeys: map[uint32][]byte{},
		used:         map[uint32]bool{},
	}
}

func (s *MemoryKyberPreKeyStore) LoadKyberPreKey(id uint32) (*KyberPreKeyRecord, error) {
	data := s.kyberPreKeys[id]
	if data == nil {
		return nil, fmt.Errorf("kyber pre-key %d not found", id)
	}
	return DeserializeKyberPreKeyRecord(data)
}

func (s *MemoryKyberPreKeyStore) StoreKyberPreKey(id uint32, record []byte) error {
	s.kyberPreKeys[id] = record
	return nil
}

func (s *MemoryKyberPreKeyStore) MarkKyberPreKeyUsed(id uint32, ecPreKeyID uint32, baseKey []byte) error {
	// ecPreKeyID and baseKey are provided for optional reuse tracking but ignored here
	s.used[id] = true
	return nil
}

// senderKeyKey returns a map key for a sender key (address + distribution ID).
func senderKeyKey(addr *Address, distributionID [16]byte) string {
	name, _ := addr.Name()
	devID, _ := addr.DeviceID()
	return fmt.Sprintf("%s:%d:%x", name, devID, distributionID)
}

// MemorySenderKeyStore is an in-memory SenderKeyStore.
type MemorySenderKeyStore struct {
	senderKeys map[string][]byte
}

func NewMemorySenderKeyStore() *MemorySenderKeyStore {
	return &MemorySenderKeyStore{senderKeys: map[string][]byte{}}
}

func (s *MemorySenderKeyStore) LoadSenderKey(sender *Address, distributionID [16]byte) (*SenderKeyRecord, error) {
	data := s.senderKeys[senderKeyKey(sender, distributionID)]
	if data == nil {
		return nil, nil
	}
	return DeserializeSenderKeyRecord(data)
}

func (s *MemorySenderKeyStore) StoreSenderKey(sender *Address, distributionID [16]byte, record []byte) error {
	s.senderKeys[senderKeyKey(sender, distributionID)] = record
	return nil
}
