package libsignal

// SessionStore stores session records keyed by protocol address.
type SessionStore interface {
	LoadSession(address *Address) (*SessionRecord, error)
	StoreSession(address *Address, record *SessionRecord) error
}

// IdentityKeyStore manages the local identity key and remote identity trust.
type IdentityKeyStore interface {
	GetIdentityKeyPair() (*PrivateKey, error)
	GetLocalRegistrationID() (uint32, error)
	SaveIdentityKey(address *Address, key *PublicKey) error
	GetIdentityKey(address *Address) (*PublicKey, error)
	IsTrustedIdentity(address *Address, key *PublicKey, direction uint) (bool, error)
}

// PreKeyStore stores one-time pre-key records.
type PreKeyStore interface {
	LoadPreKey(id uint32) (*PreKeyRecord, error)
	StorePreKey(id uint32, record *PreKeyRecord) error
	RemovePreKey(id uint32) error
}

// SignedPreKeyStore stores signed pre-key records.
type SignedPreKeyStore interface {
	LoadSignedPreKey(id uint32) (*SignedPreKeyRecord, error)
	StoreSignedPreKey(id uint32, record *SignedPreKeyRecord) error
}

// KyberPreKeyStore stores Kyber pre-key records.
type KyberPreKeyStore interface {
	LoadKyberPreKey(id uint32) (*KyberPreKeyRecord, error)
	StoreKyberPreKey(id uint32, record *KyberPreKeyRecord) error
	MarkKyberPreKeyUsed(id uint32) error
}
