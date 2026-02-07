package libsignal

// SessionStore stores session records keyed by protocol address.
type SessionStore interface {
	LoadSession(address *Address) (*SessionRecord, error)
	StoreSession(address *Address, record []byte) error
}

// IdentityKeyStore manages the local identity key and remote identity trust.
type IdentityKeyStore interface {
	GetIdentityKeyPair() (*PrivateKey, error)
	GetLocalRegistrationID() (uint32, error)
	// SaveIdentityKey stores a remote identity key (serialized). Returns true if this
	// replaced an existing different identity key (identity change), false if new or unchanged.
	SaveIdentityKey(address *Address, key []byte) (replaced bool, err error)
	GetIdentityKey(address *Address) (*PublicKey, error)
	IsTrustedIdentity(address *Address, key *PublicKey, direction uint) (bool, error)
}

// PreKeyStore stores one-time pre-key records.
type PreKeyStore interface {
	LoadPreKey(id uint32) (*PreKeyRecord, error)
	StorePreKey(id uint32, record []byte) error
	RemovePreKey(id uint32) error
}

// SignedPreKeyStore stores signed pre-key records.
type SignedPreKeyStore interface {
	LoadSignedPreKey(id uint32) (*SignedPreKeyRecord, error)
	StoreSignedPreKey(id uint32, record []byte) error
}

// KyberPreKeyStore stores Kyber pre-key records.
type KyberPreKeyStore interface {
	LoadKyberPreKey(id uint32) (*KyberPreKeyRecord, error)
	StoreKyberPreKey(id uint32, record []byte) error
	// MarkKyberPreKeyUsed marks a Kyber pre-key as used. The ecPreKeyID and baseKey
	// parameters can be used for reuse tracking (optional; implementations may ignore them).
	MarkKyberPreKeyUsed(id uint32, ecPreKeyID uint32, baseKey []byte) error
}

// SenderKeyStore stores sender key records for group messaging.
// Sender keys are keyed by (sender address, distribution ID).
type SenderKeyStore interface {
	LoadSenderKey(sender *Address, distributionID [16]byte) (*SenderKeyRecord, error)
	StoreSenderKey(sender *Address, distributionID [16]byte, record []byte) error
}
