package signalservice

// BasicAuth holds credentials for HTTP Basic authentication.
type BasicAuth struct {
	Username string // "{aci}.{deviceId}"
	Password string
}

// RegisterRequest is the JSON body for PUT /v1/devices/link.
type RegisterRequest struct {
	VerificationCode  string            `json:"verificationCode"`
	AccountAttributes AccountAttributes `json:"accountAttributes"`
	ACISignedPreKey   SignedPreKeyEntity `json:"aciSignedPreKey"`
	PNISignedPreKey   SignedPreKeyEntity `json:"pniSignedPreKey"`
	ACIPqLastResort   KyberPreKeyEntity  `json:"aciPqLastResortPreKey"`
	PNIPqLastResort   KyberPreKeyEntity  `json:"pniPqLastResortPreKey"`
}

// AccountAttributes describes the account properties for registration.
type AccountAttributes struct {
	RegistrationID    int          `json:"registrationId"`
	PNIRegistrationID int          `json:"pniRegistrationId"`
	FetchesMessages   bool         `json:"fetchesMessages"`
	Name              string       `json:"name"` // base64 encrypted device name
	Capabilities      Capabilities `json:"capabilities"`
}

// Capabilities declares supported features.
type Capabilities struct {
	Storage                  bool `json:"storage"`
	VersionedExpirationTimer bool `json:"versionedExpirationTimer"`
	AttachmentBackfill       bool `json:"attachmentBackfill"`
}

// SignedPreKeyEntity is the JSON representation of a signed EC pre-key.
type SignedPreKeyEntity struct {
	KeyID     int    `json:"keyId"`
	PublicKey string `json:"publicKey"` // base64 no-pad
	Signature string `json:"signature"` // base64 no-pad
}

// KyberPreKeyEntity is the JSON representation of a Kyber pre-key.
type KyberPreKeyEntity struct {
	KeyID     int    `json:"keyId"`
	PublicKey string `json:"publicKey"` // base64 no-pad
	Signature string `json:"signature"` // base64 no-pad
}

// RegisterResponse is the JSON response from PUT /v1/devices/link.
type RegisterResponse struct {
	UUID     string `json:"uuid"`
	PNI      string `json:"pni"`
	DeviceID int    `json:"deviceId"`
}

// PreKeyUpload is the JSON body for PUT /v2/keys.
type PreKeyUpload struct {
	SignedPreKey    *SignedPreKeyEntity `json:"signedPreKey,omitempty"`
	PqLastResortKey *KyberPreKeyEntity `json:"pqLastResortPreKey,omitempty"`
}
