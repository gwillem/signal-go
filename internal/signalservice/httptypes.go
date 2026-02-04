package signalservice

import "github.com/gwillem/signal-go/internal/proto"

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
	RegistrationID                 int          `json:"registrationId"`
	PNIRegistrationID              int          `json:"pniRegistrationId"`
	Voice                          bool         `json:"voice"`
	Video                          bool         `json:"video"`
	FetchesMessages                bool         `json:"fetchesMessages"`
	Name                           string       `json:"name,omitempty"` // base64 encrypted device name
	Capabilities                   Capabilities `json:"capabilities"`
	UnidentifiedAccessKey          string       `json:"unidentifiedAccessKey,omitempty"`          // base64, 16 bytes
	UnrestrictedUnidentifiedAccess bool         `json:"unrestrictedUnidentifiedAccess,omitempty"` // allow sealed sender from anyone
	DiscoverableByPhoneNumber      *bool        `json:"discoverableByPhoneNumber,omitempty"`      // allow finding via CDSI
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

// PreKeyResponse is the JSON response from GET /v2/keys/{destination}/{deviceId}.
type PreKeyResponse struct {
	IdentityKey string             `json:"identityKey"`
	Devices     []PreKeyDeviceInfo `json:"devices"`
}

// PreKeyDeviceInfo contains pre-key material for a single device.
type PreKeyDeviceInfo struct {
	DeviceID       int                `json:"deviceId"`
	RegistrationID int                `json:"registrationId"`
	SignedPreKey   *SignedPreKeyEntity `json:"signedPreKey"`
	PreKey         *PreKeyEntity       `json:"preKey,omitempty"`
	PqPreKey       *KyberPreKeyEntity  `json:"pqPreKey,omitempty"`
}

// PreKeyEntity is the JSON representation of a one-time pre-key.
type PreKeyEntity struct {
	KeyID     int    `json:"keyId"`
	PublicKey string `json:"publicKey"`
}

// OutgoingMessageList is the JSON body for PUT /v1/messages/{destination}.
type OutgoingMessageList struct {
	Destination string            `json:"destination"`
	Timestamp   uint64            `json:"timestamp"`
	Messages    []OutgoingMessage `json:"messages"`
	Online      bool              `json:"online"`
	Urgent      bool              `json:"urgent"`
}

// OutgoingMessage is a single message in an OutgoingMessageList.
type OutgoingMessage struct {
	Type                      proto.Envelope_Type `json:"type"`
	DestinationDeviceID       int                 `json:"destinationDeviceId"`
	DestinationRegistrationID int                 `json:"destinationRegistrationId"`
	Content                   string              `json:"content"` // base64
}

// DeviceListResponse is the JSON response from GET /v1/devices/.
type DeviceListResponse struct {
	Devices []DeviceInfo `json:"devices"`
}

// DeviceInfo describes a registered device.
type DeviceInfo struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Created  int64  `json:"created"`
	LastSeen int64  `json:"lastSeen"`
}

// VerificationSessionRequest creates a new verification session for primary registration.
type VerificationSessionRequest struct {
	Number    string `json:"number"`
	PushToken string `json:"pushToken,omitempty"`
	MCC       string `json:"mcc,omitempty"`
	MNC       string `json:"mnc,omitempty"`
}

// VerificationSessionResponse contains the current state of a verification session.
type VerificationSessionResponse struct {
	ID                      string   `json:"id"`
	NextSms                 *int     `json:"nextSms"`
	NextCall                *int     `json:"nextCall"`
	NextVerificationAttempt *int     `json:"nextVerificationAttempt"`
	AllowedToRequestCode    bool     `json:"allowedToRequestCode"`
	RequestedInformation    []string `json:"requestedInformation"` // e.g., ["captcha", "pushChallenge"]
	Verified                bool     `json:"verified"`
}

// RequestVerificationCodeRequest asks for an SMS or voice verification code.
type RequestVerificationCodeRequest struct {
	Transport string `json:"transport"` // "sms" or "voice"
	Client    string `json:"client"`    // e.g., "android-2024-01"
}

// SubmitVerificationCodeRequest submits the received 6-digit code.
type SubmitVerificationCodeRequest struct {
	Code string `json:"code"`
}

// UpdateSessionRequest submits CAPTCHA or push challenge response.
type UpdateSessionRequest struct {
	Captcha       string `json:"captcha,omitempty"`
	PushChallenge string `json:"pushChallenge,omitempty"`
}

// PrimaryRegistrationRequest registers a new primary device.
type PrimaryRegistrationRequest struct {
	SessionID             string             `json:"sessionId,omitempty"`
	RecoveryPassword      string             `json:"recoveryPassword,omitempty"`
	AccountAttributes     AccountAttributes  `json:"accountAttributes"`
	ACIIdentityKey        string             `json:"aciIdentityKey"`        // base64
	PNIIdentityKey        string             `json:"pniIdentityKey"`        // base64
	ACISignedPreKey       SignedPreKeyEntity `json:"aciSignedPreKey"`
	PNISignedPreKey       SignedPreKeyEntity `json:"pniSignedPreKey"`
	ACIPqLastResortPreKey KyberPreKeyEntity  `json:"aciPqLastResortPreKey"`
	PNIPqLastResortPreKey KyberPreKeyEntity  `json:"pniPqLastResortPreKey"`
	SkipDeviceTransfer    bool               `json:"skipDeviceTransfer"`
	RequireAtomic         bool               `json:"requireAtomic,omitempty"`
}

// PrimaryRegistrationResponse is returned from POST /v1/registration.
type PrimaryRegistrationResponse struct {
	UUID           string `json:"uuid"`
	PNI            string `json:"pni"`
	Number         string `json:"number"`
	StorageCapable bool   `json:"storageCapable"`
}

// ProfileWrite is the JSON body for PUT /v1/profile.
type ProfileWrite struct {
	Version            string   `json:"version"`            // hex-encoded profile key version
	Name               []byte   `json:"name"`               // encrypted name
	About              []byte   `json:"about"`              // encrypted about text
	AboutEmoji         []byte   `json:"aboutEmoji"`         // encrypted emoji
	PhoneNumberSharing []byte   `json:"phoneNumberSharing"` // encrypted boolean
	Avatar             bool     `json:"avatar"`             // whether to set avatar
	SameAvatar         bool     `json:"sameAvatar"`         // keep existing avatar
	Commitment         []byte   `json:"commitment"`         // profile key commitment
	BadgeIDs           []string `json:"badgeIds"`           // visible badge IDs
}

// ProfileResponse is the JSON response from GET /v1/profile/{aci}/{version}.
type ProfileResponse struct {
	IdentityKey                    string `json:"identityKey"`
	Name                           string `json:"name"`                          // base64 encrypted
	About                          string `json:"about"`                         // base64 encrypted
	AboutEmoji                     string `json:"aboutEmoji"`                    // base64 encrypted
	Avatar                         string `json:"avatar"`                        // CDN path
	UnidentifiedAccess             string `json:"unidentifiedAccess"`            // base64
	UnrestrictedUnidentifiedAccess bool   `json:"unrestrictedUnidentifiedAccess"`
}

// SenderCertificateResponse is the JSON response from GET /v1/certificate/delivery.
type SenderCertificateResponse struct {
	Certificate string `json:"certificate"` // base64-encoded SenderCertificate protobuf
}
