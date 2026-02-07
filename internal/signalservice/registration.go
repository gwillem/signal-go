package signalservice

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
)

// RegistrationResult holds the output of a complete device link + registration.
type RegistrationResult struct {
	ProvisionData     *provisioncrypto.ProvisionData
	DeviceID          int
	ACI               string
	PNI               string
	Password          string
	RegistrationID    int
	PNIRegistrationID int

	// Serialized pre-key records for local storage.
	ACISignedPreKey   []byte
	ACIKyberPreKey    []byte
	PNISignedPreKey   []byte
	PNIKyberPreKey    []byte
}

// RegisterLinkedDevice performs the full device registration after provisioning:
// generates pre-keys, encrypts device name, calls PUT /v1/devices/link,
// then uploads pre-keys via PUT /v2/keys.
func RegisterLinkedDevice(ctx context.Context, apiURL string, data *provisioncrypto.ProvisionData, deviceName string, tlsConf *tls.Config) (*RegistrationResult, error) {
	// Reconstruct ACI identity key pair.
	aciPriv, err := libsignal.DeserializePrivateKey(data.ACIIdentityKeyPrivate)
	if err != nil {
		return nil, fmt.Errorf("registration: deserialize ACI private key: %w", err)
	}
	defer aciPriv.Destroy()

	aciPub, err := libsignal.DeserializePublicKey(data.ACIIdentityKeyPublic)
	if err != nil {
		return nil, fmt.Errorf("registration: deserialize ACI public key: %w", err)
	}
	defer aciPub.Destroy()

	aciIdentity := &libsignal.IdentityKeyPair{PublicKey: aciPub, PrivateKey: aciPriv}

	// Reconstruct PNI identity key pair.
	pniPriv, err := libsignal.DeserializePrivateKey(data.PNIIdentityKeyPrivate)
	if err != nil {
		return nil, fmt.Errorf("registration: deserialize PNI private key: %w", err)
	}
	defer pniPriv.Destroy()

	// Generate random registration IDs (14-bit, non-zero).
	registrationID := generateRegistrationID()
	pniRegistrationID := generateRegistrationID()

	// Generate pre-key sets for ACI and PNI.
	// PNI uses offset IDs (0x01000001) to avoid colliding with ACI in local storage.
	aciKeys, err := GeneratePreKeySet(aciPriv, 1, 1)
	if err != nil {
		return nil, fmt.Errorf("registration: generate ACI keys: %w", err)
	}
	defer aciKeys.SignedPreKey.Destroy()
	defer aciKeys.KyberLastResort.Destroy()

	pniKeys, err := GeneratePreKeySet(pniPriv, 0x01000001, 0x01000001)
	if err != nil {
		return nil, fmt.Errorf("registration: generate PNI keys: %w", err)
	}
	defer pniKeys.SignedPreKey.Destroy()
	defer pniKeys.KyberLastResort.Destroy()

	// Encrypt device name.
	encryptedName, err := provisioncrypto.EncryptDeviceName(deviceName, aciIdentity)
	if err != nil {
		return nil, fmt.Errorf("registration: encrypt device name: %w", err)
	}
	encodedName := base64.StdEncoding.EncodeToString(encryptedName)

	// Build signed pre-key entities.
	aciSPK, err := SignedPreKeyToEntity(aciKeys.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("registration: ACI signed pre-key entity: %w", err)
	}

	pniSPK, err := SignedPreKeyToEntity(pniKeys.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("registration: PNI signed pre-key entity: %w", err)
	}

	aciKPK, err := KyberPreKeyToEntity(aciKeys.KyberLastResort)
	if err != nil {
		return nil, fmt.Errorf("registration: ACI Kyber entity: %w", err)
	}

	pniKPK, err := KyberPreKeyToEntity(pniKeys.KyberLastResort)
	if err != nil {
		return nil, fmt.Errorf("registration: PNI Kyber entity: %w", err)
	}

	// Derive unidentified access key from profile key (sealed sender).
	var uakB64 string
	if len(data.ProfileKey) > 0 {
		uak, err := DeriveAccessKey(data.ProfileKey)
		if err != nil {
			return nil, fmt.Errorf("registration: derive access key: %w", err)
		}
		uakB64 = base64.StdEncoding.EncodeToString(uak)
	}

	// Generate password before the link call — Signal requires Basic auth on
	// PUT /v1/devices/link with e164 as username and this password.
	password := generatePassword()

	// Register device.
	transport := NewTransport(apiURL, tlsConf, nil)

	regReq := &RegisterRequest{
		VerificationCode: data.ProvisioningCode,
		AccountAttributes: AccountAttributes{
			RegistrationID:                 registrationID,
			PNIRegistrationID:              pniRegistrationID,
			Voice:                          true,
			Video:                          true,
			FetchesMessages:                true,
			Name:                           encodedName,
			UnidentifiedAccessKey:          uakB64,
			UnrestrictedUnidentifiedAccess: false,
			Capabilities: Capabilities{
				Storage:                  true,
				VersionedExpirationTimer: true,
				AttachmentBackfill:       true,
			},
		},
		ACISignedPreKey: *aciSPK,
		PNISignedPreKey: *pniSPK,
		ACIPqLastResort: *aciKPK,
		PNIPqLastResort: *pniKPK,
	}

	linkAuth := BasicAuth{
		Username: data.Number,
		Password: password,
	}

	// PUT /v1/devices/link
	respBody, status, err := transport.PutJSON(ctx, "/v1/devices/link", regReq, &linkAuth)
	if err != nil {
		return nil, fmt.Errorf("registration: register device: %w", err)
	}
	if status != 200 {
		return nil, fmt.Errorf("registration: register device: status %d: %s", status, respBody)
	}
	var regResp RegisterResponse
	if err := json.Unmarshal(respBody, &regResp); err != nil {
		return nil, fmt.Errorf("registration: unmarshal response: %w", err)
	}

	// Auth for subsequent key uploads uses ACI.deviceID as username.
	auth := BasicAuth{
		Username: fmt.Sprintf("%s.%d", regResp.UUID, regResp.DeviceID),
		Password: password,
	}

	// Upload pre-keys for ACI (PUT /v2/keys?identity=aci).
	respBody, status, err = transport.PutJSON(ctx, "/v2/keys?identity=aci", &PreKeyUpload{
		SignedPreKey:    aciSPK,
		PqLastResortKey: aciKPK,
	}, &auth)
	if err != nil {
		return nil, fmt.Errorf("registration: upload ACI keys: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return nil, fmt.Errorf("registration: upload ACI keys: status %d: %s", status, respBody)
	}

	// Upload pre-keys for PNI (PUT /v2/keys?identity=pni).
	respBody, status, err = transport.PutJSON(ctx, "/v2/keys?identity=pni", &PreKeyUpload{
		SignedPreKey:    pniSPK,
		PqLastResortKey: pniKPK,
	}, &auth)
	if err != nil {
		return nil, fmt.Errorf("registration: upload PNI keys: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return nil, fmt.Errorf("registration: upload PNI keys: status %d: %s", status, respBody)
	}

	// Set account attributes (PUT /v1/accounts/attributes/).
	respBody, status, err = transport.PutJSON(ctx, "/v1/accounts/attributes/", &regReq.AccountAttributes, &auth)
	if err != nil {
		return nil, fmt.Errorf("registration: set account attributes: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return nil, fmt.Errorf("registration: set account attributes: status %d: %s", status, respBody)
	}

	// Serialize pre-key records for local storage.
	aciSPKBytes, err := aciKeys.SignedPreKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("registration: serialize ACI signed pre-key: %w", err)
	}
	aciKPKBytes, err := aciKeys.KyberLastResort.Serialize()
	if err != nil {
		return nil, fmt.Errorf("registration: serialize ACI Kyber pre-key: %w", err)
	}
	pniSPKBytes, err := pniKeys.SignedPreKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("registration: serialize PNI signed pre-key: %w", err)
	}
	pniKPKBytes, err := pniKeys.KyberLastResort.Serialize()
	if err != nil {
		return nil, fmt.Errorf("registration: serialize PNI Kyber pre-key: %w", err)
	}

	return &RegistrationResult{
		ProvisionData:     data,
		DeviceID:          regResp.DeviceID,
		ACI:               regResp.UUID,
		PNI:               regResp.PNI,
		Password:          password,
		RegistrationID:    registrationID,
		PNIRegistrationID: pniRegistrationID,
		ACISignedPreKey:   aciSPKBytes,
		ACIKyberPreKey:    aciKPKBytes,
		PNISignedPreKey:   pniSPKBytes,
		PNIKyberPreKey:    pniKPKBytes,
	}, nil
}

// SignedPreKeyEntity converts a SignedPreKeyRecord to a SignedPreKeyEntity for upload.
func SignedPreKeyToEntity(rec *libsignal.SignedPreKeyRecord) (*SignedPreKeyEntity, error) {
	id, err := rec.ID()
	if err != nil {
		return nil, err
	}

	pub, err := rec.PublicKey()
	if err != nil {
		return nil, err
	}
	defer pub.Destroy()

	pubBytes, err := pub.Serialize()
	if err != nil {
		return nil, err
	}

	sig, err := rec.Signature()
	if err != nil {
		return nil, err
	}

	return &SignedPreKeyEntity{
		KeyID:     int(id),
		PublicKey: base64.RawStdEncoding.EncodeToString(pubBytes),
		Signature: base64.RawStdEncoding.EncodeToString(sig),
	}, nil
}

// KyberPreKeyToEntity converts a KyberPreKeyRecord to a KyberPreKeyEntity for upload.
func KyberPreKeyToEntity(rec *libsignal.KyberPreKeyRecord) (*KyberPreKeyEntity, error) {
	id, err := rec.ID()
	if err != nil {
		return nil, err
	}

	pub, err := rec.PublicKey()
	if err != nil {
		return nil, err
	}
	defer pub.Destroy()

	pubBytes, err := pub.Serialize()
	if err != nil {
		return nil, err
	}

	sig, err := rec.Signature()
	if err != nil {
		return nil, err
	}

	return &KyberPreKeyEntity{
		KeyID:     int(id),
		PublicKey: base64.RawStdEncoding.EncodeToString(pubBytes),
		Signature: base64.RawStdEncoding.EncodeToString(sig),
	}, nil
}

// generateRegistrationID generates a random 14-bit registration ID (1-16380).
func generateRegistrationID() int {
	var buf [4]byte
	rand.Read(buf[:])
	return int(binary.BigEndian.Uint32(buf[:])&0x3FFF) + 1
}

// generatePassword generates a random 24-byte password, base64url-encoded.
func generatePassword() string {
	buf := make([]byte, 24)
	rand.Read(buf)
	return base64.RawURLEncoding.EncodeToString(buf)
}

// GenerateProfileKey generates a random 32-byte profile key.
func GenerateProfileKey() []byte {
	buf := make([]byte, 32)
	rand.Read(buf)
	return buf
}

