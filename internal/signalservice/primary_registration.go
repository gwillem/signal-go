package signalservice

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"slices"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// PrimaryRegistrationResult holds the output of a complete primary device registration.
type PrimaryRegistrationResult struct {
	ACI               string
	PNI               string
	Number            string
	DeviceID          int // Always 1 for primary
	Password          string
	RegistrationID    int
	PNIRegistrationID int

	// Identity key pairs (generated locally).
	ACIIdentityKeyPrivate []byte
	ACIIdentityKeyPublic  []byte
	PNIIdentityKeyPrivate []byte
	PNIIdentityKeyPublic  []byte

	// Serialized pre-key records for local storage.
	ACISignedPreKey []byte
	ACIKyberPreKey  []byte
	PNISignedPreKey []byte
	PNIKyberPreKey  []byte
}

// CaptchaRequiredError is returned when a CAPTCHA challenge is required.
type CaptchaRequiredError struct {
	SessionID string
}

func (e *CaptchaRequiredError) Error() string {
	return "captcha required: visit https://signalcaptchas.org/registration/generate.html"
}

// RegisterPrimary orchestrates the full primary device registration flow:
// 1. Create verification session
// 2. Request verification code (SMS or voice)
// 3. Handle CAPTCHA challenges if required
// 4. Submit verification code
// 5. Generate identity keys locally
// 6. Generate pre-keys
// 7. Register account
// 8. Upload pre-keys
//
// The getCode callback is called to prompt the user for the verification code.
// The getCaptcha callback is called if a CAPTCHA challenge is required; it should
// return the token from the signalcaptcha:// redirect URL.
func RegisterPrimary(
	ctx context.Context,
	apiURL string,
	number string,
	transport string, // "sms" or "voice"
	getCode func() (string, error),
	getCaptcha func() (string, error),
	tlsConf *tls.Config,
	logger *log.Logger,
) (*PrimaryRegistrationResult, error) {
	httpClient := NewHTTPClient(apiURL, tlsConf, logger)

	// Step 1: Create verification session.
	logf(logger, "creating verification session for %s", number)
	session, err := httpClient.CreateVerificationSession(ctx, number)
	if err != nil {
		return nil, fmt.Errorf("primary registration: create session: %w", err)
	}
	logf(logger, "session created: id=%s allowedToRequestCode=%v requestedInformation=%v",
		session.ID, session.AllowedToRequestCode, session.RequestedInformation)

	// Step 2: Handle CAPTCHA if required before requesting code.
	if slices.Contains(session.RequestedInformation, "captcha") {
		logf(logger, "CAPTCHA required before requesting code")
		captchaToken, err := getCaptcha()
		if err != nil {
			return nil, fmt.Errorf("primary registration: get captcha: %w", err)
		}
		session, err = httpClient.UpdateSession(ctx, session.ID, &UpdateSessionRequest{
			Captcha: captchaToken,
		})
		if err != nil {
			return nil, fmt.Errorf("primary registration: submit captcha: %w", err)
		}
		logf(logger, "CAPTCHA submitted, session updated: allowedToRequestCode=%v", session.AllowedToRequestCode)
	}

	// Step 3: Request verification code.
	if !session.AllowedToRequestCode {
		return nil, fmt.Errorf("primary registration: not allowed to request code (session: %+v)", session)
	}
	logf(logger, "requesting %s verification code", transport)
	session, err = httpClient.RequestVerificationCode(ctx, session.ID, transport)
	if err != nil {
		return nil, fmt.Errorf("primary registration: request code: %w", err)
	}
	logf(logger, "verification code requested")

	// Step 4: Get code from user and submit.
	code, err := getCode()
	if err != nil {
		return nil, fmt.Errorf("primary registration: get code from user: %w", err)
	}
	logf(logger, "submitting verification code")
	session, err = httpClient.SubmitVerificationCode(ctx, session.ID, code)
	if err != nil {
		return nil, fmt.Errorf("primary registration: submit code: %w", err)
	}
	if !session.Verified {
		return nil, fmt.Errorf("primary registration: session not verified after code submission")
	}
	logf(logger, "session verified")

	// Step 5: Generate identity keys locally.
	logf(logger, "generating identity keys")
	aciIdentity, err := libsignal.GenerateIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("primary registration: generate ACI identity: %w", err)
	}
	defer aciIdentity.PrivateKey.Destroy()
	defer aciIdentity.PublicKey.Destroy()

	pniIdentity, err := libsignal.GenerateIdentityKeyPair()
	if err != nil {
		return nil, fmt.Errorf("primary registration: generate PNI identity: %w", err)
	}
	defer pniIdentity.PrivateKey.Destroy()
	defer pniIdentity.PublicKey.Destroy()

	// Serialize identity keys.
	aciPrivBytes, err := aciIdentity.PrivateKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("primary registration: serialize ACI private key: %w", err)
	}
	aciPubBytes, err := aciIdentity.PublicKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("primary registration: serialize ACI public key: %w", err)
	}
	pniPrivBytes, err := pniIdentity.PrivateKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("primary registration: serialize PNI private key: %w", err)
	}
	pniPubBytes, err := pniIdentity.PublicKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("primary registration: serialize PNI public key: %w", err)
	}

	// Step 6: Generate random registration IDs.
	registrationID := generateRegistrationID()
	pniRegistrationID := generateRegistrationID()

	// Step 7: Generate pre-key sets.
	logf(logger, "generating pre-keys")
	aciKeys, err := GeneratePreKeySet(aciIdentity.PrivateKey, 1, 1)
	if err != nil {
		return nil, fmt.Errorf("primary registration: generate ACI keys: %w", err)
	}
	defer aciKeys.SignedPreKey.Destroy()
	defer aciKeys.KyberLastResort.Destroy()

	pniKeys, err := GeneratePreKeySet(pniIdentity.PrivateKey, 0x01000001, 0x01000001)
	if err != nil {
		return nil, fmt.Errorf("primary registration: generate PNI keys: %w", err)
	}
	defer pniKeys.SignedPreKey.Destroy()
	defer pniKeys.KyberLastResort.Destroy()

	// Build pre-key entities.
	aciSPK, err := signedPreKeyEntity(aciKeys.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("primary registration: ACI signed pre-key entity: %w", err)
	}
	pniSPK, err := signedPreKeyEntity(pniKeys.SignedPreKey)
	if err != nil {
		return nil, fmt.Errorf("primary registration: PNI signed pre-key entity: %w", err)
	}
	aciKPK, err := kyberPreKeyEntity(aciKeys.KyberLastResort)
	if err != nil {
		return nil, fmt.Errorf("primary registration: ACI Kyber entity: %w", err)
	}
	pniKPK, err := kyberPreKeyEntity(pniKeys.KyberLastResort)
	if err != nil {
		return nil, fmt.Errorf("primary registration: PNI Kyber entity: %w", err)
	}

	// Generate password for Basic auth.
	password := generatePassword()

	// Step 8: Register account.
	// Auth uses phone number as username and the generated password.
	regAuth := BasicAuth{
		Username: number,
		Password: password,
	}

	logf(logger, "registering account")
	discoverable := true
	regReq := &PrimaryRegistrationRequest{
		SessionID: session.ID,
		AccountAttributes: AccountAttributes{
			RegistrationID:            registrationID,
			PNIRegistrationID:         pniRegistrationID,
			Voice:                     true,
			Video:                     true,
			FetchesMessages:           true,
			DiscoverableByPhoneNumber: &discoverable,
			Capabilities: Capabilities{
				Storage:                  true,
				VersionedExpirationTimer: true,
				AttachmentBackfill:       true,
			},
		},
		ACIIdentityKey:        base64.StdEncoding.EncodeToString(aciPubBytes),
		PNIIdentityKey:        base64.StdEncoding.EncodeToString(pniPubBytes),
		ACISignedPreKey:       *aciSPK,
		PNISignedPreKey:       *pniSPK,
		ACIPqLastResortPreKey: *aciKPK,
		PNIPqLastResortPreKey: *pniKPK,
		SkipDeviceTransfer:    true,
	}

	regResp, err := httpClient.RegisterPrimaryDevice(ctx, regReq, regAuth)
	if err != nil {
		return nil, fmt.Errorf("primary registration: register: %w", err)
	}
	logf(logger, "registered: aci=%s pni=%s number=%s", regResp.UUID, regResp.PNI, regResp.Number)

	// Step 9: Upload pre-keys (primary device is always device 1).
	auth := BasicAuth{
		Username: fmt.Sprintf("%s.1", regResp.UUID),
		Password: password,
	}

	logf(logger, "uploading ACI pre-keys")
	err = httpClient.UploadPreKeys(ctx, "aci", &PreKeyUpload{
		SignedPreKey:    aciSPK,
		PqLastResortKey: aciKPK,
	}, auth)
	if err != nil {
		return nil, fmt.Errorf("primary registration: upload ACI keys: %w", err)
	}

	logf(logger, "uploading PNI pre-keys")
	err = httpClient.UploadPreKeys(ctx, "pni", &PreKeyUpload{
		SignedPreKey:    pniSPK,
		PqLastResortKey: pniKPK,
	}, auth)
	if err != nil {
		return nil, fmt.Errorf("primary registration: upload PNI keys: %w", err)
	}

	// Serialize pre-key records for local storage.
	aciSPKBytes, err := aciKeys.SignedPreKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("primary registration: serialize ACI signed pre-key: %w", err)
	}
	aciKPKBytes, err := aciKeys.KyberLastResort.Serialize()
	if err != nil {
		return nil, fmt.Errorf("primary registration: serialize ACI Kyber pre-key: %w", err)
	}
	pniSPKBytes, err := pniKeys.SignedPreKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("primary registration: serialize PNI signed pre-key: %w", err)
	}
	pniKPKBytes, err := pniKeys.KyberLastResort.Serialize()
	if err != nil {
		return nil, fmt.Errorf("primary registration: serialize PNI Kyber pre-key: %w", err)
	}

	return &PrimaryRegistrationResult{
		ACI:                   regResp.UUID,
		PNI:                   regResp.PNI,
		Number:                regResp.Number,
		DeviceID:              1,
		Password:              password,
		RegistrationID:        registrationID,
		PNIRegistrationID:     pniRegistrationID,
		ACIIdentityKeyPrivate: aciPrivBytes,
		ACIIdentityKeyPublic:  aciPubBytes,
		PNIIdentityKeyPrivate: pniPrivBytes,
		PNIIdentityKeyPublic:  pniPubBytes,
		ACISignedPreKey:       aciSPKBytes,
		ACIKyberPreKey:        aciKPKBytes,
		PNISignedPreKey:       pniSPKBytes,
		PNIKyberPreKey:        pniKPKBytes,
	}, nil
}
