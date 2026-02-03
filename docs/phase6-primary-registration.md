# Phase 6: Primary Device Registration

## Goal

Implement `sgnl register +NNNNNN` to register a new Signal account as a primary device. This enables testing sealed sender and other features with a fully controlled account.

## Background

Currently signal-go only supports linking as a secondary device (`sgnl link`). Primary device registration is a separate flow that:
- Generates identity keys locally (instead of receiving them via provisioning)
- Uses SMS/voice verification (instead of QR code provisioning)
- Registers via `POST /v1/registration` (instead of `PUT /v1/devices/link`)

## Registration Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  1. Create Session                                              │
│     POST /v1/verification/session                               │
│     Body: { number: "+31612345678" }                            │
│     Response: { id, nextSms, allowedToRequestCode, verified }   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  2. Request Verification Code                                   │
│     POST /v1/verification/session/{sessionId}/code              │
│     Body: { transport: "sms" }                                  │
│     Response: { nextSms, nextCall, allowedToRequestCode }       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. (Optional) Handle Challenges                                │
│     PATCH /v1/verification/session/{sessionId}                  │
│     Body: { captcha: "...", pushChallenge: "..." }              │
│     Only if requestedInformation contains challenges            │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Submit Verification Code                                    │
│     PUT /v1/verification/session/{sessionId}/code               │
│     Body: { code: "123456" }                                    │
│     Response: { verified: true }                                │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  5. Register Account                                            │
│     POST /v1/registration                                       │
│     Body: {                                                     │
│       sessionId,                                                │
│       accountAttributes,                                        │
│       aciIdentityKey, pniIdentityKey,                           │
│       aciSignedPreKey, pniSignedPreKey,                         │
│       aciPqLastResortPreKey, pniPqLastResortPreKey              │
│     }                                                           │
│     Response: { uuid, pni, number }                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│  6. Upload Pre-Keys                                             │
│     PUT /v2/keys?identity=aci                                   │
│     PUT /v2/keys?identity=pni                                   │
│     (Same as secondary device flow)                             │
└─────────────────────────────────────────────────────────────────┘
```

## Implementation Plan

### Task 1: Add HTTP Types

**File: `internal/signalservice/httptypes.go`**

```go
// VerificationSessionRequest creates a new verification session
type VerificationSessionRequest struct {
    Number    string `json:"number"`
    PushToken string `json:"pushToken,omitempty"`
    MCC       string `json:"mcc,omitempty"`
    MNC       string `json:"mnc,omitempty"`
}

// VerificationSessionResponse contains session state
type VerificationSessionResponse struct {
    ID                      string   `json:"id"`
    NextSms                 *int     `json:"nextSms"`
    NextCall                *int     `json:"nextCall"`
    NextVerificationAttempt *int     `json:"nextVerificationAttempt"`
    AllowedToRequestCode    bool     `json:"allowedToRequestCode"`
    RequestedInformation    []string `json:"requestedInformation"` // ["captcha", "pushChallenge"]
    Verified                bool     `json:"verified"`
}

// RequestVerificationCodeRequest asks for SMS or voice code
type RequestVerificationCodeRequest struct {
    Transport string `json:"transport"` // "sms" or "voice"
    Client    string `json:"client"`    // "android-2024-01" or similar
}

// SubmitVerificationCodeRequest submits the received code
type SubmitVerificationCodeRequest struct {
    Code string `json:"code"`
}

// UpdateSessionRequest for CAPTCHA/push challenge
type UpdateSessionRequest struct {
    Captcha       string `json:"captcha,omitempty"`
    PushChallenge string `json:"pushChallenge,omitempty"`
}

// PrimaryRegistrationRequest registers a new primary device
type PrimaryRegistrationRequest struct {
    SessionID            string              `json:"sessionId,omitempty"`
    RecoveryPassword     string              `json:"recoveryPassword,omitempty"`
    AccountAttributes    AccountAttributes   `json:"accountAttributes"`
    ACIIdentityKey       string              `json:"aciIdentityKey"`       // base64
    PNIIdentityKey       string              `json:"pniIdentityKey"`       // base64
    ACISignedPreKey      SignedPreKeyEntity  `json:"aciSignedPreKey"`
    PNISignedPreKey      SignedPreKeyEntity  `json:"pniSignedPreKey"`
    ACIPqLastResortPreKey KyberPreKeyEntity  `json:"aciPqLastResortPreKey"`
    PNIPqLastResortPreKey KyberPreKeyEntity  `json:"pniPqLastResortPreKey"`
    SkipDeviceTransfer   bool                `json:"skipDeviceTransfer"`
    RequireAtomic        bool                `json:"requireAtomic"`
}

// PrimaryRegistrationResponse from POST /v1/registration
type PrimaryRegistrationResponse struct {
    UUID           string `json:"uuid"`
    PNI            string `json:"pni"`
    Number         string `json:"number"`
    StorageCapable bool   `json:"storageCapable"`
    Reregistration bool   `json:"reregistration"`
}
```

### Task 2: Add HTTP Client Methods

**File: `internal/signalservice/httpclient.go`**

```go
// CreateVerificationSession starts the registration flow
func (c *HTTPClient) CreateVerificationSession(ctx context.Context, number string) (*VerificationSessionResponse, error)

// GetSessionStatus polls session state
func (c *HTTPClient) GetSessionStatus(ctx context.Context, sessionID string) (*VerificationSessionResponse, error)

// RequestVerificationCode requests SMS or voice code
func (c *HTTPClient) RequestVerificationCode(ctx context.Context, sessionID, transport string) (*VerificationSessionResponse, error)

// SubmitVerificationCode submits the 6-digit code
func (c *HTTPClient) SubmitVerificationCode(ctx context.Context, sessionID, code string) (*VerificationSessionResponse, error)

// UpdateSession submits CAPTCHA or push challenge
func (c *HTTPClient) UpdateSession(ctx context.Context, sessionID string, req *UpdateSessionRequest) (*VerificationSessionResponse, error)

// RegisterPrimaryDevice registers a new primary account
func (c *HTTPClient) RegisterPrimaryDevice(ctx context.Context, req *PrimaryRegistrationRequest) (*PrimaryRegistrationResponse, error)
```

### Task 3: Add Registration Orchestration

**File: `internal/signalservice/primary_registration.go`**

```go
// PrimaryRegistrationResult contains the complete registration result
type PrimaryRegistrationResult struct {
    ACI             string
    PNI             string
    Number          string
    DeviceID        uint32 // Always 1 for primary
    ACIIdentityKey  *libsignal.PrivateKey
    PNIIdentityKey  *libsignal.PrivateKey
}

// RegisterPrimaryDevice orchestrates the full registration flow
func RegisterPrimaryDevice(
    ctx context.Context,
    httpClient *HTTPClient,
    number string,
    getCode func() (string, error), // Callback to get verification code from user
    logger *log.Logger,
) (*PrimaryRegistrationResult, error) {
    // 1. Create session
    // 2. Request SMS code
    // 3. Handle challenges if needed
    // 4. Get code from user via callback
    // 5. Submit code
    // 6. Generate identity keys locally
    // 7. Generate pre-keys
    // 8. Register account
    // 9. Return result
}
```

### Task 4: Add CLI Command

**File: `cmd/sgnl/register.go`**

```go
type registerCommand struct {
    Args struct {
        Number string `positional-arg-name:"number" required:"true" description:"Phone number in E.164 format (+31612345678)"`
    } `positional-args:"true" required:"true"`
    Voice bool `long:"voice" description:"Request voice call instead of SMS"`
}

func (cmd *registerCommand) Execute(args []string) error {
    // 1. Create HTTP client (no auth needed initially)
    // 2. Start registration flow
    // 3. Prompt user for verification code
    // 4. Complete registration
    // 5. Save credentials to store
    // 6. Print success message with ACI/PNI
}
```

**File: `cmd/sgnl/main.go`**

Add to globalOpts:
```go
Register registerCommand `command:"register" description:"Register a new Signal account (primary device)"`
```

### Task 5: Update Client API

**File: `client.go`**

```go
// Register registers a new Signal account as primary device.
// The getCode callback is called to prompt the user for the SMS/voice verification code.
func (c *Client) Register(ctx context.Context, number string, getCode func() (string, error)) error
```

## Key Differences from Secondary Device

| Aspect | Primary (new) | Secondary (existing) |
|--------|---------------|----------------------|
| Identity keys | Generated locally | Received via provisioning |
| Verification | SMS/voice + CAPTCHA | QR code scan |
| Endpoint | `POST /v1/registration` | `PUT /v1/devices/link` |
| Device ID | Always 1 | Assigned by server (2+) |
| Auth | None initially | Basic auth after linking |

## Files to Create/Modify

| File | Action | Description | Status |
|------|--------|-------------|--------|
| `internal/signalservice/httptypes.go` | Modify | Add verification session types | Done |
| `internal/signalservice/httpclient.go` | Modify | Add verification/registration endpoints | Done |
| `internal/signalservice/httpclient_test.go` | Modify | Add tests for new endpoints | Done |
| `internal/signalservice/primary_registration.go` | Create | Registration orchestration | Done |
| `cmd/sgnl/register.go` | Create | CLI command | Done |
| `cmd/sgnl/main.go` | Modify | Add register command | Done |
| `client.go` | Modify | Add Register() method | Done |

## Testing

### Unit Tests

- `TestCreateVerificationSession` - mock HTTP response
- `TestRequestVerificationCode` - SMS and voice transport
- `TestSubmitVerificationCode` - success and failure cases
- `TestRegisterPrimaryDevice` - full registration with mocked HTTP

### Integration Test (Manual)

```bash
# Register new account
go run ./cmd/sgnl register +31612345678

# Enter verification code when prompted
# Should output:
# Registered successfully!
# ACI: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# PNI: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
# Number: +31612345678

# Verify by receiving a message
go run ./cmd/sgnl -v receive
```

## Error Handling

| Error | Cause | Resolution |
|-------|-------|------------|
| 400 Bad Request | Invalid phone number format | Validate E.164 format |
| 402 Payment Required | CAPTCHA required | Prompt user for CAPTCHA token |
| 409 Conflict | Number already registered | Offer re-registration option |
| 429 Too Many Requests | Rate limited | Wait and retry (use Retry-After header) |
| 440 Unprocessable | Session expired | Start new session |

## CAPTCHA Handling

When `requestedInformation` contains `"captcha"`:

1. Direct user to Signal's CAPTCHA URL
2. User solves CAPTCHA in browser
3. User copies token from redirect URL
4. Submit token via `PATCH /v1/verification/session/{id}`

CAPTCHA URL: `https://signalcaptchas.org/registration/generate.html`

Token format: `signalcaptcha://signal-recaptcha-v2.{token}`

## Status

- [x] Task 1: Add HTTP types
- [x] Task 2: Add HTTP client methods
- [x] Task 3: Add registration orchestration
- [x] Task 4: Add CLI command
- [x] Task 5: Update Client API
- [x] Task 6: Add tests
- [ ] Task 7: Manual integration test

## References

- Signal-Android: `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/api/registration/RegistrationApi.kt`
- Signal-Android: `lib/libsignal-service/src/main/java/org/whispersystems/signalservice/internal/push/PushServiceSocket.java`
- Existing secondary device code: `internal/signalservice/registration.go`
