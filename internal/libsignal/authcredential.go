package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"
import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"unsafe"
)

// ServerPublicParams contains the public parameters for the Signal server.
// These are used for zkgroup operations like auth credential verification.
type ServerPublicParams struct {
	ptr C.SignalMutPointerServerPublicParams
}

// SignalServerPublicParams is the base64-encoded production server public params.
// From Signal-Android BuildConfig.ZKGROUP_SERVER_PUBLIC_PARAMS
const SignalServerPublicParams = "AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQP5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6wkU5J+DPQalQguMg12Jzug3q4TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCWJmP4zqUFeTTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh/f2DPVOOmR0RW6bgRvc7DSF20V/omg+YBw=="

// NewServerPublicParams deserializes server public params from bytes.
func NewServerPublicParams(data []byte) (*ServerPublicParams, error) {
	var ptr C.SignalMutPointerServerPublicParams
	if err := wrapError(C.signal_server_public_params_deserialize(&ptr, borrowedBuffer(data))); err != nil {
		return nil, fmt.Errorf("deserialize server public params: %w", err)
	}
	return &ServerPublicParams{ptr: ptr}, nil
}

// NewServerPublicParamsFromBase64 deserializes server public params from base64.
func NewServerPublicParamsFromBase64(b64 string) (*ServerPublicParams, error) {
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("decode base64: %w", err)
	}
	return NewServerPublicParams(data)
}

// GetSignalServerPublicParams returns the production Signal server public params.
func GetSignalServerPublicParams() (*ServerPublicParams, error) {
	return NewServerPublicParamsFromBase64(SignalServerPublicParams)
}

// Close releases the server public params resources.
func (p *ServerPublicParams) Close() {
	if p.ptr.raw != nil {
		C.signal_server_public_params_destroy(p.ptr)
		p.ptr.raw = nil
	}
}

// ReceiveAuthCredentialWithPni verifies and extracts an auth credential from the server response.
// aci and pni are 16-byte UUIDs.
// redemptionTime is the expected redemption time in seconds since epoch.
func (p *ServerPublicParams) ReceiveAuthCredentialWithPni(aci, pni [16]byte, redemptionTime uint64, response []byte) ([]byte, error) {
	var out C.SignalOwnedBuffer

	// Create service ID bytes (ACI type prefix 0x00 + 16 bytes UUID)
	var aciBytes [17]byte
	aciBytes[0] = 0x00 // ACI type
	copy(aciBytes[1:], aci[:])

	var pniBytes [17]byte
	pniBytes[0] = 0x01 // PNI type
	copy(pniBytes[1:], pni[:])

	aciPtr := (*C.SignalServiceIdFixedWidthBinaryBytes)(unsafe.Pointer(&aciBytes[0]))
	pniPtr := (*C.SignalServiceIdFixedWidthBinaryBytes)(unsafe.Pointer(&pniBytes[0]))

	if err := wrapError(C.signal_server_public_params_receive_auth_credential_with_pni_as_service_id(
		&out,
		C.SignalConstPointerServerPublicParams(p.ptr),
		aciPtr,
		pniPtr,
		C.uint64_t(redemptionTime),
		borrowedBuffer(response),
	)); err != nil {
		return nil, fmt.Errorf("receive auth credential: %w", err)
	}

	return freeOwnedBuffer(out), nil
}

// CreateAuthCredentialPresentation creates an auth credential presentation for group API requests.
// The returned presentation is used as the password in HTTP Basic Auth for Groups V2 API.
func (p *ServerPublicParams) CreateAuthCredentialPresentation(groupSecretParams GroupSecretParams, authCredential []byte) ([]byte, error) {
	var out C.SignalOwnedBuffer

	// Generate randomness
	var randomness [32]byte
	if _, err := rand.Read(randomness[:]); err != nil {
		return nil, fmt.Errorf("generate randomness: %w", err)
	}
	randomnessPtr := (*[32]C.uint8_t)(unsafe.Pointer(&randomness[0]))

	paramsPtr := (*[289]C.uchar)(unsafe.Pointer(&groupSecretParams[0]))

	if err := wrapError(C.signal_server_public_params_create_auth_credential_with_pni_presentation_deterministic(
		&out,
		C.SignalConstPointerServerPublicParams(p.ptr),
		randomnessPtr,
		paramsPtr,
		borrowedBuffer(authCredential),
	)); err != nil {
		return nil, fmt.Errorf("create auth credential presentation: %w", err)
	}

	return freeOwnedBuffer(out), nil
}
