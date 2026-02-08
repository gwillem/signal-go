package libsignal

/*
#include "libsignal-ffi.h"

extern void bridge_cdsi_lookup_new_complete(SignalFfiError *err, const SignalMutPointerCdsiLookup *result, const void *ctx);
extern void bridge_cdsi_response_complete(SignalFfiError *err, const SignalFfiCdsiLookupResponse *result, const void *ctx);

// bridge_cdsi_lookup_new constructs the promise and calls signal_cdsi_lookup_new entirely on the C side.
// ctx is passed as uintptr_t (not a pointer) to avoid CGO Go-pointer checks.
static inline SignalFfiError *bridge_cdsi_lookup_new(
	SignalConstPointerTokioAsyncContext async_runtime,
	SignalConstPointerConnectionManager connection_manager,
	const char *username,
	const char *password,
	SignalConstPointerLookupRequest request,
	uintptr_t ctx
) {
	SignalCPromiseMutPointerCdsiLookup promise = {0};
	promise.complete = bridge_cdsi_lookup_new_complete;
	promise.context = (const void *)ctx;
	return signal_cdsi_lookup_new(&promise, async_runtime, connection_manager, username, password, request);
}

// bridge_cdsi_lookup_complete constructs the promise and calls signal_cdsi_lookup_complete entirely on the C side.
static inline SignalFfiError *bridge_cdsi_lookup_complete(
	SignalConstPointerTokioAsyncContext async_runtime,
	SignalConstPointerCdsiLookup lookup,
	uintptr_t ctx
) {
	SignalCPromiseFfiCdsiLookupResponse promise = {0};
	promise.complete = bridge_cdsi_response_complete;
	promise.context = (const void *)ctx;
	return signal_cdsi_lookup_complete(&promise, async_runtime, lookup);
}
*/
import "C"
import (
	"fmt"
	"time"
	"unsafe"
)

// cdsiTimeout bounds how long we wait for Rust's async callback. CDSI lookups
// involve a TLS handshake to an SGX enclave plus the actual query, so they can
// take several seconds under normal conditions. 30 s gives plenty of headroom
// while still failing fast if the tokio runtime is wedged or the network is
// completely unreachable.
const cdsiTimeout = 30 * time.Second

// LookupRequest wraps a libsignal CDSI lookup request.
type LookupRequest struct {
	ptr *C.SignalLookupRequest
}

// NewLookupRequest creates a new empty CDSI lookup request.
func NewLookupRequest() (*LookupRequest, error) {
	var out C.SignalMutPointerLookupRequest
	if err := wrapError(C.signal_lookup_request_new(&out)); err != nil {
		return nil, err
	}
	return &LookupRequest{ptr: out.raw}, nil
}

// AddE164 adds an E.164 phone number to the lookup request.
func (r *LookupRequest) AddE164(e164 string) error {
	cE164 := C.CString(e164)
	defer C.free(unsafe.Pointer(cE164))
	return wrapError(C.signal_lookup_request_add_e164(
		C.SignalConstPointerLookupRequest{raw: r.ptr},
		cE164,
	))
}

// SetToken sets a continuation token from a previous lookup (for delta lookups).
func (r *LookupRequest) SetToken(token []byte) error {
	return wrapError(C.signal_lookup_request_set_token(
		C.SignalConstPointerLookupRequest{raw: r.ptr},
		borrowedBuffer(token),
	))
}

// Destroy frees the underlying C resource.
func (r *LookupRequest) Destroy() {
	if r.ptr != nil {
		C.signal_lookup_request_destroy(C.SignalMutPointerLookupRequest{raw: r.ptr})
		r.ptr = nil
	}
}

// CDSIResult holds the result of a CDSI lookup for a single phone number.
type CDSIResult struct {
	E164 uint64
	ACI  [16]byte
	PNI  [16]byte
}

// cdsiLookupResult is the internal channel message for the async lookup.
type cdsiLookupResult struct {
	ptr *C.SignalCdsiLookup
	err error
}

// cdsiResponseResult is the internal channel message for the async response.
type cdsiResponseResult struct {
	entries []CDSIResult
	err     error
}

//export goCdsiLookupNewComplete
func goCdsiLookupNewComplete(errp *C.SignalFfiError, result *C.SignalCdsiLookup, ctx unsafe.Pointer) {
	ch := restorePointer(ctx).(chan cdsiLookupResult)
	deletePointer(ctx) // callback owns cleanup — safe even if Go side timed out
	var r cdsiLookupResult
	if errp != nil {
		r.err = wrapError(errp)
	} else {
		r.ptr = result
	}
	ch <- r
}

//export goCdsiResponseComplete
func goCdsiResponseComplete(errp *C.SignalFfiError, result *C.SignalFfiCdsiLookupResponse, ctx unsafe.Pointer) {
	ch := restorePointer(ctx).(chan cdsiResponseResult)
	deletePointer(ctx) // callback owns cleanup — safe even if Go side timed out
	var r cdsiResponseResult
	if errp != nil {
		r.err = wrapError(errp)
	} else if result != nil {
		// Copy entries before returning — Rust owns this memory.
		count := int(result.entries.length)
		if count > 0 && result.entries.base != nil {
			entries := unsafe.Slice(result.entries.base, count)
			r.entries = make([]CDSIResult, count)
			for i := range count {
				r.entries[i].E164 = uint64(entries[i].e164)
				for j := range 16 {
					r.entries[i].ACI[j] = byte(entries[i].rawAciUuid[j])
					r.entries[i].PNI[j] = byte(entries[i].rawPniUuid[j])
				}
			}
		}
	}
	ch <- r
}

// CDSILookup performs a two-phase CDSI lookup:
//  1. signal_cdsi_lookup_new — initiates the lookup, returns a CdsiLookup handle
//  2. signal_cdsi_lookup_complete — completes the lookup, returns response entries
//
// This is a blocking call that bridges Rust's async FFI to Go via channels.
func CDSILookup(
	asyncCtx *TokioAsyncContext,
	connMgr *ConnectionManager,
	username, password string,
	request *LookupRequest,
) ([]CDSIResult, error) {
	// Phase 1: initiate lookup.
	lookupHandle, err := cdsiLookupNew(asyncCtx, connMgr, username, password, request)
	if err != nil {
		return nil, fmt.Errorf("cdsi: lookup new: %w", err)
	}
	defer C.signal_cdsi_lookup_destroy(C.SignalMutPointerCdsiLookup{raw: lookupHandle})

	// Phase 2: complete lookup and get response.
	results, err := cdsiLookupComplete(asyncCtx, lookupHandle)
	if err != nil {
		return nil, fmt.Errorf("cdsi: lookup complete: %w", err)
	}
	return results, nil
}

// cdsiLookupNew initiates the async CDSI lookup and blocks until the handle is ready.
func cdsiLookupNew(
	asyncCtx *TokioAsyncContext,
	connMgr *ConnectionManager,
	username, password string,
	request *LookupRequest,
) (*C.SignalCdsiLookup, error) {
	ch := make(chan cdsiLookupResult, 1)
	ctx := savePointer(ch)

	cUser := C.CString(username)
	defer C.free(unsafe.Pointer(cUser))
	cPass := C.CString(password)
	defer C.free(unsafe.Pointer(cPass))

	err := wrapError(C.bridge_cdsi_lookup_new(
		C.SignalConstPointerTokioAsyncContext{raw: asyncCtx.ptr},
		C.SignalConstPointerConnectionManager{raw: connMgr.ptr},
		cUser,
		cPass,
		C.SignalConstPointerLookupRequest{raw: request.ptr},
		C.uintptr_t(uintptr(ctx)),
	))
	if err != nil {
		// Synchronous error — callback won't fire, clean up immediately.
		deletePointer(ctx)
		return nil, err
	}

	select {
	case result := <-ch:
		// deletePointer already called by the callback.
		if result.err != nil {
			return nil, result.err
		}
		return result.ptr, nil
	case <-time.After(cdsiTimeout):
		// Handle will be cleaned up when the late callback eventually fires.
		return nil, fmt.Errorf("cdsi: timeout waiting for lookup handle")
	}
}

// cdsiLookupComplete completes the CDSI lookup and returns parsed results.
func cdsiLookupComplete(asyncCtx *TokioAsyncContext, lookup *C.SignalCdsiLookup) ([]CDSIResult, error) {
	ch := make(chan cdsiResponseResult, 1)
	ctx := savePointer(ch)

	err := wrapError(C.bridge_cdsi_lookup_complete(
		C.SignalConstPointerTokioAsyncContext{raw: asyncCtx.ptr},
		C.SignalConstPointerCdsiLookup{raw: lookup},
		C.uintptr_t(uintptr(ctx)),
	))
	if err != nil {
		deletePointer(ctx)
		return nil, err
	}

	select {
	case result := <-ch:
		// deletePointer already called by the callback.
		return result.entries, result.err
	case <-time.After(cdsiTimeout):
		// Handle will be cleaned up when the late callback eventually fires.
		return nil, fmt.Errorf("cdsi: timeout waiting for lookup response")
	}
}
