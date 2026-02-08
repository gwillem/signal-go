package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"
import "unsafe"

const (
	// EnvironmentProduction is Signal's production environment.
	EnvironmentProduction = 1
	// BuildVariantProduction is the production build variant.
	BuildVariantProduction = 0
)

// TokioAsyncContext wraps a Rust tokio runtime for async FFI operations.
type TokioAsyncContext struct {
	ptr *C.SignalTokioAsyncContext
}

// NewTokioAsyncContext creates a new tokio async runtime.
func NewTokioAsyncContext() (*TokioAsyncContext, error) {
	var out C.SignalMutPointerTokioAsyncContext
	if err := wrapError(C.signal_tokio_async_context_new(&out)); err != nil {
		return nil, err
	}
	return &TokioAsyncContext{ptr: out.raw}, nil
}

// Destroy frees the underlying tokio runtime.
func (t *TokioAsyncContext) Destroy() {
	if t.ptr != nil {
		C.signal_tokio_async_context_destroy(C.SignalMutPointerTokioAsyncContext{raw: t.ptr})
		t.ptr = nil
	}
}

// ConnectionManager wraps a libsignal connection manager for network operations.
type ConnectionManager struct {
	ptr *C.SignalConnectionManager
}

// NewConnectionManager creates a new connection manager for the given environment.
// The userAgent string identifies this client to the server.
func NewConnectionManager(env uint8, userAgent string) (*ConnectionManager, error) {
	// Create an empty remote config map (required by the API).
	var configMap C.SignalMutPointerBridgedStringMap
	if err := wrapError(C.signal_bridged_string_map_new(&configMap, 0)); err != nil {
		return nil, err
	}
	// connection_manager_new takes ownership of configMap — don't destroy it.

	cAgent := C.CString(userAgent)
	defer C.free(unsafe.Pointer(cAgent))

	var out C.SignalMutPointerConnectionManager
	if err := wrapError(C.signal_connection_manager_new(
		&out,
		C.uint8_t(env),
		cAgent,
		configMap,
		C.uint8_t(BuildVariantProduction),
	)); err != nil {
		// On failure, Rust did not take ownership — free the map ourselves.
		C.signal_bridged_string_map_destroy(configMap)
		return nil, err
	}
	return &ConnectionManager{ptr: out.raw}, nil
}

// Destroy frees the underlying connection manager.
func (cm *ConnectionManager) Destroy() {
	if cm.ptr != nil {
		C.signal_connection_manager_destroy(C.SignalMutPointerConnectionManager{raw: cm.ptr})
		cm.ptr = nil
	}
}
