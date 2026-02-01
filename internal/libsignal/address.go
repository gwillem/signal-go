package libsignal

/*
#include "libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"
import "unsafe"

// Address wraps a libsignal protocol address (name + device ID).
type Address struct {
	ptr *C.SignalProtocolAddress
}

// NewAddress creates a new protocol address.
func NewAddress(name string, deviceID uint32) (*Address, error) {
	var out C.SignalMutPointerProtocolAddress
	cName := C.CString(name)
	defer C.free(unsafe.Pointer(cName))
	if err := wrapError(C.signal_address_new(&out, cName, C.uint32_t(deviceID))); err != nil {
		return nil, err
	}
	return &Address{ptr: out.raw}, nil
}

// Name returns the address name (e.g. phone number or UUID).
func (a *Address) Name() (string, error) {
	var out *C.char
	cPtr := C.SignalConstPointerProtocolAddress{raw: a.ptr}
	if err := wrapError(C.signal_address_get_name(&out, cPtr)); err != nil {
		return "", err
	}
	name := C.GoString(out)
	C.signal_free_string(out)
	return name, nil
}

// DeviceID returns the device ID component of the address.
func (a *Address) DeviceID() (uint32, error) {
	var out C.uint32_t
	cPtr := C.SignalConstPointerProtocolAddress{raw: a.ptr}
	if err := wrapError(C.signal_address_get_device_id(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint32(out), nil
}

// Destroy frees the underlying C resource.
func (a *Address) Destroy() {
	if a.ptr != nil {
		C.signal_address_destroy(C.SignalMutPointerProtocolAddress{raw: a.ptr})
		a.ptr = nil
	}
}
