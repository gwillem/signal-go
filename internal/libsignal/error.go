package libsignal

/*
#include "libsignal-ffi.h"
#include <stdlib.h>
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Error represents an error returned by the libsignal FFI.
type Error struct {
	Code    uint32
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("libsignal error %d: %s", e.Code, e.Message)
}

// wrapError converts a SignalFfiError pointer into a Go error.
// Returns nil if err is nil (success).
func wrapError(err *C.SignalFfiError) error {
	if err == nil {
		return nil
	}
	defer C.signal_error_free(err)

	code := C.signal_error_get_type(err)

	var msgPtr *C.char
	C.signal_error_get_message(err, &msgPtr)
	var msg string
	if msgPtr != nil {
		msg = C.GoString(msgPtr)
		C.signal_free_string(msgPtr)
	}

	return &Error{Code: uint32(code), Message: msg}
}

// freeOwnedBuffer copies data from a SignalOwnedBuffer into a Go byte slice
// and frees the C-allocated memory.
func freeOwnedBuffer(buf C.SignalOwnedBuffer) []byte {
	if buf.base == nil || buf.length == 0 {
		return nil
	}
	data := C.GoBytes(unsafe.Pointer(buf.base), C.int(buf.length))
	C.signal_free_buffer(buf.base, buf.length)
	return data
}
