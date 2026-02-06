package libsignal

// #cgo CFLAGS: -I${SRCDIR}/lib
// #cgo darwin,arm64 LDFLAGS: ${SRCDIR}/lib/darwin-arm64/libsignal_ffi.a -framework Security -framework Foundation -lm
// #cgo linux,amd64 LDFLAGS: ${SRCDIR}/lib/linux-amd64/libsignal_ffi.a -ldl -lm -lpthread
// #include "libsignal-ffi.h"
// #include <stdlib.h>
import "C"
