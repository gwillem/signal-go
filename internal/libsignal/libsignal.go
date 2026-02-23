package libsignal

// #cgo CFLAGS: -I${SRCDIR}/lib
// #cgo darwin,arm64 LDFLAGS: ${SRCDIR}/lib/darwin-arm64/libsignal_ffi.a -framework Security -framework Foundation -lm -lc++
// #cgo linux,amd64 LDFLAGS: ${SRCDIR}/lib/linux-amd64/libsignal_ffi.a -ldl -lm -lpthread -lstdc++
// #include "libsignal-ffi.h"
// #include <stdlib.h>
import "C"
