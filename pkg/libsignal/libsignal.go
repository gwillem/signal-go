package libsignal

// #cgo CFLAGS: -I${SRCDIR}
// #cgo linux LDFLAGS: ${SRCDIR}/../../../libsignal/target/release/libsignal_ffi.a -ldl -lm -lpthread
// #cgo darwin LDFLAGS: ${SRCDIR}/../../../libsignal/target/release/libsignal_ffi.a -framework Security -framework Foundation -lm
// #include "libsignal-ffi.h"
// #include <stdlib.h>
import "C"
