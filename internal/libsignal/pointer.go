package libsignal

import (
	"sync"
	"sync/atomic"
	"unsafe"
)

// handleMap stores Go values keyed by an incrementing handle, allowing safe
// passage of Go pointers through C void* without violating cgo pointer rules.
var (
	handleMu  sync.RWMutex
	handleSeq atomic.Uintptr
	handles   = map[uintptr]any{}
)

// savePointer saves a Go value and returns a C-safe handle as unsafe.Pointer.
func savePointer(v any) unsafe.Pointer {
	h := handleSeq.Add(1)
	handleMu.Lock()
	handles[h] = v
	handleMu.Unlock()
	return unsafe.Pointer(h)
}

// restorePointer retrieves a Go value by its handle.
func restorePointer(p unsafe.Pointer) any {
	h := uintptr(p)
	handleMu.RLock()
	v := handles[h]
	handleMu.RUnlock()
	return v
}

// deletePointer removes a handle, freeing the reference.
func deletePointer(p unsafe.Pointer) {
	h := uintptr(p)
	handleMu.Lock()
	delete(handles, h)
	handleMu.Unlock()
}
