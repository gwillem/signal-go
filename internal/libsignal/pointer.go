package libsignal

import (
	"runtime"
	"runtime/cgo"
	"unsafe"
)

// handleWrapper holds a cgo.Handle and its Pinner to keep the memory pinned
// while C code holds a reference to it.
type handleWrapper struct {
	h      cgo.Handle
	pinner runtime.Pinner
}

// savePointer saves a Go value and returns a C-safe pointer.
// The handle is heap-allocated and pinned so C can safely store it.
// Per cgo.Handle docs, we pass the address of the handle, not the handle value.
func savePointer(v any) unsafe.Pointer {
	w := &handleWrapper{h: cgo.NewHandle(v)}
	w.pinner.Pin(w)
	return unsafe.Pointer(w)
}

// restorePointer retrieves a Go value by dereferencing the handle pointer.
func restorePointer(p unsafe.Pointer) any {
	w := (*handleWrapper)(p)
	return w.h.Value()
}

// deletePointer unpins, deletes the handle, and frees resources.
func deletePointer(p unsafe.Pointer) {
	w := (*handleWrapper)(p)
	w.pinner.Unpin()
	w.h.Delete()
}
