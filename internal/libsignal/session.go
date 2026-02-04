package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// SessionRecord wraps a libsignal session record.
type SessionRecord struct {
	ptr *C.SignalSessionRecord
}

// DeserializeSessionRecord reconstructs a session record from serialized form.
func DeserializeSessionRecord(data []byte) (*SessionRecord, error) {
	var out C.SignalMutPointerSessionRecord
	if err := wrapError(C.signal_session_record_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &SessionRecord{ptr: out.raw}, nil
}

// Serialize returns the serialized form of this session record.
func (r *SessionRecord) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	cPtr := C.SignalConstPointerSessionRecord{raw: r.ptr}
	if err := wrapError(C.signal_session_record_serialize(&buf, cPtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// ArchiveCurrentState archives the current session state.
func (r *SessionRecord) ArchiveCurrentState() error {
	mPtr := C.SignalMutPointerSessionRecord{raw: r.ptr}
	return wrapError(C.signal_session_record_archive_current_state(mPtr))
}

// RemoteRegistrationID returns the registration ID of the remote party.
// This is the ID that was provided during session establishment.
func (r *SessionRecord) RemoteRegistrationID() (uint32, error) {
	var out C.uint32_t
	cPtr := C.SignalConstPointerSessionRecord{raw: r.ptr}
	if err := wrapError(C.signal_session_record_get_remote_registration_id(&out, cPtr)); err != nil {
		return 0, err
	}
	return uint32(out), nil
}

// Destroy frees the underlying C resource.
func (r *SessionRecord) Destroy() {
	if r.ptr != nil {
		C.signal_session_record_destroy(C.SignalMutPointerSessionRecord{raw: r.ptr})
		r.ptr = nil
	}
}
