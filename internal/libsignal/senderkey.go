package libsignal

/*
#include "libsignal-ffi.h"
*/
import "C"

// SenderKeyRecord wraps a libsignal sender key record for group messaging.
type SenderKeyRecord struct {
	ptr *C.SignalSenderKeyRecord
}

// Destroy frees the underlying C resource.
func (r *SenderKeyRecord) Destroy() {
	if r.ptr != nil {
		C.signal_sender_key_record_destroy(C.SignalMutPointerSenderKeyRecord{raw: r.ptr})
		r.ptr = nil
	}
}

// Serialize returns the serialized form of the sender key record.
func (r *SenderKeyRecord) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	if err := wrapError(C.signal_sender_key_record_serialize(&buf, C.SignalConstPointerSenderKeyRecord{raw: r.ptr})); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// DeserializeSenderKeyRecord deserializes a sender key record from bytes.
func DeserializeSenderKeyRecord(data []byte) (*SenderKeyRecord, error) {
	var out C.SignalMutPointerSenderKeyRecord
	if err := wrapError(C.signal_sender_key_record_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &SenderKeyRecord{ptr: out.raw}, nil
}

// SenderKeyDistributionMessage wraps a libsignal sender key distribution message.
// These messages are sent to distribute sender keys to group members.
type SenderKeyDistributionMessage struct {
	ptr *C.SignalSenderKeyDistributionMessage
}

// Destroy frees the underlying C resource.
func (m *SenderKeyDistributionMessage) Destroy() {
	if m.ptr != nil {
		C.signal_sender_key_distribution_message_destroy(C.SignalMutPointerSenderKeyDistributionMessage{raw: m.ptr})
		m.ptr = nil
	}
}

// Serialize returns the serialized form of the distribution message.
func (m *SenderKeyDistributionMessage) Serialize() ([]byte, error) {
	var buf C.SignalOwnedBuffer
	if err := wrapError(C.signal_sender_key_distribution_message_serialize(&buf, C.SignalConstPointerSenderKeyDistributionMessage{raw: m.ptr})); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(buf), nil
}

// DeserializeSenderKeyDistributionMessage deserializes a sender key distribution message.
func DeserializeSenderKeyDistributionMessage(data []byte) (*SenderKeyDistributionMessage, error) {
	var out C.SignalMutPointerSenderKeyDistributionMessage
	if err := wrapError(C.signal_sender_key_distribution_message_deserialize(&out, borrowedBuffer(data))); err != nil {
		return nil, err
	}
	return &SenderKeyDistributionMessage{ptr: out.raw}, nil
}

// ProcessSenderKeyDistributionMessage processes a received sender key distribution message,
// storing the sender key for later use in decrypting group messages.
func ProcessSenderKeyDistributionMessage(
	sender *Address,
	message *SenderKeyDistributionMessage,
	store SenderKeyStore,
) error {
	cSender := C.SignalConstPointerProtocolAddress{raw: sender.ptr}
	cMessage := C.SignalConstPointerSenderKeyDistributionMessage{raw: message.ptr}

	cStore, cleanup := wrapSenderKeyStore(store)
	defer cleanup()
	cStorePtr := C.SignalConstPointerFfiSenderKeyStoreStruct{raw: cStore}

	return wrapError(C.signal_process_sender_key_distribution_message(cSender, cMessage, cStorePtr))
}

// GroupDecryptMessage decrypts a sender key encrypted message (type 7).
func GroupDecryptMessage(
	ciphertext []byte,
	sender *Address,
	store SenderKeyStore,
) ([]byte, error) {
	var out C.SignalOwnedBuffer

	cSender := C.SignalConstPointerProtocolAddress{raw: sender.ptr}
	cStore, cleanup := wrapSenderKeyStore(store)
	defer cleanup()
	cStorePtr := C.SignalConstPointerFfiSenderKeyStoreStruct{raw: cStore}

	if err := wrapError(C.signal_group_decrypt_message(&out, cSender, borrowedBuffer(ciphertext), cStorePtr)); err != nil {
		return nil, err
	}
	return freeOwnedBuffer(out), nil
}

// CreateSenderKeyDistributionMessage creates a new sender key distribution message.
// This message should be sent to group members so they can decrypt messages from this sender.
// The distributionID is a UUID that identifies this sender key distribution (typically derived from the group).
func CreateSenderKeyDistributionMessage(
	sender *Address,
	distributionID [16]byte,
	store SenderKeyStore,
) (*SenderKeyDistributionMessage, error) {
	var out C.SignalMutPointerSenderKeyDistributionMessage

	cSender := C.SignalConstPointerProtocolAddress{raw: sender.ptr}

	// Convert distribution ID to SignalUuid
	var cDistID C.SignalUuid
	for i := range 16 {
		cDistID.bytes[i] = C.uint8_t(distributionID[i])
	}

	cStore, cleanup := wrapSenderKeyStore(store)
	defer cleanup()
	cStorePtr := C.SignalConstPointerFfiSenderKeyStoreStruct{raw: cStore}

	if err := wrapError(C.signal_sender_key_distribution_message_create(&out, cSender, cDistID, cStorePtr)); err != nil {
		return nil, err
	}
	return &SenderKeyDistributionMessage{ptr: out.raw}, nil
}

// GroupEncryptMessage encrypts a message using sender key for group messaging.
// Returns a CiphertextMessage of type SenderKey (7).
func GroupEncryptMessage(
	plaintext []byte,
	sender *Address,
	distributionID [16]byte,
	store SenderKeyStore,
) (*CiphertextMessage, error) {
	var out C.SignalMutPointerCiphertextMessage

	cSender := C.SignalConstPointerProtocolAddress{raw: sender.ptr}

	// Convert distribution ID to SignalUuid
	var cDistID C.SignalUuid
	for i := range 16 {
		cDistID.bytes[i] = C.uint8_t(distributionID[i])
	}

	cStore, cleanup := wrapSenderKeyStore(store)
	defer cleanup()
	cStorePtr := C.SignalConstPointerFfiSenderKeyStoreStruct{raw: cStore}

	if err := wrapError(C.signal_group_encrypt_message(&out, cSender, cDistID, borrowedBuffer(plaintext), cStorePtr)); err != nil {
		return nil, err
	}
	return &CiphertextMessage{ptr: out.raw}, nil
}
