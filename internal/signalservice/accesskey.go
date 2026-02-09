package signalservice

import (
	"errors"
	"fmt"

	"github.com/gwillem/signal-go/internal/signalcrypto"
)

// unrestrictedKey is 16 zero bytes, used when no profile key is available.
// Matches Signal-Android's SealedSenderAccessUtil.UNRESTRICTED_KEY.
var unrestrictedKey [16]byte

// accessKeyRejectedError is returned when a sealed sender 401 indicates the
// access key was rejected by the server.
type accessKeyRejectedError struct{}

func (e *accessKeyRejectedError) Error() string {
	return "sealed sender: access key rejected (401)"
}

// isAccessKeyRejected returns true if err is an accessKeyRejectedError.
func isAccessKeyRejected(err error) bool {
	var target *accessKeyRejectedError
	return errors.As(err, &target)
}

// resolveAccessKey returns the unidentified access key for a recipient.
// If a profile key is available, derives the key and returns (key, true).
// Otherwise returns (unrestricted key, false).
func resolveAccessKey(st contactLookup, recipient string) ([]byte, bool) {
	contact, err := st.GetContactByACI(recipient)
	if err != nil || contact == nil || len(contact.ProfileKey) == 0 {
		return unrestrictedKey[:], false
	}
	key, err := signalcrypto.DeriveAccessKey(contact.ProfileKey)
	if err != nil {
		return unrestrictedKey[:], false
	}
	return key, true
}

// deriveAccessKeyForRecipient looks up a recipient's profile key and derives
// their unidentified access key. Returns an error if no profile key is available.
func deriveAccessKeyForRecipient(st contactLookup, recipient string) ([]byte, error) {
	contact, err := st.GetContactByACI(recipient)
	if err != nil {
		return nil, fmt.Errorf("get contact: %w", err)
	}
	if contact == nil || len(contact.ProfileKey) == 0 {
		return nil, fmt.Errorf("no profile key for %s (run sync-contacts or receive a message from them first)", recipient)
	}
	return signalcrypto.DeriveAccessKey(contact.ProfileKey)
}
