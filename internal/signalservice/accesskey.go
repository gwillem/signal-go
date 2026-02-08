package signalservice

import (
	"fmt"

	"github.com/gwillem/signal-go/internal/signalcrypto"
	"github.com/gwillem/signal-go/internal/store"
)

// deriveAccessKeyForRecipient looks up a recipient's profile key and derives
// their unidentified access key. Returns an error if no profile key is available.
func deriveAccessKeyForRecipient(st *store.Store, recipient string) ([]byte, error) {
	contact, err := st.GetContactByACI(recipient)
	if err != nil {
		return nil, fmt.Errorf("get contact: %w", err)
	}
	if contact == nil || len(contact.ProfileKey) == 0 {
		return nil, fmt.Errorf("no profile key for %s (run sync-contacts or receive a message from them first)", recipient)
	}
	return signalcrypto.DeriveAccessKey(contact.ProfileKey)
}
