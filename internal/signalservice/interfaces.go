package signalservice

import (
	"context"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/store"
)

// cryptoStore combines all 6 libsignal store interfaces.
// Passed opaquely to libsignal FFI calls.
type cryptoStore interface {
	libsignal.SessionStore
	libsignal.IdentityKeyStore
	libsignal.PreKeyStore
	libsignal.SignedPreKeyStore
	libsignal.KyberPreKeyStore
	libsignal.SenderKeyStore
}

// wsConn is the WebSocket interface for receiving messages.
type wsConn interface {
	ReadMessage(ctx context.Context) (*proto.WebSocketMessage, error)
	SendResponse(ctx context.Context, id uint64, status uint32, message string) error
	Close() error
}

// receiverDataStore is the data store interface needed by Receiver.
type receiverDataStore interface {
	GetContactByACI(string) (*store.Contact, error)
	SaveContact(*store.Contact) error
	SaveContacts([]*store.Contact) error
	LoadAccount() (*store.Account, error)
	GetGroup(string) (*store.Group, error)
	SaveGroup(*store.Group) error
	PNI() libsignal.IdentityKeyStore
}

// senderDataStore is the data store interface needed by Sender.
type senderDataStore interface {
	LoadAccount() (*store.Account, error)
	ArchiveSession(string, uint32) error
	GetDevices(string) ([]int, error)
	SetDevices(string, []int) error
	GetContactByACI(string) (*store.Contact, error)
	GetPNIIdentityKeyPair() (*libsignal.PrivateKey, error)
}

// senderCryptoStore combines session and identity stores needed by Sender.
type senderCryptoStore interface {
	libsignal.SessionStore
	libsignal.IdentityKeyStore
}

// contactLookup provides contact lookup by ACI.
type contactLookup interface {
	GetContactByACI(string) (*store.Contact, error)
}
