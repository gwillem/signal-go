package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// Store wraps a SQLite database and implements all libsignal store interfaces
// plus account credential management.
type Store struct {
	db              *sql.DB
	identityKeyPair *libsignal.PrivateKey // cached from account table
	registrationID  uint32                // cached from account table
}

// Compile-time interface checks.
var (
	_ libsignal.SessionStore      = (*Store)(nil)
	_ libsignal.IdentityKeyStore  = (*Store)(nil)
	_ libsignal.PreKeyStore       = (*Store)(nil)
	_ libsignal.SignedPreKeyStore  = (*Store)(nil)
	_ libsignal.KyberPreKeyStore  = (*Store)(nil)
)

const schema = `
CREATE TABLE IF NOT EXISTS account (
	key TEXT PRIMARY KEY,
	value BLOB
);
CREATE TABLE IF NOT EXISTS session (
	address TEXT NOT NULL,
	device_id INTEGER NOT NULL,
	record BLOB NOT NULL,
	PRIMARY KEY (address, device_id)
);
CREATE TABLE IF NOT EXISTS identity (
	address TEXT PRIMARY KEY,
	public_key BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS pre_key (
	id INTEGER PRIMARY KEY,
	record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS signed_pre_key (
	id INTEGER PRIMARY KEY,
	record BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS kyber_pre_key (
	id INTEGER PRIMARY KEY,
	record BLOB NOT NULL,
	used INTEGER NOT NULL DEFAULT 0
);
`

// DefaultDataDir returns the default data directory for signal-go databases.
// Uses $XDG_DATA_HOME/signal-go, falling back to ~/.local/share/signal-go.
func DefaultDataDir() string {
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		home, _ := os.UserHomeDir()
		dataHome = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(dataHome, "signal-go")
}

// Open opens or creates a SQLite store at the given path.
// If dbPath is empty, it defaults to $XDG_DATA_HOME/signal-go/default.db.
func Open(dbPath string) (*Store, error) {
	if dbPath == "" {
		dbPath = filepath.Join(DefaultDataDir(), "default.db")
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("store: create dir: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("store: open db: %w", err)
	}

	// Enable WAL mode for better concurrent read performance.
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: set WAL mode: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: create schema: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	if s.identityKeyPair != nil {
		s.identityKeyPair.Destroy()
		s.identityKeyPair = nil
	}
	return s.db.Close()
}

// SetIdentity sets the local identity key pair and registration ID.
// These are cached in memory and used by IdentityKeyStore methods.
func (s *Store) SetIdentity(keyPair *libsignal.PrivateKey, registrationID uint32) {
	s.identityKeyPair = keyPair
	s.registrationID = registrationID
}
