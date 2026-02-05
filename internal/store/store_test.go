package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gwillem/signal-go/internal/libsignal"
)

func tempStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenClose(t *testing.T) {
	s := tempStore(t)
	if s.db == nil {
		t.Fatal("db should not be nil")
	}
}

func TestOpenCreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sub", "dir", "test.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	if _, err := os.Stat(filepath.Dir(path)); os.IsNotExist(err) {
		t.Fatal("directory should have been created")
	}
}

func TestAccountSaveLoad(t *testing.T) {
	s := tempStore(t)

	// Loading with no account returns nil.
	acct, err := s.LoadAccount()
	if err != nil {
		t.Fatal(err)
	}
	if acct != nil {
		t.Fatal("expected nil account")
	}

	// Save and load.
	want := &Account{
		Number:                "+15551234567",
		ACI:                   "aci-uuid",
		PNI:                   "pni-uuid",
		Password:              "secret",
		DeviceID:              2,
		RegistrationID:        12345,
		PNIRegistrationID:     67890,
		ACIIdentityKeyPrivate: []byte("aci-priv"),
		ACIIdentityKeyPublic:  []byte("aci-pub"),
		PNIIdentityKeyPrivate: []byte("pni-priv"),
		PNIIdentityKeyPublic:  []byte("pni-pub"),
		ProfileKey:            []byte("profile"),
		MasterKey:             []byte("master"),
	}

	if err := s.SaveAccount(want); err != nil {
		t.Fatal(err)
	}

	got, err := s.LoadAccount()
	if err != nil {
		t.Fatal(err)
	}

	if got.Number != want.Number {
		t.Errorf("number: got %q, want %q", got.Number, want.Number)
	}
	if got.ACI != want.ACI {
		t.Errorf("aci: got %q, want %q", got.ACI, want.ACI)
	}
	if got.DeviceID != want.DeviceID {
		t.Errorf("deviceId: got %d, want %d", got.DeviceID, want.DeviceID)
	}
	if got.Password != want.Password {
		t.Errorf("password: got %q, want %q", got.Password, want.Password)
	}

	// Overwrite.
	want.Password = "new-secret"
	if err := s.SaveAccount(want); err != nil {
		t.Fatal(err)
	}
	got, err = s.LoadAccount()
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "new-secret" {
		t.Errorf("password after overwrite: got %q", got.Password)
	}
}

func TestSessionStore(t *testing.T) {
	s := tempStore(t)

	// Generate a real session via protocol handshake.
	alicePriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer alicePriv.Destroy()

	bobPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPriv.Destroy()

	bobPub, err := bobPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPub.Destroy()

	addr, err := libsignal.NewAddress("bob-uuid", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer addr.Destroy()

	// Load non-existent session returns nil.
	rec, err := s.LoadSession(addr)
	if err != nil {
		t.Fatal(err)
	}
	if rec != nil {
		t.Fatal("expected nil session")
	}

	// Create a session through the full protocol (need pre-key bundle).
	// For simplicity, just create a minimal session record via the memory store
	// and then store/load through SQLite.
	memSession := libsignal.NewMemorySessionStore()
	memIdentity := libsignal.NewMemoryIdentityKeyStore(alicePriv, 1)

	spk, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spk.Destroy()

	spkPub, err := spk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPub.Destroy()

	spkPubBytes, err := spkPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	spkSig, err := bobPriv.Sign(spkPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	kyberKP, err := libsignal.GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberKP.Destroy()

	kyberPub, err := kyberKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	kyberSig, err := bobPriv.Sign(kyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	preKeyPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyPriv.Destroy()

	preKeyPub, err := preKeyPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyPub.Destroy()

	bundle, err := libsignal.NewPreKeyBundle(
		1, 1,
		1, preKeyPub,
		1, spkPub, spkSig,
		bobPub,
		1, kyberPub, kyberSig,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()

	now := time.Now()
	if err := libsignal.ProcessPreKeyBundle(bundle, addr, memSession, memIdentity, now); err != nil {
		t.Fatal(err)
	}

	// Load the session from memory store.
	sessionRec, err := memSession.LoadSession(addr)
	if err != nil {
		t.Fatal(err)
	}
	if sessionRec == nil {
		t.Fatal("expected session after ProcessPreKeyBundle")
	}

	// Store it in SQLite.
	if err := s.StoreSession(addr, sessionRec); err != nil {
		t.Fatal(err)
	}

	// Load it back.
	loaded, err := s.LoadSession(addr)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("expected loaded session")
	}
	defer loaded.Destroy()

	// Verify by serializing both.
	origData, err := sessionRec.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	loadedData, err := loaded.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(origData) != len(loadedData) {
		t.Fatalf("session data length mismatch: %d vs %d", len(origData), len(loadedData))
	}

	// Overwrite session.
	if err := s.StoreSession(addr, sessionRec); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityKeyStore(t *testing.T) {
	s := tempStore(t)

	priv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	// Don't defer Destroy — SetIdentity takes ownership.

	s.SetIdentity(priv, 42)

	// GetIdentityKeyPair.
	got, err := s.GetIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer got.Destroy()

	// GetLocalRegistrationID.
	regID, err := s.GetLocalRegistrationID()
	if err != nil {
		t.Fatal(err)
	}
	if regID != 42 {
		t.Fatalf("registrationID: got %d, want 42", regID)
	}

	// SaveIdentityKey / GetIdentityKey.
	addr, err := libsignal.NewAddress("bob-uuid", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer addr.Destroy()

	bobPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPriv.Destroy()

	bobPub, err := bobPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPub.Destroy()

	// No identity yet.
	existing, err := s.GetIdentityKey(addr)
	if err != nil {
		t.Fatal(err)
	}
	if existing != nil {
		t.Fatal("expected nil identity")
	}

	// TOFU: unknown identity is trusted.
	trusted, err := s.IsTrustedIdentity(addr, bobPub, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Fatal("expected unknown identity to be trusted (TOFU)")
	}

	// Save identity.
	if _, err := s.SaveIdentityKey(addr, bobPub); err != nil {
		t.Fatal(err)
	}

	// Load it back.
	loaded, err := s.GetIdentityKey(addr)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("expected loaded identity")
	}
	defer loaded.Destroy()

	// Same key is trusted.
	trusted, err = s.IsTrustedIdentity(addr, bobPub, 0)
	if err != nil {
		t.Fatal(err)
	}
	if !trusted {
		t.Fatal("expected same key to be trusted")
	}

	// Different key is not trusted.
	otherPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer otherPriv.Destroy()

	otherPub, err := otherPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer otherPub.Destroy()

	trusted, err = s.IsTrustedIdentity(addr, otherPub, 0)
	if err != nil {
		t.Fatal(err)
	}
	if trusted {
		t.Fatal("expected different key to be untrusted")
	}
}

func TestPreKeyStore(t *testing.T) {
	s := tempStore(t)

	// Load non-existent pre-key returns error.
	_, err := s.LoadPreKey(1)
	if err == nil {
		t.Fatal("expected error for missing pre-key")
	}

	// Generate and store a pre-key.
	priv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()

	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer pub.Destroy()

	rec, err := libsignal.NewPreKeyRecord(1, pub, priv)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.StorePreKey(1, rec); err != nil {
		t.Fatal(err)
	}

	// Load it back.
	loaded, err := s.LoadPreKey(1)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Destroy()

	// Remove it.
	if err := s.RemovePreKey(1); err != nil {
		t.Fatal(err)
	}

	// Loading again should fail.
	_, err = s.LoadPreKey(1)
	if err == nil {
		t.Fatal("expected error after remove")
	}
}

func TestSignedPreKeyStore(t *testing.T) {
	s := tempStore(t)

	// Load non-existent.
	_, err := s.LoadSignedPreKey(1)
	if err == nil {
		t.Fatal("expected error for missing signed pre-key")
	}

	// Generate identity key for signing.
	identityPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityPriv.Destroy()

	// Generate signed pre-key.
	spkPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPriv.Destroy()

	spkPub, err := spkPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPub.Destroy()

	spkPubBytes, err := spkPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := identityPriv.Sign(spkPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := libsignal.NewSignedPreKeyRecord(1, 1000, spkPub, spkPriv, sig)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.StoreSignedPreKey(1, rec); err != nil {
		t.Fatal(err)
	}

	loaded, err := s.LoadSignedPreKey(1)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Destroy()

	// Verify round-trip.
	origData, err := rec.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	loadedData, err := loaded.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	if len(origData) != len(loadedData) {
		t.Fatalf("signed pre-key data length mismatch: %d vs %d", len(origData), len(loadedData))
	}
}

func TestArchiveSession(t *testing.T) {
	s := tempStore(t)

	// Set up identity so StoreSession works through CGO callbacks.
	identityPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	s.SetIdentity(identityPriv, 1)

	bobPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPriv.Destroy()

	bobPub, err := bobPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPub.Destroy()

	addr, err := libsignal.NewAddress("bob-uuid", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer addr.Destroy()

	// Create a session via pre-key bundle processing.
	memSession := libsignal.NewMemorySessionStore()

	spk, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spk.Destroy()

	spkPub, err := spk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPub.Destroy()

	spkPubBytes, err := spkPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	spkSig, err := bobPriv.Sign(spkPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	kyberKP, err := libsignal.GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberKP.Destroy()

	kyberPub, err := kyberKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	kyberSig, err := bobPriv.Sign(kyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	preKeyPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyPriv.Destroy()

	preKeyPub, err := preKeyPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer preKeyPub.Destroy()

	memIdentity := libsignal.NewMemoryIdentityKeyStore(identityPriv, 1)

	bundle, err := libsignal.NewPreKeyBundle(1, 1, 1, preKeyPub, 1, spkPub, spkSig, bobPub, 1, kyberPub, kyberSig)
	if err != nil {
		t.Fatal(err)
	}
	defer bundle.Destroy()

	if err := libsignal.ProcessPreKeyBundle(bundle, addr, memSession, memIdentity, time.Now()); err != nil {
		t.Fatal(err)
	}

	sessionRec, err := memSession.LoadSession(addr)
	if err != nil {
		t.Fatal(err)
	}
	if sessionRec == nil {
		t.Fatal("expected session")
	}

	// Store in SQLite.
	if err := s.StoreSession(addr, sessionRec); err != nil {
		t.Fatal(err)
	}

	// Verify session exists.
	loaded, err := s.LoadSession(addr)
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil {
		t.Fatal("expected session to exist before archive")
	}
	loaded.Destroy()

	// Archive (delete) the session.
	if err := s.ArchiveSession("bob-uuid", 1); err != nil {
		t.Fatal(err)
	}

	// Verify session is gone.
	loaded, err = s.LoadSession(addr)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != nil {
		loaded.Destroy()
		t.Fatal("expected nil session after archive")
	}

	// Archiving non-existent session should not error.
	if err := s.ArchiveSession("nonexistent", 1); err != nil {
		t.Fatal(err)
	}
}

func TestKyberPreKeyStore(t *testing.T) {
	s := tempStore(t)

	// Load non-existent.
	_, err := s.LoadKyberPreKey(1)
	if err == nil {
		t.Fatal("expected error for missing kyber pre-key")
	}

	// Generate identity key for signing.
	identityPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityPriv.Destroy()

	// Generate kyber pre-key.
	kyberKP, err := libsignal.GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberKP.Destroy()

	kyberPub, err := kyberKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := identityPriv.Sign(kyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	rec, err := libsignal.NewKyberPreKeyRecord(1, 1000, kyberKP, sig)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.StoreKyberPreKey(1, rec); err != nil {
		t.Fatal(err)
	}

	loaded, err := s.LoadKyberPreKey(1)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Destroy()

	// Mark used.
	if err := s.MarkKyberPreKeyUsed(1, 0, nil); err != nil {
		t.Fatal(err)
	}
}
