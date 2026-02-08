package store

import (
	"path/filepath"
	"testing"

	"github.com/gwillem/signal-go/internal/libsignal"
)

func TestPNIIdentityStore(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "pni_test.db")
	s, err := Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// Generate ACI and PNI identity keys.
	aciPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer aciPriv.Destroy()

	pniPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer pniPriv.Destroy()

	if err := s.SetIdentity(aciPriv, 100); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPNIIdentity(pniPriv, 200); err != nil {
		t.Fatal(err)
	}

	// Store.GetIdentityKeyPair should return ACI key.
	aciKey, err := s.GetIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer aciKey.Destroy()

	aciPub, err := aciKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer aciPub.Destroy()

	// Store.GetLocalRegistrationID should return ACI reg ID.
	regID, err := s.GetLocalRegistrationID()
	if err != nil {
		t.Fatal(err)
	}
	if regID != 100 {
		t.Fatalf("expected ACI reg ID 100, got %d", regID)
	}

	// PNI wrapper should return PNI key.
	pni := s.PNI()
	pniKey, err := pni.GetIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer pniKey.Destroy()

	pniPub, err := pniKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer pniPub.Destroy()

	// PNI wrapper should return PNI reg ID.
	pniRegID, err := pni.GetLocalRegistrationID()
	if err != nil {
		t.Fatal(err)
	}
	if pniRegID != 200 {
		t.Fatalf("expected PNI reg ID 200, got %d", pniRegID)
	}

	// ACI and PNI public keys should be different.
	cmp, err := aciPub.Compare(pniPub)
	if err != nil {
		t.Fatal(err)
	}
	if cmp == 0 {
		t.Fatal("ACI and PNI public keys should be different")
	}

	// Verify original ACI public key matches what we get from the original key.
	origAciPub, err := aciPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer origAciPub.Destroy()

	cmp, err = aciPub.Compare(origAciPub)
	if err != nil {
		t.Fatal(err)
	}
	if cmp != 0 {
		t.Fatal("ACI key from store should match original")
	}

	// Verify PNI public key matches what we get from the original key.
	origPniPub, err := pniPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer origPniPub.Destroy()

	cmp, err = pniPub.Compare(origPniPub)
	if err != nil {
		t.Fatal(err)
	}
	if cmp != 0 {
		t.Fatal("PNI key from store should match original")
	}
}
