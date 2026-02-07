package signalservice

import (
	"testing"

	"github.com/gwillem/signal-go/internal/libsignal"
)

func TestGeneratePreKeySet(t *testing.T) {
	identityPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityPriv.Destroy()

	identityPub, err := identityPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer identityPub.Destroy()

	set, err := generatePreKeySet(identityPriv, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer set.SignedPreKey.Destroy()
	defer set.KyberLastResort.Destroy()

	// Verify signed pre-key ID.
	spkID, err := set.SignedPreKey.ID()
	if err != nil {
		t.Fatal(err)
	}
	if spkID != 1 {
		t.Fatalf("signed pre-key ID: got %d, want 1", spkID)
	}

	// Verify Kyber pre-key ID.
	kpkID, err := set.KyberLastResort.ID()
	if err != nil {
		t.Fatal(err)
	}
	if kpkID != 1 {
		t.Fatalf("kyber pre-key ID: got %d, want 1", kpkID)
	}

	// Verify signed pre-key signature is valid.
	spkPub, err := set.SignedPreKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer spkPub.Destroy()

	spkPubBytes, err := spkPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	spkSig, err := set.SignedPreKey.Signature()
	if err != nil {
		t.Fatal(err)
	}

	valid, err := identityPub.Verify(spkPubBytes, spkSig)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("signed pre-key signature should be valid")
	}

	// Verify Kyber pre-key signature is valid.
	kpkPub, err := set.KyberLastResort.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer kpkPub.Destroy()

	kpkPubBytes, err := kpkPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	kpkSig, err := set.KyberLastResort.Signature()
	if err != nil {
		t.Fatal(err)
	}

	valid, err = identityPub.Verify(kpkPubBytes, kpkSig)
	if err != nil {
		t.Fatal(err)
	}
	if !valid {
		t.Fatal("kyber pre-key signature should be valid")
	}
}
