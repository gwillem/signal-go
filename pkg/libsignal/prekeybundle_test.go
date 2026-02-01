package libsignal

import "testing"

// C6: Build PreKeyBundle from all components (EC + Kyber)
func TestPreKeyBundle(t *testing.T) {
	// Identity key
	identityPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey (identity): %v", err)
	}
	defer identityPriv.Destroy()

	identityPub, err := identityPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey (identity): %v", err)
	}
	defer identityPub.Destroy()

	// EC pre-key
	preKeyPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey (prekey): %v", err)
	}
	defer preKeyPriv.Destroy()

	preKeyPub, err := preKeyPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey (prekey): %v", err)
	}
	defer preKeyPub.Destroy()

	// Signed pre-key
	signedPreKeyPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey (signed): %v", err)
	}
	defer signedPreKeyPriv.Destroy()

	signedPreKeyPub, err := signedPreKeyPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey (signed): %v", err)
	}
	defer signedPreKeyPub.Destroy()

	signedPreKeyPubBytes, err := signedPreKeyPub.Serialize()
	if err != nil {
		t.Fatalf("Serialize signed pub: %v", err)
	}

	signedPreKeySig, err := identityPriv.Sign(signedPreKeyPubBytes)
	if err != nil {
		t.Fatalf("Sign signed prekey: %v", err)
	}

	// Kyber pre-key
	kyberKP, err := GenerateKyberKeyPair()
	if err != nil {
		t.Fatalf("GenerateKyberKeyPair: %v", err)
	}
	defer kyberKP.Destroy()

	kyberPub, err := kyberKP.PublicKey()
	if err != nil {
		t.Fatalf("KyberPublicKey: %v", err)
	}
	defer kyberPub.Destroy()

	kyberPubBytes, err := kyberPub.Serialize()
	if err != nil {
		t.Fatalf("Serialize kyber pub: %v", err)
	}

	kyberSig, err := identityPriv.Sign(kyberPubBytes)
	if err != nil {
		t.Fatalf("Sign kyber: %v", err)
	}

	bundle, err := NewPreKeyBundle(
		1,    // registrationID
		1,    // deviceID
		42,   // preKeyID
		preKeyPub,
		7,    // signedPreKeyID
		signedPreKeyPub,
		signedPreKeySig,
		identityPub,
		99,   // kyberPreKeyID
		kyberPub,
		kyberSig,
	)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}
	defer bundle.Destroy()
}
