package libsignal

import (
	"testing"
	"time"
)

func TestInvalidDeserialization(t *testing.T) {
	allBadInputs := []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"single 0xff", []byte{0xff}},
		{"truncated", []byte{0x0a, 0x01}},
	}

	// Protobuf-based types accept nil/empty as valid (empty protobuf message),
	// so only test garbage/truncated data for those.
	garbageInputs := allBadInputs[2:] // 0xff and truncated only

	type deserFunc struct {
		name   string
		fn     func([]byte) error
		inputs []struct {
			name string
			data []byte
		}
	}

	funcs := []deserFunc{
		{"DeserializePrivateKey", func(d []byte) error {
			_, err := DeserializePrivateKey(d)
			return err
		}, allBadInputs},
		{"DeserializePublicKey", func(d []byte) error {
			_, err := DeserializePublicKey(d)
			return err
		}, allBadInputs},
		{"DeserializeIdentityKeyPair", func(d []byte) error {
			_, err := DeserializeIdentityKeyPair(d)
			return err
		}, allBadInputs},
		{"DeserializePreKeyRecord", func(d []byte) error {
			_, err := DeserializePreKeyRecord(d)
			return err
		}, garbageInputs},
		{"DeserializeSignedPreKeyRecord", func(d []byte) error {
			_, err := DeserializeSignedPreKeyRecord(d)
			return err
		}, garbageInputs},
		{"DeserializeKyberPreKeyRecord", func(d []byte) error {
			_, err := DeserializeKyberPreKeyRecord(d)
			return err
		}, garbageInputs},
		{"DeserializeSessionRecord", func(d []byte) error {
			_, err := DeserializeSessionRecord(d)
			return err
		}, garbageInputs},
		{"DeserializePreKeySignalMessage", func(d []byte) error {
			_, err := DeserializePreKeySignalMessage(d)
			return err
		}, allBadInputs},
		{"DeserializeSignalMessage", func(d []byte) error {
			_, err := DeserializeSignalMessage(d)
			return err
		}, allBadInputs},
	}

	for _, fn := range funcs {
		for _, input := range fn.inputs {
			t.Run(fn.name+"/"+input.name, func(t *testing.T) {
				err := fn.fn(input.data)
				if err == nil {
					t.Errorf("%s(%s) expected error, got nil", fn.name, input.name)
				}
			})
		}
	}
}

func TestDoubleDestroy(t *testing.T) {
	t.Run("PrivateKey", func(t *testing.T) {
		k, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		k.Destroy()
		k.Destroy() // should not panic
	})

	t.Run("PublicKey", func(t *testing.T) {
		priv, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := priv.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		priv.Destroy()
		pub.Destroy()
		pub.Destroy()
	})

	t.Run("IdentityKeyPair", func(t *testing.T) {
		kp, err := GenerateIdentityKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		kp.Destroy()
		kp.Destroy()
	})

	t.Run("Address", func(t *testing.T) {
		addr, err := NewAddress("test", 1)
		if err != nil {
			t.Fatal(err)
		}
		addr.Destroy()
		addr.Destroy()
	})

	t.Run("PreKeyRecord", func(t *testing.T) {
		priv, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := priv.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		rec, err := NewPreKeyRecord(1, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		pub.Destroy()
		priv.Destroy()
		rec.Destroy()
		rec.Destroy()
	})

	t.Run("SignedPreKeyRecord", func(t *testing.T) {
		priv, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := priv.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		identity, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := pub.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := identity.Sign(pubBytes)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := NewSignedPreKeyRecord(1, 0, pub, priv, sig)
		if err != nil {
			t.Fatal(err)
		}
		identity.Destroy()
		pub.Destroy()
		priv.Destroy()
		rec.Destroy()
		rec.Destroy()
	})

	t.Run("KyberKeyPair", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		kp.Destroy()
		kp.Destroy()
	})

	t.Run("KyberPublicKey", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		kp.Destroy()
		pub.Destroy()
		pub.Destroy()
	})

	t.Run("KyberPreKeyRecord", func(t *testing.T) {
		kp, err := GenerateKyberKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		identity, err := GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		pub, err := kp.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		pubBytes, err := pub.Serialize()
		if err != nil {
			t.Fatal(err)
		}
		sig, err := identity.Sign(pubBytes)
		if err != nil {
			t.Fatal(err)
		}
		rec, err := NewKyberPreKeyRecord(1, 0, kp, sig)
		if err != nil {
			t.Fatal(err)
		}
		identity.Destroy()
		kp.Destroy()
		pub.Destroy()
		rec.Destroy()
		rec.Destroy()
	})

	t.Run("PreKeyBundle", func(t *testing.T) {
		party := newParty(t, 1)
		bundle := party.buildPreKeyBundle(t)
		bundle.Destroy()
		bundle.Destroy()
	})

	t.Run("CiphertextMessage", func(t *testing.T) {
		// Need a real ciphertext to test double destroy
		alice := newParty(t, 1)
		bob := newParty(t, 2)
		bobAddr, err := NewAddress("+31600000002", 1)
		if err != nil {
			t.Fatal(err)
		}
		defer bobAddr.Destroy()
		bobBundle := bob.buildPreKeyBundle(t)
		defer bobBundle.Destroy()
		if err := ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now()); err != nil {
			t.Fatal(err)
		}
		ct, err := Encrypt([]byte("test"), bobAddr, alice.sessionStore, alice.identityStore, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		ct.Destroy()
		ct.Destroy()
	})

	t.Run("SessionRecord", func(t *testing.T) {
		alice := newParty(t, 1)
		bob := newParty(t, 2)
		bobAddr, err := NewAddress("+31600000002", 1)
		if err != nil {
			t.Fatal(err)
		}
		defer bobAddr.Destroy()
		bobBundle := bob.buildPreKeyBundle(t)
		defer bobBundle.Destroy()
		if err := ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now()); err != nil {
			t.Fatal(err)
		}
		session, err := alice.sessionStore.LoadSession(bobAddr)
		if err != nil {
			t.Fatal(err)
		}
		session.Destroy()
		session.Destroy()
	})
}
