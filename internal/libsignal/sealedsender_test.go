package libsignal

import (
	"bytes"
	"testing"
	"time"
)

// TestSealedSenderDecryptToUSMCInvalidCiphertext verifies that the two-step
// approach also returns proper errors for invalid ciphertext.
func TestSealedSenderDecryptToUSMCInvalidCiphertext(t *testing.T) {
	bob := newParty(t, 2)

	_, err := SealedSenderDecryptToUSMC(
		[]byte("not-valid-sealed-sender-ciphertext"),
		bob.identityStore,
	)
	if err == nil {
		t.Fatal("expected error for invalid ciphertext, got nil")
	}
	t.Logf("got expected error: %v", err)
}

// TestSealedSenderEncryptDecrypt verifies the full sealed sender round-trip:
// 1. Create trust root, server cert, sender cert
// 2. Establish session between alice and bob
// 3. Alice encrypts inner message, wraps in USMC, seals with sealed sender
// 4. Bob decrypts outer layer, validates cert, decrypts inner message
// 5. Verify plaintext matches
func TestSealedSenderEncryptDecrypt(t *testing.T) {
	alice := newParty(t, 1)
	bob := newParty(t, 2)

	aliceUUID := "alice-9d0652a3-dcc3-4d11-975f-74d61598733f"
	bobUUID := "bob-796abedb-ca4e-4f18-8803-1fde5b921f9f"
	aliceDeviceID := uint32(1)

	// Create addresses.
	aliceAddr, err := NewAddress(aliceUUID, aliceDeviceID)
	if err != nil {
		t.Fatalf("NewAddress alice: %v", err)
	}
	defer aliceAddr.Destroy()

	bobAddr, err := NewAddress(bobUUID, 1)
	if err != nil {
		t.Fatalf("NewAddress bob: %v", err)
	}
	defer bobAddr.Destroy()

	// 1. Create trust root and server certificate.
	trustRootPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey trustRoot: %v", err)
	}
	trustRootPub, err := trustRootPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey trustRoot: %v", err)
	}
	defer trustRootPub.Destroy()

	serverPriv, err := GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey server: %v", err)
	}
	serverPub, err := serverPriv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey server: %v", err)
	}
	defer serverPub.Destroy()

	serverCert, err := NewServerCertificate(1, serverPub, trustRootPriv)
	if err != nil {
		t.Fatalf("NewServerCertificate: %v", err)
	}
	defer serverCert.Destroy()

	// 2. Create sender certificate for alice.
	alicePub := alice.identityPub
	expires := uint64(time.Now().Add(time.Hour).UnixMilli())

	senderCert, err := NewSenderCertificate(
		aliceUUID,
		"+14151111111", // e164
		alicePub,
		aliceDeviceID,
		expires,
		serverCert,
		serverPriv,
	)
	if err != nil {
		t.Fatalf("NewSenderCertificate: %v", err)
	}
	defer senderCert.Destroy()

	// 3. Establish session: alice processes bob's pre-key bundle.
	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()

	err = ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("ProcessPreKeyBundle: %v", err)
	}

	// 4. Alice encrypts inner message.
	plaintext := []byte("hello from sealed sender!")
	ciphertext, err := Encrypt(plaintext, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	defer ciphertext.Destroy()

	msgType, err := ciphertext.Type()
	if err != nil {
		t.Fatalf("ciphertext.Type: %v", err)
	}
	if msgType != CiphertextMessageTypePreKey {
		t.Fatalf("expected PreKey message type, got %d", msgType)
	}

	// 5. Create UnidentifiedSenderMessageContent wrapping the ciphertext.
	usmc, err := NewUnidentifiedSenderMessageContent(ciphertext, senderCert, ContentHintDefault, nil)
	if err != nil {
		t.Fatalf("NewUnidentifiedSenderMessageContent: %v", err)
	}
	defer usmc.Destroy()

	// 6. Encrypt with sealed sender (uses bob's identity for ECDH).
	// First we need bob's identity in alice's identity store.
	bobIdentityPubBytes, err := bob.identityPub.Serialize()
	if err != nil {
		t.Fatalf("Serialize bob identity pub: %v", err)
	}
	_, err = alice.identityStore.SaveIdentityKey(bobAddr, bobIdentityPubBytes)
	if err != nil {
		t.Fatalf("SaveIdentityKey: %v", err)
	}

	sealed, err := SealedSenderEncrypt(bobAddr, usmc, alice.identityStore)
	if err != nil {
		t.Fatalf("SealedSenderEncrypt: %v", err)
	}
	t.Logf("sealed sender ciphertext length: %d", len(sealed))

	// 7. Bob decrypts outer layer.
	decryptedUSMC, err := SealedSenderDecryptToUSMC(sealed, bob.identityStore)
	if err != nil {
		t.Fatalf("SealedSenderDecryptToUSMC: %v", err)
	}
	defer decryptedUSMC.Destroy()

	// 8. Verify sender certificate.
	cert, err := decryptedUSMC.GetSenderCert()
	if err != nil {
		t.Fatalf("GetSenderCert: %v", err)
	}
	defer cert.Destroy()

	// Validate with a timestamp before expiration.
	validationTime := uint64(time.Now().UnixMilli())
	valid, err := cert.Validate(trustRootPub, validationTime)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if !valid {
		t.Fatal("sender certificate invalid")
	}

	// Verify sender info from certificate.
	senderUUID, err := cert.SenderUUID()
	if err != nil {
		t.Fatalf("SenderUUID: %v", err)
	}
	if senderUUID != aliceUUID {
		t.Errorf("sender UUID mismatch: got %s, want %s", senderUUID, aliceUUID)
	}

	senderDevice, err := cert.DeviceID()
	if err != nil {
		t.Fatalf("DeviceID: %v", err)
	}
	if senderDevice != aliceDeviceID {
		t.Errorf("sender device mismatch: got %d, want %d", senderDevice, aliceDeviceID)
	}

	// 9. Decrypt inner message.
	innerMsgType, err := decryptedUSMC.MsgType()
	if err != nil {
		t.Fatalf("MsgType: %v", err)
	}
	if innerMsgType != CiphertextMessageTypePreKey {
		t.Fatalf("inner message type mismatch: got %d, want %d", innerMsgType, CiphertextMessageTypePreKey)
	}

	innerContent, err := decryptedUSMC.Contents()
	if err != nil {
		t.Fatalf("Contents: %v", err)
	}

	preKeyMsg, err := DeserializePreKeySignalMessage(innerContent)
	if err != nil {
		t.Fatalf("DeserializePreKeySignalMessage: %v", err)
	}
	defer preKeyMsg.Destroy()

	decrypted, err := DecryptPreKeyMessage(preKeyMsg, aliceAddr,
		bob.sessionStore, bob.identityStore,
		bob.preKeyStore, bob.signedPreKeyStore, bob.kyberPreKeyStore)
	if err != nil {
		t.Fatalf("DecryptPreKeyMessage: %v", err)
	}

	// 10. Verify plaintext matches.
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("plaintext mismatch: got %q, want %q", decrypted, plaintext)
	}
	t.Logf("successfully decrypted sealed sender message: %q", decrypted)
}

// TestSealedSenderWrongIdentityKey verifies that decryption fails when the
// recipient's identity key doesn't match what was used for encryption.
// This simulates the scenario where a re-linked device has a different identity key.
func TestSealedSenderWrongIdentityKey(t *testing.T) {
	alice := newParty(t, 1)
	bob := newParty(t, 2)
	bobWrong := newParty(t, 3) // Different identity key for bob

	aliceUUID := "alice-9d0652a3-dcc3-4d11-975f-74d61598733f"
	bobUUID := "bob-796abedb-ca4e-4f18-8803-1fde5b921f9f"
	aliceDeviceID := uint32(1)

	aliceAddr, err := NewAddress(aliceUUID, aliceDeviceID)
	if err != nil {
		t.Fatalf("NewAddress alice: %v", err)
	}
	defer aliceAddr.Destroy()

	bobAddr, err := NewAddress(bobUUID, 1)
	if err != nil {
		t.Fatalf("NewAddress bob: %v", err)
	}
	defer bobAddr.Destroy()

	// Create certs.
	trustRootPriv, _ := GeneratePrivateKey()
	trustRootPub, _ := trustRootPriv.PublicKey()
	defer trustRootPub.Destroy()

	serverPriv, _ := GeneratePrivateKey()
	serverPub, _ := serverPriv.PublicKey()
	defer serverPub.Destroy()

	serverCert, _ := NewServerCertificate(1, serverPub, trustRootPriv)
	defer serverCert.Destroy()

	expires := uint64(time.Now().Add(time.Hour).UnixMilli())
	senderCert, _ := NewSenderCertificate(aliceUUID, "", alice.identityPub, aliceDeviceID, expires, serverCert, serverPriv)
	defer senderCert.Destroy()

	// Establish session with bob's CORRECT identity.
	bobBundle := bob.buildPreKeyBundle(t)
	defer bobBundle.Destroy()
	ProcessPreKeyBundle(bobBundle, bobAddr, alice.sessionStore, alice.identityStore, time.Now())

	// Encrypt for bob's CORRECT identity.
	plaintext := []byte("test message")
	ciphertext, _ := Encrypt(plaintext, bobAddr, alice.sessionStore, alice.identityStore, time.Now())
	defer ciphertext.Destroy()

	usmc, _ := NewUnidentifiedSenderMessageContent(ciphertext, senderCert, ContentHintDefault, nil)
	defer usmc.Destroy()

	// Save bob's CORRECT identity for sealed sender encryption.
	bobIdentityPubBytes, _ := bob.identityPub.Serialize()
	_, _ = alice.identityStore.SaveIdentityKey(bobAddr, bobIdentityPubBytes)

	sealed, err := SealedSenderEncrypt(bobAddr, usmc, alice.identityStore)
	if err != nil {
		t.Fatalf("SealedSenderEncrypt: %v", err)
	}

	// Try to decrypt with the WRONG identity key (bobWrong instead of bob).
	// This simulates a re-linked device with different keys.
	_, err = SealedSenderDecryptToUSMC(sealed, bobWrong.identityStore)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong identity key, but it succeeded")
	}
	t.Logf("correctly failed with wrong identity key: %v", err)

	// Verify it succeeds with the CORRECT identity key.
	decryptedUSMC, err := SealedSenderDecryptToUSMC(sealed, bob.identityStore)
	if err != nil {
		t.Fatalf("SealedSenderDecryptToUSMC with correct key: %v", err)
	}
	decryptedUSMC.Destroy()
	t.Log("correctly succeeded with correct identity key")
}
