package provisioncrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"testing"

	"github.com/gwillem/signal-go/internal/libsignal"
)

// encryptProvisionBody simulates primary-side encryption of a provisioning message.
func encryptProvisionBody(cipherKey, macKey, plaintext []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	padded := PKCS7Pad(plaintext, aes.BlockSize)
	ct := make([]byte, len(padded))

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	// body: version(1) || iv(16) || ciphertext || mac(32)
	body := make([]byte, 0, 1+len(iv)+len(ct)+32)
	body = append(body, 0x01)
	body = append(body, iv...)
	body = append(body, ct...)

	mac := ComputeMAC(macKey, body)
	body = append(body, mac...)

	return body, nil
}

func TestDecryptProvisionEnvelope(t *testing.T) {
	// Secondary generates an ephemeral key pair.
	ourPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ourPriv.Destroy()

	ourPub, err := ourPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer ourPub.Destroy()

	// Primary generates its own ephemeral key pair.
	theirPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer theirPriv.Destroy()

	theirPub, err := theirPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer theirPub.Destroy()

	theirPubBytes, err := theirPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Primary: ECDH agreement with secondary's public key.
	sharedSecret, err := theirPriv.Agree(ourPub)
	if err != nil {
		t.Fatal(err)
	}

	// Primary: derive keys.
	cipherKey, macKey, err := DeriveProvisioningKeys(sharedSecret)
	if err != nil {
		t.Fatal(err)
	}

	// Primary: encrypt.
	plaintext := []byte("hello from primary device")
	body, err := encryptProvisionBody(cipherKey, macKey, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Secondary: decrypt.
	decrypted, err := DecryptProvisionEnvelope(ourPriv, theirPubBytes, body)
	if err != nil {
		t.Fatal(err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("got %q, want %q", decrypted, plaintext)
	}

	// Tampered body should fail.
	tampered := make([]byte, len(body))
	copy(tampered, body)
	tampered[20] ^= 0xff
	if _, err := DecryptProvisionEnvelope(ourPriv, theirPubBytes, tampered); err == nil {
		t.Fatal("expected error for tampered body")
	}

	// Wrong version should fail.
	badVersion := make([]byte, len(body))
	copy(badVersion, body)
	badVersion[0] = 0x02
	if _, err := DecryptProvisionEnvelope(ourPriv, theirPubBytes, badVersion); err == nil {
		t.Fatal("expected error for bad version")
	}
}

func TestDecryptProvisionEnvelopeTooShort(t *testing.T) {
	priv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer priv.Destroy()

	_, err = DecryptProvisionEnvelope(priv, []byte{0x05}, []byte{0x01})
	if err == nil {
		t.Fatal("expected error for too-short body")
	}
}
