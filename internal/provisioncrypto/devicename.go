package provisioncrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// EncryptDeviceName encrypts a device name using the ACI identity key pair.
// The algorithm follows Signal-Android's DeviceNameCipher.kt.
//
// Returns the marshaled DeviceName protobuf (caller base64-encodes for JSON).
func EncryptDeviceName(name string, aciIdentity *libsignal.IdentityKeyPair) ([]byte, error) {
	plaintext := []byte(name)

	// Generate ephemeral EC key pair.
	ephemeralPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("devicename: generate key: %w", err)
	}
	defer ephemeralPriv.Destroy()

	ephemeralPub, err := ephemeralPriv.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("devicename: public key: %w", err)
	}
	defer ephemeralPub.Destroy()

	ephemeralPubBytes, err := ephemeralPub.Serialize()
	if err != nil {
		return nil, fmt.Errorf("devicename: serialize ephemeral pub: %w", err)
	}

	// ECDH: masterSecret = ephemeralPriv.Agree(aciIdentity.PublicKey)
	masterSecret, err := ephemeralPriv.Agree(aciIdentity.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("devicename: ECDH: %w", err)
	}

	// syntheticIvKey = HMAC-SHA256(masterSecret, "auth")
	syntheticIvKey := hmacSHA256(masterSecret, []byte("auth"))

	// syntheticIv = HMAC-SHA256(syntheticIvKey, plaintext)[:16]
	syntheticIvFull := hmacSHA256(syntheticIvKey, plaintext)
	syntheticIv := syntheticIvFull[:16]

	// cipherKeyKey = HMAC-SHA256(masterSecret, "cipher")
	cipherKeyKey := hmacSHA256(masterSecret, []byte("cipher"))

	// cipherKey = HMAC-SHA256(cipherKeyKey, syntheticIv)
	cipherKey := hmacSHA256(cipherKeyKey, syntheticIv)

	// AES-256-CTR encrypt plaintext with cipherKey, IV=zeros
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, fmt.Errorf("devicename: aes: %w", err)
	}

	ciphertext := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize)) // zero IV
	stream.XORKeyStream(ciphertext, plaintext)

	// Marshal DeviceName protobuf
	deviceName := &proto.DeviceName{
		EphemeralPublic: ephemeralPubBytes,
		SyntheticIv:     syntheticIv,
		Ciphertext:      ciphertext,
	}

	return pb.Marshal(deviceName)
}

// DecryptDeviceName decrypts a marshaled DeviceName protobuf using the ACI identity key pair.
// Used for testing round-trips.
func DecryptDeviceName(data []byte, aciIdentity *libsignal.IdentityKeyPair) (string, error) {
	dn := new(proto.DeviceName)
	if err := pb.Unmarshal(data, dn); err != nil {
		return "", fmt.Errorf("devicename: unmarshal: %w", err)
	}

	ephemeralPub, err := libsignal.DeserializePublicKey(dn.GetEphemeralPublic())
	if err != nil {
		return "", fmt.Errorf("devicename: deserialize ephemeral pub: %w", err)
	}
	defer ephemeralPub.Destroy()

	// ECDH: masterSecret = aciIdentity.PrivateKey.Agree(ephemeralPub)
	masterSecret, err := aciIdentity.PrivateKey.Agree(ephemeralPub)
	if err != nil {
		return "", fmt.Errorf("devicename: ECDH: %w", err)
	}

	// cipherKeyKey = HMAC-SHA256(masterSecret, "cipher")
	cipherKeyKey := hmacSHA256(masterSecret, []byte("cipher"))

	// cipherKey = HMAC-SHA256(cipherKeyKey, syntheticIv)
	cipherKey := hmacSHA256(cipherKeyKey, dn.GetSyntheticIv())

	// AES-256-CTR decrypt
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return "", fmt.Errorf("devicename: aes: %w", err)
	}

	plaintext := make([]byte, len(dn.GetCiphertext()))
	stream := cipher.NewCTR(block, make([]byte, aes.BlockSize))
	stream.XORKeyStream(plaintext, dn.GetCiphertext())

	// Verify syntheticIv
	syntheticIvKey := hmacSHA256(masterSecret, []byte("auth"))
	expectedIv := hmacSHA256(syntheticIvKey, plaintext)[:16]

	if !hmac.Equal(expectedIv, dn.GetSyntheticIv()) {
		return "", fmt.Errorf("devicename: synthetic IV verification failed")
	}

	return string(plaintext), nil
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
