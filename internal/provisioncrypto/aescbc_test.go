package provisioncrypto

import (
	"bytes"
	"crypto/aes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)

	for _, size := range []int{0, 1, 15, 16, 17, 31, 32, 100} {
		plaintext := bytes.Repeat([]byte{0x42}, size)
		encrypted, err := EncryptAESCBC(key, plaintext)
		if err != nil {
			t.Fatalf("size=%d: encrypt: %v", size, err)
		}

		iv := encrypted[:aes.BlockSize]
		ct := encrypted[aes.BlockSize:]

		decrypted, err := DecryptAESCBC(key, iv, ct)
		if err != nil {
			t.Fatalf("size=%d: decrypt: %v", size, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("size=%d: mismatch", size)
		}
	}
}

func TestDecryptRejectsBadCiphertextLength(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	iv := bytes.Repeat([]byte{0x00}, 16)
	_, err := DecryptAESCBC(key, iv, []byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for non-block-aligned ciphertext")
	}
}

func TestDecryptRejectsBadPadding(t *testing.T) {
	key := bytes.Repeat([]byte{0xAB}, 32)
	// Encrypt something, then corrupt the last block.
	encrypted, err := EncryptAESCBC(key, []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	iv := encrypted[:aes.BlockSize]
	ct := encrypted[aes.BlockSize:]
	// Flip a bit in the ciphertext to corrupt padding after decryption.
	ct[len(ct)-1] ^= 0xff
	_, err = DecryptAESCBC(key, iv, ct)
	if err == nil {
		t.Fatal("expected error for corrupted ciphertext")
	}
}
