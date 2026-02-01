package provisioncrypto

import (
	"encoding/hex"
	"testing"
)

func TestDeriveProvisioningKeysDeterministic(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}

	ck1, mk1, err := DeriveProvisioningKeys(secret)
	if err != nil {
		t.Fatal(err)
	}
	ck2, mk2, err := DeriveProvisioningKeys(secret)
	if err != nil {
		t.Fatal(err)
	}

	if hex.EncodeToString(ck1) != hex.EncodeToString(ck2) {
		t.Fatal("cipher keys not deterministic")
	}
	if hex.EncodeToString(mk1) != hex.EncodeToString(mk2) {
		t.Fatal("mac keys not deterministic")
	}
	if len(ck1) != 32 || len(mk1) != 32 {
		t.Fatalf("unexpected key lengths: cipher=%d, mac=%d", len(ck1), len(mk1))
	}

	// Ensure the two keys are different from each other.
	if hex.EncodeToString(ck1) == hex.EncodeToString(mk1) {
		t.Fatal("cipher key and mac key should differ")
	}
}
