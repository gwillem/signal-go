package signalservice

import (
	"encoding/hex"
	"testing"
)

func TestDeriveAccessKey(t *testing.T) {
	// Known test vectors from libsignal's profile_key.rs access_key_kat test
	tests := []struct {
		profileKey string
		accessKey  string
	}{
		{
			// First test vector from libsignal zkgroup
			profileKey: "b95042a2c2d9e5b3bb09300ee408a172facd96e91b504e043a5a023dc4cff359",
			accessKey:  "24fb96d4a5e333e9d4451205b9e2faed",
		},
		{
			// Second test vector from libsignal zkgroup
			profileKey: "26197b17e5a2c36d8c9518c35358f123c476000db6da7565c0d41f6674462c4d",
			accessKey:  "e895c30cf780757d22f7a179708b14a1",
		},
	}

	for _, tt := range tests {
		pk, _ := hex.DecodeString(tt.profileKey)
		expected, _ := hex.DecodeString(tt.accessKey)

		result, err := DeriveAccessKey(pk)
		if err != nil {
			t.Fatalf("DeriveAccessKey: %v", err)
		}

		if hex.EncodeToString(result) != tt.accessKey {
			t.Errorf("DeriveAccessKey mismatch:\ngot:  %x\nwant: %x", result, expected)
		}
	}
}

func TestDeriveAccessKey_InvalidLength(t *testing.T) {
	_, err := DeriveAccessKey([]byte("too short"))
	if err == nil {
		t.Error("expected error for invalid profile key length")
	}
}
