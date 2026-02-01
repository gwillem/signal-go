package signalservice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterSecondaryDevice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method: got %s, want PUT", r.Method)
		}
		if r.URL.Path != "/v1/devices/link" {
			t.Errorf("path: got %s, want /v1/devices/link", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type: got %s", r.Header.Get("Content-Type"))
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var req RegisterRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if req.VerificationCode == "" {
			t.Error("verificationCode should not be empty")
		}
		if req.AccountAttributes.FetchesMessages != true {
			t.Error("fetchesMessages should be true")
		}
		if req.ACISignedPreKey.KeyID == 0 {
			t.Error("aciSignedPreKey.keyId should not be 0")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RegisterResponse{
			UUID:     "aci-uuid",
			PNI:      "pni-uuid",
			DeviceID: 2,
		})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL)

	req := &RegisterRequest{
		VerificationCode: "test-code",
		AccountAttributes: AccountAttributes{
			RegistrationID:    12345,
			PNIRegistrationID: 67890,
			FetchesMessages:   true,
			Name:              "dGVzdA==",
			Capabilities: Capabilities{
				Storage:                  true,
				VersionedExpirationTimer: true,
				AttachmentBackfill:       true,
			},
		},
		ACISignedPreKey: SignedPreKeyEntity{KeyID: 1, PublicKey: "abc", Signature: "def"},
		PNISignedPreKey: SignedPreKeyEntity{KeyID: 1, PublicKey: "ghi", Signature: "jkl"},
		ACIPqLastResort: KyberPreKeyEntity{KeyID: 1, PublicKey: "mno", Signature: "pqr"},
		PNIPqLastResort: KyberPreKeyEntity{KeyID: 1, PublicKey: "stu", Signature: "vwx"},
	}

	resp, err := client.RegisterSecondaryDevice(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}

	if resp.UUID != "aci-uuid" {
		t.Fatalf("uuid: got %q, want %q", resp.UUID, "aci-uuid")
	}
	if resp.DeviceID != 2 {
		t.Fatalf("deviceId: got %d, want 2", resp.DeviceID)
	}
}

func TestRegisterSecondaryDeviceError(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"forbidden", 403},
		{"length required", 411},
		{"rate limited", 429},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.status)
				w.Write([]byte("error"))
			}))
			defer srv.Close()

			client := NewHTTPClient(srv.URL)
			_, err := client.RegisterSecondaryDevice(context.Background(), &RegisterRequest{})
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestUploadPreKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method: got %s, want PUT", r.Method)
		}
		if r.URL.Path != "/v2/keys" {
			t.Errorf("path: got %s, want /v2/keys", r.URL.Path)
		}
		if r.URL.Query().Get("identity") != "aci" {
			t.Errorf("identity: got %q, want aci", r.URL.Query().Get("identity"))
		}

		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("missing basic auth")
		}
		if user != "aci-uuid.2" {
			t.Errorf("username: got %q", user)
		}
		if pass != "password123" {
			t.Errorf("password: got %q", pass)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}

		var upload PreKeyUpload
		if err := json.Unmarshal(body, &upload); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if upload.SignedPreKey == nil {
			t.Error("signedPreKey should not be nil")
		}
		if upload.PqLastResortKey == nil {
			t.Error("pqLastResortPreKey should not be nil")
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL)

	err := client.UploadPreKeys(context.Background(), "aci", &PreKeyUpload{
		SignedPreKey:    &SignedPreKeyEntity{KeyID: 1, PublicKey: "abc", Signature: "def"},
		PqLastResortKey: &KyberPreKeyEntity{KeyID: 1, PublicKey: "ghi", Signature: "jkl"},
	}, BasicAuth{Username: "aci-uuid.2", Password: "password123"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestUploadPreKeysError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("forbidden"))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL)
	err := client.UploadPreKeys(context.Background(), "aci", &PreKeyUpload{}, BasicAuth{})
	if err == nil {
		t.Fatal("expected error")
	}
}
