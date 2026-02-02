package signalservice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

		user, pass, ok := r.BasicAuth()
		if !ok || user == "" || pass == "" {
			t.Error("missing or empty basic auth on /v1/devices/link")
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

	client := NewHTTPClient(srv.URL, nil, nil)

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

	resp, err := client.RegisterSecondaryDevice(context.Background(), req, BasicAuth{
		Username: "+15551234567",
		Password: "test-password",
	})
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
				if tt.status == 429 {
					w.Header().Set("Retry-After", "0")
				}
				w.WriteHeader(tt.status)
				w.Write([]byte("error"))
			}))
			defer srv.Close()

			ctx := context.Background()
			if tt.status == 429 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 2*time.Second)
				defer cancel()
			}

			client := NewHTTPClient(srv.URL, nil, nil)
			_, err := client.RegisterSecondaryDevice(ctx, &RegisterRequest{}, BasicAuth{})
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

	client := NewHTTPClient(srv.URL, nil, nil)

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

	client := NewHTTPClient(srv.URL, nil, nil)
	err := client.UploadPreKeys(context.Background(), "aci", &PreKeyUpload{}, BasicAuth{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestGetPreKeys(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method: got %s, want GET", r.Method)
		}
		if r.URL.Path != "/v2/keys/recipient-aci/1" {
			t.Errorf("path: got %s, want /v2/keys/recipient-aci/1", r.URL.Path)
		}

		user, _, ok := r.BasicAuth()
		if !ok {
			t.Error("missing basic auth")
		}
		if user != "my-aci.2" {
			t.Errorf("username: got %q", user)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PreKeyResponse{
			IdentityKey: "aWRlbnRpdHk",
			Devices: []PreKeyDeviceInfo{
				{
					DeviceID:       1,
					RegistrationID: 12345,
					SignedPreKey:   &SignedPreKeyEntity{KeyID: 1, PublicKey: "c3BrLXB1Yg", Signature: "c2ln"},
					PreKey:         &PreKeyEntity{KeyID: 100, PublicKey: "cHJla2V5"},
					PqPreKey:       &KyberPreKeyEntity{KeyID: 200, PublicKey: "a3liZXI", Signature: "a3NpZw"},
				},
			},
		})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	resp, err := client.GetPreKeys(context.Background(), "recipient-aci", 1, BasicAuth{
		Username: "my-aci.2",
		Password: "mypass",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.IdentityKey != "aWRlbnRpdHk" {
		t.Errorf("identityKey: got %q", resp.IdentityKey)
	}
	if len(resp.Devices) != 1 {
		t.Fatalf("devices: got %d", len(resp.Devices))
	}
	if resp.Devices[0].DeviceID != 1 {
		t.Errorf("deviceId: got %d", resp.Devices[0].DeviceID)
	}
	if resp.Devices[0].RegistrationID != 12345 {
		t.Errorf("registrationId: got %d", resp.Devices[0].RegistrationID)
	}
	if resp.Devices[0].PreKey == nil {
		t.Error("preKey should not be nil")
	}
	if resp.Devices[0].PqPreKey == nil {
		t.Error("pqPreKey should not be nil")
	}
}

func TestGetPreKeysError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("not found"))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	_, err := client.GetPreKeys(context.Background(), "unknown", 1, BasicAuth{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestSendMessage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method: got %s, want PUT", r.Method)
		}
		if r.URL.Path != "/v1/messages/recipient-aci" {
			t.Errorf("path: got %s, want /v1/messages/recipient-aci", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type: got %s", r.Header.Get("Content-Type"))
		}

		user, _, ok := r.BasicAuth()
		if !ok {
			t.Error("missing basic auth")
		}
		if user != "my-aci.2" {
			t.Errorf("username: got %q", user)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}

		var msg OutgoingMessageList
		if err := json.Unmarshal(body, &msg); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if msg.Destination != "recipient-aci" {
			t.Errorf("destination: got %q", msg.Destination)
		}
		if msg.Timestamp == 0 {
			t.Error("timestamp should not be 0")
		}
		if len(msg.Messages) != 1 {
			t.Fatalf("messages: got %d", len(msg.Messages))
		}
		if msg.Messages[0].Content == "" {
			t.Error("content should not be empty")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	err := client.SendMessage(context.Background(), "recipient-aci", &OutgoingMessageList{
		Destination: "recipient-aci",
		Timestamp:   1234567890,
		Messages: []OutgoingMessage{
			{
				Type:                      3,
				DestinationDeviceID:       1,
				DestinationRegistrationID: 12345,
				Content:                   "ZW5jcnlwdGVk",
			},
		},
		Urgent: true,
	}, BasicAuth{Username: "my-aci.2", Password: "mypass"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSendMessageError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		w.Write([]byte("stale devices"))
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	err := client.SendMessage(context.Background(), "recipient", &OutgoingMessageList{}, BasicAuth{})
	if err == nil {
		t.Fatal("expected error")
	}
}
