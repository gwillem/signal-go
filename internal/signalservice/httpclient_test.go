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

func TestCreateVerificationSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/verification/session" {
			t.Errorf("path: got %s, want /v1/verification/session", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type: got %s", r.Header.Get("Content-Type"))
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var req VerificationSessionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Number != "+15551234567" {
			t.Errorf("e164: got %q, want +15551234567", req.Number)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerificationSessionResponse{
			ID:                   "session-123",
			AllowedToRequestCode: true,
			Verified:             false,
		})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	resp, err := client.CreateVerificationSession(context.Background(), "+15551234567")
	if err != nil {
		t.Fatal(err)
	}

	if resp.ID != "session-123" {
		t.Errorf("id: got %q, want session-123", resp.ID)
	}
	if !resp.AllowedToRequestCode {
		t.Error("allowedToRequestCode should be true")
	}
	if resp.Verified {
		t.Error("verified should be false")
	}
}

func TestRequestVerificationCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/verification/session/session-123/code" {
			t.Errorf("path: got %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var req RequestVerificationCodeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Transport != "sms" {
			t.Errorf("transport: got %q, want sms", req.Transport)
		}

		w.Header().Set("Content-Type", "application/json")
		nextSms := 60
		json.NewEncoder(w).Encode(VerificationSessionResponse{
			ID:                   "session-123",
			NextSms:              &nextSms,
			AllowedToRequestCode: false,
		})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	resp, err := client.RequestVerificationCode(context.Background(), "session-123", "sms")
	if err != nil {
		t.Fatal(err)
	}

	if resp.ID != "session-123" {
		t.Errorf("id: got %q", resp.ID)
	}
	if resp.NextSms == nil || *resp.NextSms != 60 {
		t.Error("nextSms should be 60")
	}
}

func TestSubmitVerificationCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method: got %s, want PUT", r.Method)
		}
		if r.URL.Path != "/v1/verification/session/session-123/code" {
			t.Errorf("path: got %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var req SubmitVerificationCodeRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Code != "123456" {
			t.Errorf("code: got %q, want 123456", req.Code)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerificationSessionResponse{
			ID:       "session-123",
			Verified: true,
		})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	resp, err := client.SubmitVerificationCode(context.Background(), "session-123", "123456")
	if err != nil {
		t.Fatal(err)
	}

	if !resp.Verified {
		t.Error("verified should be true")
	}
}

func TestUpdateSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch {
			t.Errorf("method: got %s, want PATCH", r.Method)
		}
		if r.URL.Path != "/v1/verification/session/session-123" {
			t.Errorf("path: got %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var req UpdateSessionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Captcha != "captcha-token" {
			t.Errorf("captcha: got %q", req.Captcha)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(VerificationSessionResponse{
			ID:                   "session-123",
			AllowedToRequestCode: true,
		})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	resp, err := client.UpdateSession(context.Background(), "session-123", &UpdateSessionRequest{
		Captcha: "captcha-token",
	})
	if err != nil {
		t.Fatal(err)
	}

	if !resp.AllowedToRequestCode {
		t.Error("allowedToRequestCode should be true after CAPTCHA")
	}
}

func TestRegisterPrimaryDevice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method: got %s, want POST", r.Method)
		}
		if r.URL.Path != "/v1/registration" {
			t.Errorf("path: got %s, want /v1/registration", r.URL.Path)
		}

		user, pass, ok := r.BasicAuth()
		if !ok {
			t.Error("missing basic auth")
		}
		if user != "+15551234567" {
			t.Errorf("username: got %q, want +15551234567", user)
		}
		if pass != "test-password" {
			t.Errorf("password: got %q", pass)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var req PrimaryRegistrationRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.SessionID != "session-123" {
			t.Errorf("sessionId: got %q", req.SessionID)
		}
		if req.ACIIdentityKey == "" {
			t.Error("aciIdentityKey should not be empty")
		}
		if req.PNIIdentityKey == "" {
			t.Error("pniIdentityKey should not be empty")
		}
		if !req.SkipDeviceTransfer {
			t.Error("skipDeviceTransfer should be true")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(PrimaryRegistrationResponse{
			UUID:   "aci-uuid-123",
			PNI:    "pni-uuid-456",
			Number: "+15551234567",
		})
	}))
	defer srv.Close()

	client := NewHTTPClient(srv.URL, nil, nil)
	resp, err := client.RegisterPrimaryDevice(context.Background(), &PrimaryRegistrationRequest{
		SessionID: "session-123",
		AccountAttributes: AccountAttributes{
			RegistrationID:    12345,
			PNIRegistrationID: 67890,
			FetchesMessages:   true,
		},
		ACIIdentityKey:        "YWNpLWtleQ==",
		PNIIdentityKey:        "cG5pLWtleQ==",
		ACISignedPreKey:       SignedPreKeyEntity{KeyID: 1, PublicKey: "abc", Signature: "def"},
		PNISignedPreKey:       SignedPreKeyEntity{KeyID: 1, PublicKey: "ghi", Signature: "jkl"},
		ACIPqLastResortPreKey: KyberPreKeyEntity{KeyID: 1, PublicKey: "mno", Signature: "pqr"},
		PNIPqLastResortPreKey: KyberPreKeyEntity{KeyID: 1, PublicKey: "stu", Signature: "vwx"},
		SkipDeviceTransfer:    true,
	}, BasicAuth{Username: "+15551234567", Password: "test-password"})
	if err != nil {
		t.Fatal(err)
	}

	if resp.UUID != "aci-uuid-123" {
		t.Errorf("uuid: got %q", resp.UUID)
	}
	if resp.PNI != "pni-uuid-456" {
		t.Errorf("pni: got %q", resp.PNI)
	}
	if resp.Number != "+15551234567" {
		t.Errorf("number: got %q", resp.Number)
	}
}
