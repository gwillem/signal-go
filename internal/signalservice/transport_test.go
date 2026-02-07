package signalservice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportPutJSON(t *testing.T) {
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
			t.Error("missing or empty basic auth")
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(RegisterResponse{
			UUID:     "aci-uuid",
			PNI:      "pni-uuid",
			DeviceID: 2,
		})
	}))
	defer srv.Close()

	transport := NewTransport(srv.URL, nil, nil)
	auth := BasicAuth{Username: "+15551234567", Password: "test-password"}

	req := &RegisterRequest{
		VerificationCode: "test-code",
		AccountAttributes: AccountAttributes{
			RegistrationID:    12345,
			PNIRegistrationID: 67890,
			FetchesMessages:   true,
		},
		ACISignedPreKey: SignedPreKeyEntity{KeyID: 1, PublicKey: "abc", Signature: "def"},
		PNISignedPreKey: SignedPreKeyEntity{KeyID: 1, PublicKey: "ghi", Signature: "jkl"},
		ACIPqLastResort: KyberPreKeyEntity{KeyID: 1, PublicKey: "mno", Signature: "pqr"},
		PNIPqLastResort: KyberPreKeyEntity{KeyID: 1, PublicKey: "stu", Signature: "vwx"},
	}

	respBody, status, err := transport.PutJSON(context.Background(), "/v1/devices/link", req, &auth)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200", status)
	}

	var resp RegisterResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatal(err)
	}

	if resp.UUID != "aci-uuid" {
		t.Errorf("uuid: got %q, want %q", resp.UUID, "aci-uuid")
	}
	if resp.DeviceID != 2 {
		t.Errorf("deviceId: got %d, want 2", resp.DeviceID)
	}
}

func TestTransportPostJSON(t *testing.T) {
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

		var req verificationSessionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Number != "+15551234567" {
			t.Errorf("number: got %q, want +15551234567", req.Number)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verificationSessionResponse{
			ID:                   "session-123",
			AllowedToRequestCode: true,
			Verified:             false,
		})
	}))
	defer srv.Close()

	transport := NewTransport(srv.URL, nil, nil)

	req := &verificationSessionRequest{Number: "+15551234567"}
	respBody, status, err := transport.PostJSON(context.Background(), "/v1/verification/session", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200", status)
	}

	var resp verificationSessionResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatal(err)
	}

	if resp.ID != "session-123" {
		t.Errorf("id: got %q, want session-123", resp.ID)
	}
	if !resp.AllowedToRequestCode {
		t.Error("allowedToRequestCode should be true")
	}
}

func TestTransportPatchJSON(t *testing.T) {
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

		var req updateSessionRequest
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if req.Captcha != "captcha-token" {
			t.Errorf("captcha: got %q", req.Captcha)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(verificationSessionResponse{
			ID:                   "session-123",
			AllowedToRequestCode: true,
		})
	}))
	defer srv.Close()

	transport := NewTransport(srv.URL, nil, nil)

	req := &updateSessionRequest{Captcha: "captcha-token"}
	respBody, status, err := transport.PatchJSON(context.Background(), "/v1/verification/session/session-123", req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200", status)
	}

	var resp verificationSessionResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		t.Fatal(err)
	}

	if !resp.AllowedToRequestCode {
		t.Error("allowedToRequestCode should be true after CAPTCHA")
	}
}

func TestTransportGetJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method: got %s, want GET", r.Method)
		}
		if r.URL.Path != "/v1/devices/" {
			t.Errorf("path: got %s", r.URL.Path)
		}

		user, _, ok := r.BasicAuth()
		if !ok {
			t.Error("missing basic auth")
		}
		if user != "aci-uuid.1" {
			t.Errorf("username: got %q", user)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(deviceListResponse{
			Devices: []DeviceInfo{
				{ID: 1, Name: "Primary"},
				{ID: 2, Name: "Secondary"},
			},
		})
	}))
	defer srv.Close()

	transport := NewTransport(srv.URL, nil, nil)
	auth := BasicAuth{Username: "aci-uuid.1", Password: "password"}

	var resp deviceListResponse
	status, err := transport.GetJSON(context.Background(), "/v1/devices/", &auth, &resp)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Fatalf("status: got %d, want 200", status)
	}

	if len(resp.Devices) != 2 {
		t.Errorf("devices: got %d, want 2", len(resp.Devices))
	}
	if resp.Devices[0].Name != "Primary" {
		t.Errorf("device[0].name: got %q", resp.Devices[0].Name)
	}
}
