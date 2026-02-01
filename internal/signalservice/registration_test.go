package signalservice

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
)

func TestRegisterLinkedDevice(t *testing.T) {
	// Generate real identity keys for ACI and PNI.
	aciIdentity, err := libsignal.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer aciIdentity.Destroy()

	pniIdentity, err := libsignal.GenerateIdentityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer pniIdentity.Destroy()

	aciPrivBytes, err := aciIdentity.PrivateKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	aciPubBytes, err := aciIdentity.PublicKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pniPrivBytes, err := pniIdentity.PrivateKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pniPubBytes, err := pniIdentity.PublicKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	data := &provisioncrypto.ProvisionData{
		Number:                "+15551234567",
		ProvisioningCode:      "test-provision-code",
		ACI:                   "aci-uuid-1234",
		PNI:                   "pni-uuid-5678",
		ACIIdentityKeyPublic:  aciPubBytes,
		ACIIdentityKeyPrivate: aciPrivBytes,
		PNIIdentityKeyPublic:  pniPubBytes,
		PNIIdentityKeyPrivate: pniPrivBytes,
	}

	var uploadCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/devices/link" && r.Method == http.MethodPut:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
				w.WriteHeader(500)
				return
			}

			var req RegisterRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("unmarshal: %v", err)
				w.WriteHeader(500)
				return
			}

			if req.VerificationCode != "test-provision-code" {
				t.Errorf("verificationCode: got %q", req.VerificationCode)
			}
			if !req.AccountAttributes.FetchesMessages {
				t.Error("fetchesMessages should be true")
			}
			if req.AccountAttributes.RegistrationID == 0 {
				t.Error("registrationId should not be 0")
			}
			if req.AccountAttributes.Name == "" {
				t.Error("name should not be empty")
			}
			if req.ACISignedPreKey.PublicKey == "" {
				t.Error("aciSignedPreKey.publicKey should not be empty")
			}
			if req.ACIPqLastResort.PublicKey == "" {
				t.Error("aciPqLastResortPreKey.publicKey should not be empty")
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(RegisterResponse{
				UUID:     "aci-uuid-1234",
				PNI:      "pni-uuid-5678",
				DeviceID: 2,
			})

		case r.URL.Path == "/v2/keys" && r.Method == http.MethodPut:
			identity := r.URL.Query().Get("identity")
			if identity != "aci" && identity != "pni" {
				t.Errorf("unexpected identity: %q", identity)
				w.WriteHeader(400)
				return
			}

			user, pass, ok := r.BasicAuth()
			if !ok || user == "" || pass == "" {
				t.Error("missing or empty basic auth")
				w.WriteHeader(401)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("read body: %v", err)
				w.WriteHeader(500)
				return
			}

			var upload PreKeyUpload
			if err := json.Unmarshal(body, &upload); err != nil {
				t.Errorf("unmarshal upload: %v", err)
				w.WriteHeader(500)
				return
			}

			if upload.SignedPreKey == nil {
				t.Error("signedPreKey should not be nil")
			}
			if upload.PqLastResortKey == nil {
				t.Error("pqLastResortPreKey should not be nil")
			}

			uploadCount.Add(1)
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	result, err := RegisterLinkedDevice(context.Background(), srv.URL, data, "signal-go-test")
	if err != nil {
		t.Fatal(err)
	}

	if result.DeviceID != 2 {
		t.Fatalf("deviceId: got %d, want 2", result.DeviceID)
	}
	if result.ACI != "aci-uuid-1234" {
		t.Fatalf("ACI: got %q", result.ACI)
	}
	if result.PNI != "pni-uuid-5678" {
		t.Fatalf("PNI: got %q", result.PNI)
	}
	if result.Password == "" {
		t.Fatal("password should not be empty")
	}

	// Should have uploaded keys for both ACI and PNI.
	if got := uploadCount.Load(); got != 2 {
		t.Fatalf("upload count: got %d, want 2", got)
	}
}
