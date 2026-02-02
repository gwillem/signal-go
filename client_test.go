package signal

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
	"github.com/gwillem/signal-go/internal/signalservice"
	"github.com/gwillem/signal-go/internal/store"
	pb "google.golang.org/protobuf/proto"
)

func TestClientLink(t *testing.T) {
	// Primary device key pair.
	primaryPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer primaryPriv.Destroy()

	primaryPub, err := primaryPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer primaryPub.Destroy()

	primaryPubBytes, err := primaryPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Generate real ACI and PNI identity keys for provisioning.
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

	aciPubBytes, err := aciIdentity.PublicKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	aciPrivBytes, err := aciIdentity.PrivateKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pniPubBytes, err := pniIdentity.PublicKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pniPrivBytes, err := pniIdentity.PrivateKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Provision message payload with real keys.
	number := "+15551234567"
	code := "provision-code-xyz"
	aciStr := "aci-uuid-1234"
	pniStr := "pni-uuid-5678"
	provMsg := &proto.ProvisionMessage{
		Number:                &number,
		ProvisioningCode:      &code,
		Aci:                   &aciStr,
		Pni:                   &pniStr,
		AciIdentityKeyPublic:  aciPubBytes,
		AciIdentityKeyPrivate: aciPrivBytes,
		PniIdentityKeyPublic:  pniPubBytes,
		PniIdentityKeyPrivate: pniPrivBytes,
	}
	provMsgBytes, err := pb.Marshal(provMsg)
	if err != nil {
		t.Fatal(err)
	}

	testUUID := "test-provisioning-uuid-42"

	// Channel to pass the secondary's public key from QR callback to server.
	pubKeyCh := make(chan []byte, 1)

	// Mock REST API server for registration.
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/devices/link" && r.Method == http.MethodPut:
			user, pass, ok := r.BasicAuth()
			if !ok || user == "" || pass == "" {
				t.Errorf("missing basic auth on /v1/devices/link")
				w.WriteHeader(401)
				return
			}
			if user != number {
				t.Errorf("basic auth username: got %q, want %q", user, number)
			}
			_ = pass // password is randomly generated

			body, _ := io.ReadAll(r.Body)
			var req signalservice.RegisterRequest
			if err := json.Unmarshal(body, &req); err != nil {
				t.Errorf("unmarshal register: %v", err)
				w.WriteHeader(500)
				return
			}
			if req.VerificationCode != code {
				t.Errorf("verificationCode: got %q, want %q", req.VerificationCode, code)
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(signalservice.RegisterResponse{
				UUID:     aciStr,
				PNI:      pniStr,
				DeviceID: 2,
			})

		case r.URL.Path == "/v2/keys" && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusNoContent)

		case r.URL.Path == "/v1/accounts/attributes/" && r.Method == http.MethodPut:
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Errorf("unexpected API request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer apiSrv.Close()

	// Mock WebSocket server for provisioning.
	wsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer ws.CloseNow()
		ctx := r.Context()

		// Step 1: Send ProvisioningAddress.
		addr := &proto.ProvisioningAddress{Address: &testUUID}
		addrBytes, _ := pb.Marshal(addr)
		sendWSRequest(t, ws, ctx, "PUT", "/v1/address", 1, addrBytes)
		readWSResponse(t, ws, ctx, 1)

		// Wait for secondary's public key.
		secondaryPubKeyBytes := <-pubKeyCh

		secondaryPub, err := libsignal.DeserializePublicKey(secondaryPubKeyBytes)
		if err != nil {
			t.Errorf("deserialize: %v", err)
			return
		}
		defer secondaryPub.Destroy()

		// Primary: ECDH + derive + encrypt.
		sharedSecret, err := primaryPriv.Agree(secondaryPub)
		if err != nil {
			t.Errorf("agree: %v", err)
			return
		}

		cipherKey, macKey, err := provisioncrypto.DeriveProvisioningKeys(sharedSecret)
		if err != nil {
			t.Errorf("derive: %v", err)
			return
		}

		iv := make([]byte, 16)
		if _, err := rand.Read(iv); err != nil {
			t.Errorf("rand: %v", err)
			return
		}

		padded := provisioncrypto.PKCS7Pad(provMsgBytes, 16)
		ct := make([]byte, len(padded))
		block, err := aes.NewCipher(cipherKey)
		if err != nil {
			t.Errorf("cipher: %v", err)
			return
		}
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

		body := make([]byte, 0, 1+16+len(ct)+32)
		body = append(body, 0x01)
		body = append(body, iv...)
		body = append(body, ct...)
		mac := provisioncrypto.ComputeMAC(macKey, body)
		body = append(body, mac...)

		env := &proto.ProvisionEnvelope{PublicKey: primaryPubBytes, Body: body}
		envBytes, _ := pb.Marshal(env)

		// Step 2: Send encrypted provision envelope.
		sendWSRequest(t, ws, ctx, "PUT", "/v1/message", 2, envBytes)
		readWSResponse(t, ws, ctx, 2)

		ws.Close(websocket.StatusNormalClosure, "done")
	}))
	defer wsSrv.Close()

	wsURL := "ws" + strings.TrimPrefix(wsSrv.URL, "http")
	dbPath := filepath.Join(t.TempDir(), "test.db")

	client := NewClient(
		WithProvisioningURL(wsURL),
		WithAPIURL(apiSrv.URL),
		WithTLSConfig(nil),
		WithDBPath(dbPath),
	)
	defer client.Close()

	// Extract pub key from QR URI in callback.
	err = client.Link(context.Background(), func(uri string) {
		parsed, err := url.Parse(uri)
		if err != nil {
			t.Errorf("parse URI: %v", err)
			return
		}
		b64 := parsed.Query().Get("pub_key")
		if b64 == "" {
			t.Errorf("pub_key not found in URI: %s", uri)
			return
		}
		pubKey, err := base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			t.Errorf("decode pubkey: %v", err)
			return
		}
		pubKeyCh <- pubKey
	})
	if err != nil {
		t.Fatal(err)
	}

	if client.Number() != number {
		t.Fatalf("number: got %q, want %q", client.Number(), number)
	}

	if client.DeviceID() != 2 {
		t.Fatalf("deviceId: got %d, want 2", client.DeviceID())
	}

	// Verify credentials were persisted to the DB.
	if client.Store() == nil {
		t.Fatal("store should be open after Link")
	}
	acct, err := client.Store().LoadAccount()
	if err != nil {
		t.Fatal(err)
	}
	if acct == nil {
		t.Fatal("expected account to be persisted")
	}
	if acct.Number != number {
		t.Fatalf("persisted number: got %q, want %q", acct.Number, number)
	}
	if acct.ACI != aciStr {
		t.Fatalf("persisted ACI: got %q, want %q", acct.ACI, aciStr)
	}
	if acct.DeviceID != 2 {
		t.Fatalf("persisted deviceID: got %d, want 2", acct.DeviceID)
	}
}

func TestClientLoad(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// First, create a client with Link and persist credentials.
	// We'll simulate by directly saving an account to the store.
	priv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := priv.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	priv.Destroy()

	pub, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := pub.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := pubKey.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	pub.Destroy()
	pubKey.Destroy()

	// Write account directly to DB.
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	err = s.SaveAccount(&store.Account{
		Number:                "+15551234567",
		ACI:                   "test-aci",
		PNI:                   "test-pni",
		Password:              "test-password",
		DeviceID:              3,
		RegistrationID:        42,
		ACIIdentityKeyPrivate: privBytes,
		ACIIdentityKeyPublic:  pubBytes,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	// Now load from the same DB.
	client := NewClient(WithDBPath(dbPath))
	defer client.Close()

	if err := client.Load(); err != nil {
		t.Fatal(err)
	}

	if client.Number() != "+15551234567" {
		t.Fatalf("number: got %q", client.Number())
	}
	if client.DeviceID() != 3 {
		t.Fatalf("deviceID: got %d", client.DeviceID())
	}
}

func TestClientSend(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// Generate recipient (Bob) keys.
	bobPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPriv.Destroy()

	bobPub, err := bobPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPub.Destroy()

	bobPubBytes, err := bobPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Generate Bob's signed pre-key.
	bobSPKPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobSPKPriv.Destroy()

	bobSPKPub, err := bobSPKPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobSPKPub.Destroy()

	bobSPKPubBytes, err := bobSPKPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	bobSPKSig, err := bobPriv.Sign(bobSPKPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	// Generate Bob's pre-key.
	bobPreKeyPriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPreKeyPriv.Destroy()

	bobPreKeyPub, err := bobPreKeyPriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobPreKeyPub.Destroy()

	bobPreKeyPubBytes, err := bobPreKeyPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	// Generate Bob's Kyber pre-key.
	bobKyberKP, err := libsignal.GenerateKyberKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer bobKyberKP.Destroy()

	bobKyberPub, err := bobKyberKP.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	defer bobKyberPub.Destroy()

	bobKyberPubBytes, err := bobKyberPub.Serialize()
	if err != nil {
		t.Fatal(err)
	}

	bobKyberSig, err := bobPriv.Sign(bobKyberPubBytes)
	if err != nil {
		t.Fatal(err)
	}

	enc := base64.RawStdEncoding.EncodeToString

	var messageSent bool

	// Mock server.
	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v2/keys/bob-aci/1":
			json.NewEncoder(w).Encode(signalservice.PreKeyResponse{
				IdentityKey: enc(bobPubBytes),
				Devices: []signalservice.PreKeyDeviceInfo{
					{
						DeviceID:       1,
						RegistrationID: 42,
						SignedPreKey: &signalservice.SignedPreKeyEntity{
							KeyID:     1,
							PublicKey: enc(bobSPKPubBytes),
							Signature: enc(bobSPKSig),
						},
						PreKey: &signalservice.PreKeyEntity{
							KeyID:     100,
							PublicKey: enc(bobPreKeyPubBytes),
						},
						PqPreKey: &signalservice.KyberPreKeyEntity{
							KeyID:     200,
							PublicKey: enc(bobKyberPubBytes),
							Signature: enc(bobKyberSig),
						},
					},
				},
			})

		case r.Method == http.MethodPut && r.URL.Path == "/v1/messages/bob-aci":
			messageSent = true
			w.WriteHeader(http.StatusOK)

		default:
			t.Errorf("unexpected: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer apiSrv.Close()

	// Set up client with identity key.
	alicePriv, err := libsignal.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	privBytes, err := alicePriv.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	alicePub, err := alicePriv.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes, err := alicePub.Serialize()
	if err != nil {
		t.Fatal(err)
	}
	alicePriv.Destroy()
	alicePub.Destroy()

	// Write account to DB.
	s, err := store.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	s.SaveAccount(&store.Account{
		Number:                "+15551234567",
		ACI:                   "alice-aci",
		PNI:                   "alice-pni",
		Password:              "password",
		DeviceID:              2,
		RegistrationID:        1,
		ACIIdentityKeyPrivate: privBytes,
		ACIIdentityKeyPublic:  pubBytes,
	})
	s.Close()

	client := NewClient(
		WithDBPath(dbPath),
		WithAPIURL(apiSrv.URL),
		WithTLSConfig(nil),
	)
	defer client.Close()

	if err := client.Load(); err != nil {
		t.Fatal(err)
	}

	if err := client.Send(context.Background(), "bob-aci", "Hello from client!"); err != nil {
		t.Fatal(err)
	}

	if !messageSent {
		t.Fatal("expected message to be sent")
	}
}

// sendWSRequest sends a protobuf WebSocket request message.
func sendWSRequest(t *testing.T, ws *websocket.Conn, ctx context.Context, verb, path string, id uint64, body []byte) {
	t.Helper()
	msg := &proto.WebSocketMessage{
		Type: proto.WebSocketMessage_REQUEST.Enum(),
		Request: &proto.WebSocketRequestMessage{
			Verb: &verb, Path: &path, Id: &id, Body: body,
		},
	}
	data, err := pb.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	if err := ws.Write(ctx, websocket.MessageBinary, data); err != nil {
		t.Fatalf("write request: %v", err)
	}
}

// readWSResponse reads and validates a WebSocket response ACK.
func readWSResponse(t *testing.T, ws *websocket.Conn, ctx context.Context, expectedID uint64) {
	t.Helper()
	_, data, err := ws.Read(ctx)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	msg := new(proto.WebSocketMessage)
	if err := pb.Unmarshal(data, msg); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if msg.GetType() != proto.WebSocketMessage_RESPONSE {
		t.Fatalf("expected RESPONSE, got %v", msg.GetType())
	}
	if msg.GetResponse().GetId() != expectedID {
		t.Fatalf("response id: got %d, want %d", msg.GetResponse().GetId(), expectedID)
	}
}
