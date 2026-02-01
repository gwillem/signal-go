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
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
	"github.com/gwillem/signal-go/internal/signalservice"
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

	client := NewClient(
		WithProvisioningURL(wsURL),
		WithAPIURL(apiSrv.URL),
	)

	// Extract pub key from QR URI in callback.
	err = client.Link(context.Background(), func(uri string) {
		parts := strings.SplitN(uri, "pub_key=", 2)
		if len(parts) != 2 {
			t.Errorf("pub_key not found in URI: %s", uri)
			return
		}
		pubKey, err := base64.URLEncoding.DecodeString(parts[1])
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
