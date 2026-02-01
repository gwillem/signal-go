package signalservice

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
	pb "google.golang.org/protobuf/proto"
)

type testCallbacks struct {
	ch chan string // signals when URI is available
}

func newTestCallbacks() *testCallbacks {
	return &testCallbacks{ch: make(chan string, 1)}
}

func (tc *testCallbacks) OnLinkURI(uri string) {
	tc.ch <- uri
}

// extractPubKeyFromURI parses the pub_key from a device link URI.
func extractPubKeyFromURI(uri string) ([]byte, error) {
	parts := strings.SplitN(uri, "pub_key=", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("pub_key= not found in URI: %s", uri)
	}
	// The pub_key value is URL-escaped standard base64 (no padding).
	unescaped, err := url.QueryUnescape(parts[1])
	if err != nil {
		return nil, fmt.Errorf("unescape pub_key: %w", err)
	}
	return base64.RawStdEncoding.DecodeString(unescaped)
}

func TestRunProvisioningEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

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

	// Provision message payload.
	number := "+15551234567"
	code := "provision-code-xyz"
	aciStr := "aci-uuid-1234"
	provMsg := &proto.ProvisionMessage{
		Number:                &number,
		ProvisioningCode:      &code,
		Aci:                   &aciStr,
		AciIdentityKeyPublic:  []byte{0x05, 0x01, 0x02},
		AciIdentityKeyPrivate: []byte{0x03, 0x04},
	}
	provMsgBytes, err := pb.Marshal(provMsg)
	if err != nil {
		t.Fatal(err)
	}

	testUUID := "test-provisioning-uuid-42"
	cb := newTestCallbacks()

	// Channel to pass the secondary's public key from the callback to the server goroutine.
	pubKeyCh := make(chan []byte, 1)

	// Start reading link URI in a goroutine to extract the public key.
	go func() {
		select {
		case uri := <-cb.ch:
			pubKey, err := extractPubKeyFromURI(uri)
			if err != nil {
				t.Errorf("extract pubkey: %v", err)
				return
			}
			pubKeyCh <- pubKey
		case <-ctx.Done():
			return
		}
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer ws.CloseNow()

		// Step 1: Send ProvisioningAddress.
		addr := &proto.ProvisioningAddress{Address: &testUUID}
		addrBytes, err := pb.Marshal(addr)
		if err != nil {
			t.Errorf("marshal address: %v", err)
			return
		}
		sendWSRequest(t, ws, ctx, "PUT", "/v1/address", 1, addrBytes)
		readWSResponse(t, ws, ctx, 1)

		// Wait for secondary's public key (extracted from link URI callback after QR display).
		var secondaryPubKeyBytes []byte
		select {
		case secondaryPubKeyBytes = <-pubKeyCh:
		case <-ctx.Done():
			t.Errorf("timed out waiting for secondary public key")
			return
		}

		secondaryPub, err := libsignal.DeserializePublicKey(secondaryPubKeyBytes)
		if err != nil {
			t.Errorf("deserialize secondary pub: %v", err)
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
			t.Errorf("rand read: %v", err)
			return
		}

		padded := provisioncrypto.PKCS7Pad(provMsgBytes, 16)
		ct := make([]byte, len(padded))
		block, err := aes.NewCipher(cipherKey)
		if err != nil {
			t.Errorf("new cipher: %v", err)
			return
		}
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

		body := make([]byte, 0, 1+16+len(ct)+32)
		body = append(body, 0x01)
		body = append(body, iv...)
		body = append(body, ct...)
		mac := provisioncrypto.ComputeMAC(macKey, body)
		body = append(body, mac...)

		env := &proto.ProvisionEnvelope{
			PublicKey: primaryPubBytes,
			Body:      body,
		}
		envBytes, err := pb.Marshal(env)
		if err != nil {
			t.Errorf("marshal envelope: %v", err)
			return
		}

		// Step 2: Send encrypted provision envelope.
		sendWSRequest(t, ws, ctx, "PUT", "/v1/message", 2, envBytes)
		readWSResponse(t, ws, ctx, 2)

		ws.Close(websocket.StatusNormalClosure, "done")
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	result, err := RunProvisioning(ctx, wsURL, cb, nil)
	if err != nil {
		t.Fatal(err)
	}

	if result.Data.Number != number {
		t.Fatalf("number: got %q, want %q", result.Data.Number, number)
	}
	if result.Data.ProvisioningCode != code {
		t.Fatalf("code: got %q, want %q", result.Data.ProvisioningCode, code)
	}
	if result.Data.ACI != aciStr {
		t.Fatalf("aci: got %q, want %q", result.Data.ACI, aciStr)
	}
	if !strings.Contains(result.LinkURI, testUUID) {
		t.Fatalf("link URI should contain UUID: %s", result.LinkURI)
	}
}

// sendWSRequest sends a protobuf WebSocket request message.
func sendWSRequest(t *testing.T, ws *websocket.Conn, ctx context.Context, verb, path string, id uint64, body []byte) {
	t.Helper()
	msg := &proto.WebSocketMessage{
		Type: proto.WebSocketMessage_REQUEST.Enum(),
		Request: &proto.WebSocketRequestMessage{
			Verb: &verb,
			Path: &path,
			Id:   &id,
			Body: body,
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
