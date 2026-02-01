package signalservice

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/coder/websocket"
	"github.com/gwillem/signal-go/pkg/libsignal"
	"github.com/gwillem/signal-go/pkg/proto"
	"github.com/gwillem/signal-go/pkg/provisioncrypto"
	pb "google.golang.org/protobuf/proto"
)

type testCallbacks struct {
	mu      sync.Mutex
	linkURI string
	ch      chan string // signals when URI is available
}

func newTestCallbacks() *testCallbacks {
	return &testCallbacks{ch: make(chan string, 1)}
}

func (tc *testCallbacks) OnLinkURI(uri string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.linkURI = uri
	tc.ch <- uri
}

// pkcs7PadForTest duplicates PKCS7 padding for test use.
func pkcs7PadForTest(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	padding := make([]byte, pad)
	for i := range padding {
		padding[i] = byte(pad)
	}
	return append(data, padding...)
}

// extractPubKeyFromURI parses the pub_key from a device link URI.
func extractPubKeyFromURI(uri string) ([]byte, error) {
	parts := strings.SplitN(uri, "pub_key=", 2)
	return base64.URLEncoding.DecodeString(parts[1])
}

func TestRunProvisioningEndToEnd(t *testing.T) {
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
		uri := <-cb.ch
		pubKey, err := extractPubKeyFromURI(uri)
		if err != nil {
			t.Errorf("extract pubkey: %v", err)
			return
		}
		pubKeyCh <- pubKey
	}()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

		// Wait for secondary's public key (extracted from link URI callback after QR display).
		secondaryPubKeyBytes := <-pubKeyCh

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
		rand.Read(iv)

		padded := pkcs7PadForTest(provMsgBytes, 16)
		ct := make([]byte, len(padded))
		block, _ := aes.NewCipher(cipherKey)
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
		envBytes, _ := pb.Marshal(env)

		// Step 2: Send encrypted provision envelope.
		sendWSRequest(t, ws, ctx, "PUT", "/v1/message", 2, envBytes)
		readWSResponse(t, ws, ctx, 2)

		ws.Close(websocket.StatusNormalClosure, "done")
	}))
	defer srv.Close()

	ctx := context.Background()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	result, err := RunProvisioning(ctx, wsURL, cb)
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
