package signalservice

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/gwillem/signal-go/internal/libsignal"
	"github.com/gwillem/signal-go/internal/proto"
	"github.com/gwillem/signal-go/internal/provisioncrypto"
	"github.com/gwillem/signal-go/internal/signalws"
	pb "google.golang.org/protobuf/proto"
)

// provisionResult holds the output of a successful provisioning flow.
type provisionResult struct {
	Data    *provisioncrypto.ProvisionData
	LinkURI string
}

// provisionCallbacks allows callers to react to provisioning events.
type provisionCallbacks interface {
	// OnLinkURI is called when the device link URI is ready (for QR code display).
	OnLinkURI(uri string)
}

// RunProvisioning connects to the provisioning WebSocket, receives the
// provisioning address (UUID), builds a link URI, waits for the encrypted
// provision envelope from the primary device, and decrypts it.
func RunProvisioning(ctx context.Context, wsURL string, cb provisionCallbacks, tlsConf *tls.Config) (*provisionResult, error) {
	// Generate ephemeral key pair for provisioning.
	privKey, err := libsignal.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("provisioning: generate key: %w", err)
	}
	defer privKey.Destroy()

	pubKey, err := privKey.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("provisioning: public key: %w", err)
	}
	defer pubKey.Destroy()

	pubKeyBytes, err := pubKey.Serialize()
	if err != nil {
		return nil, fmt.Errorf("provisioning: serialize public key: %w", err)
	}

	conn, err := signalws.Dial(ctx, wsURL, tlsConf)
	if err != nil {
		return nil, fmt.Errorf("provisioning: %w", err)
	}
	defer conn.Close()

	// Step 1: Read ProvisioningAddress from server.
	uuid, reqID, err := readProvisioningAddress(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := conn.SendResponse(ctx, reqID, 200, "OK"); err != nil {
		return nil, fmt.Errorf("provisioning: ACK address: %w", err)
	}

	// Build and emit the link URI.
	uri := deviceLinkURI(uuid, pubKeyBytes)
	if cb != nil {
		cb.OnLinkURI(uri)
	}

	// Step 2: Read ProvisionEnvelope from primary.
	envelope, reqID, err := readProvisionEnvelope(ctx, conn)
	if err != nil {
		return nil, err
	}
	if err := conn.SendResponse(ctx, reqID, 200, "OK"); err != nil {
		return nil, fmt.Errorf("provisioning: ACK envelope: %w", err)
	}

	// Step 3: Decrypt.
	plaintext, err := provisioncrypto.DecryptProvisionEnvelope(privKey, envelope.GetPublicKey(), envelope.GetBody())
	if err != nil {
		return nil, fmt.Errorf("provisioning: decrypt: %w", err)
	}

	data, err := provisioncrypto.ParseProvisionData(plaintext)
	if err != nil {
		return nil, fmt.Errorf("provisioning: parse: %w", err)
	}

	return &provisionResult{Data: data, LinkURI: uri}, nil
}

func readProvisioningAddress(ctx context.Context, conn *signalws.Conn) (uuid string, reqID uint64, err error) {
	msg, err := conn.ReadMessage(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("provisioning: read address: %w", err)
	}
	if msg.GetType() != proto.WebSocketMessage_REQUEST {
		return "", 0, fmt.Errorf("provisioning: expected REQUEST, got %v", msg.GetType())
	}
	req := msg.GetRequest()
	if req.GetPath() != "/v1/address" || req.GetVerb() != "PUT" {
		return "", 0, fmt.Errorf("provisioning: unexpected request: %s %s", req.GetVerb(), req.GetPath())
	}

	addr := new(proto.ProvisioningAddress)
	if err := pb.Unmarshal(req.GetBody(), addr); err != nil {
		return "", 0, fmt.Errorf("provisioning: unmarshal address: %w", err)
	}

	return addr.GetAddress(), req.GetId(), nil
}

func readProvisionEnvelope(ctx context.Context, conn *signalws.Conn) (*proto.ProvisionEnvelope, uint64, error) {
	msg, err := conn.ReadMessage(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("provisioning: read envelope: %w", err)
	}
	if msg.GetType() != proto.WebSocketMessage_REQUEST {
		return nil, 0, fmt.Errorf("provisioning: expected REQUEST, got %v", msg.GetType())
	}
	req := msg.GetRequest()
	if req.GetPath() != "/v1/message" || req.GetVerb() != "PUT" {
		return nil, 0, fmt.Errorf("provisioning: unexpected request: %s %s", req.GetVerb(), req.GetPath())
	}

	env := new(proto.ProvisionEnvelope)
	if err := pb.Unmarshal(req.GetBody(), env); err != nil {
		return nil, 0, fmt.Errorf("provisioning: unmarshal envelope: %w", err)
	}

	return env, req.GetId(), nil
}
