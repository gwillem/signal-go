// Package signalws provides protobuf-framed WebSocket communication
// for the Signal provisioning protocol.
package signalws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/coder/websocket"
	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// Conn wraps a WebSocket connection with protobuf framing.
type Conn struct {
	ws *websocket.Conn
}

// Dial opens a WebSocket connection to the given URL.
// If tlsConf is non-nil, it is used for the TLS handshake.
// Optional HTTP headers are added to the upgrade request.
func Dial(ctx context.Context, url string, tlsConf *tls.Config, headers ...http.Header) (*Conn, error) {
	opts := &websocket.DialOptions{}
	if tlsConf != nil {
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: tlsConf,
			},
		}
	}
	if len(headers) > 0 {
		opts.HTTPHeader = headers[0]
	}
	ws, _, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		return nil, fmt.Errorf("signalws: dial: %w", err)
	}
	return &Conn{ws: ws}, nil
}

// ReadMessage reads and unmarshals a WebSocketMessage from the connection.
func (c *Conn) ReadMessage(ctx context.Context) (*proto.WebSocketMessage, error) {
	_, data, err := c.ws.Read(ctx)
	if err != nil {
		return nil, fmt.Errorf("signalws: read: %w", err)
	}
	msg := new(proto.WebSocketMessage)
	if err := pb.Unmarshal(data, msg); err != nil {
		return nil, fmt.Errorf("signalws: unmarshal: %w", err)
	}
	return msg, nil
}

// WriteMessage marshals and sends a WebSocketMessage.
func (c *Conn) WriteMessage(ctx context.Context, msg *proto.WebSocketMessage) error {
	data, err := pb.Marshal(msg)
	if err != nil {
		return fmt.Errorf("signalws: marshal: %w", err)
	}
	if err := c.ws.Write(ctx, websocket.MessageBinary, data); err != nil {
		return fmt.Errorf("signalws: write: %w", err)
	}
	return nil
}

// SendResponse sends a WebSocket response message (used for ACKs).
func (c *Conn) SendResponse(ctx context.Context, id uint64, status uint32, message string) error {
	msg := &proto.WebSocketMessage{
		Type: proto.WebSocketMessage_RESPONSE.Enum(),
		Response: &proto.WebSocketResponseMessage{
			Id:      &id,
			Status:  &status,
			Message: &message,
		},
	}
	return c.WriteMessage(ctx, msg)
}

// Close sends a normal closure frame and then closes the connection.
func (c *Conn) Close() error {
	return c.ws.Close(websocket.StatusNormalClosure, "")
}

// CloseNow closes the connection immediately without a close frame.
func (c *Conn) CloseNow() error {
	return c.ws.CloseNow()
}
