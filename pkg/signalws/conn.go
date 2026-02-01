// Package signalws provides protobuf-framed WebSocket communication
// for the Signal provisioning protocol.
package signalws

import (
	"context"
	"fmt"

	"github.com/gwillem/signal-go/pkg/proto"
	pb "google.golang.org/protobuf/proto"
	"github.com/coder/websocket"
)

// Conn wraps a WebSocket connection with protobuf framing.
type Conn struct {
	ws *websocket.Conn
}

// New wraps an existing WebSocket connection.
func New(ws *websocket.Conn) *Conn {
	return &Conn{ws: ws}
}

// Dial opens a WebSocket connection to the given URL.
func Dial(ctx context.Context, url string) (*Conn, error) {
	ws, _, err := websocket.Dial(ctx, url, nil)
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

// Close closes the underlying WebSocket connection.
func (c *Conn) Close() error {
	return c.ws.CloseNow()
}
