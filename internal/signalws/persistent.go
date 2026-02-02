package signalws

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gwillem/signal-go/internal/proto"
)

const (
	defaultKeepAliveInterval = 30 * time.Second
	defaultKeepAliveTimeout  = 20 * time.Second
)

// PersistentConn wraps a Conn with keep-alive heartbeats and automatic reconnection.
type PersistentConn struct {
	mu      sync.Mutex
	conn    *Conn
	url     string
	tlsConf *tls.Config
	headers http.Header
	closed  atomic.Bool

	keepAliveInterval time.Duration
	keepAliveTimeout  time.Duration
	keepAliveCallback func(rtt time.Duration) // called on successful keep-alive

	// pendingKeepAlive tracks the ID of an outstanding keep-alive request.
	pendingKeepAlive atomic.Uint64
	keepAliveSentAt  atomic.Int64   // UnixMilli when keep-alive was sent
	keepAliveAcked   chan struct{}   // signaled when keep-alive response received

	cancel context.CancelFunc // cancels the keep-alive goroutine
}

// Option configures a PersistentConn.
type Option func(*PersistentConn)

// WithKeepAliveInterval sets the interval between keep-alive requests.
func WithKeepAliveInterval(d time.Duration) Option {
	return func(pc *PersistentConn) { pc.keepAliveInterval = d }
}

// WithKeepAliveTimeout sets how long to wait for a keep-alive response before reconnecting.
func WithKeepAliveTimeout(d time.Duration) Option {
	return func(pc *PersistentConn) { pc.keepAliveTimeout = d }
}

// WithKeepAliveCallback sets a function called on each successful keep-alive round-trip.
func WithKeepAliveCallback(fn func(rtt time.Duration)) Option {
	return func(pc *PersistentConn) { pc.keepAliveCallback = fn }
}

// WithHeaders sets HTTP headers for the WebSocket upgrade request.
func WithHeaders(h http.Header) Option {
	return func(pc *PersistentConn) { pc.headers = h }
}

// DialPersistent dials a WebSocket and returns a PersistentConn with keep-alive and reconnect.
func DialPersistent(ctx context.Context, url string, tlsConf *tls.Config, opts ...Option) (*PersistentConn, error) {
	pc := &PersistentConn{
		url:               url,
		tlsConf:           tlsConf,
		keepAliveInterval: defaultKeepAliveInterval,
		keepAliveTimeout:  defaultKeepAliveTimeout,
		keepAliveAcked:    make(chan struct{}, 1),
	}
	for _, o := range opts {
		o(pc)
	}

	conn, err := Dial(ctx, url, tlsConf, pc.headers)
	if err != nil {
		return nil, err
	}
	pc.conn = conn

	kaCtx, kaCancel := context.WithCancel(context.Background())
	pc.cancel = kaCancel
	go pc.keepAliveLoop(kaCtx)

	return pc, nil
}

// ReadMessage reads the next message, filtering out keep-alive responses.
// On read error, it attempts to reconnect and retry.
func (pc *PersistentConn) ReadMessage(ctx context.Context) (*proto.WebSocketMessage, error) {
	for {
		pc.mu.Lock()
		conn := pc.conn
		pc.mu.Unlock()

		if conn == nil {
			if pc.closed.Load() {
				return nil, fmt.Errorf("signalws: persistent conn closed")
			}
			if err := pc.reconnect(ctx); err != nil {
				return nil, err
			}
			continue
		}

		msg, err := conn.ReadMessage(ctx)
		if err != nil {
			if pc.closed.Load() {
				return nil, err
			}
			// Connection broken, try reconnect.
			if reconnErr := pc.reconnect(ctx); reconnErr != nil {
				return nil, reconnErr
			}
			continue
		}

		// Filter keep-alive responses.
		if msg.GetType() == proto.WebSocketMessage_RESPONSE {
			pendingID := pc.pendingKeepAlive.Load()
			if pendingID != 0 && msg.GetResponse().GetId() == pendingID {
				pc.handleKeepAliveResponse()
				continue
			}
		}

		return msg, nil
	}
}

// WriteMessage writes a message to the current connection.
func (pc *PersistentConn) WriteMessage(ctx context.Context, msg *proto.WebSocketMessage) error {
	pc.mu.Lock()
	conn := pc.conn
	pc.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("signalws: no active connection")
	}
	return conn.WriteMessage(ctx, msg)
}

// SendResponse sends an ACK response message.
func (pc *PersistentConn) SendResponse(ctx context.Context, id uint64, status uint32, message string) error {
	pc.mu.Lock()
	conn := pc.conn
	pc.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("signalws: no active connection")
	}
	return conn.SendResponse(ctx, id, status, message)
}

// Close stops keep-alive and closes the connection. No further reconnects will happen.
func (pc *PersistentConn) Close() error {
	if pc.closed.Swap(true) {
		return nil // already closed
	}
	pc.cancel()
	pc.mu.Lock()
	conn := pc.conn
	pc.conn = nil
	pc.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (pc *PersistentConn) keepAliveLoop(ctx context.Context) {
	ticker := time.NewTicker(pc.keepAliveInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if pc.closed.Load() {
				return
			}
			if err := pc.sendKeepAlive(ctx); err != nil {
				// Connection may be broken; reconnect will happen on next ReadMessage.
				continue
			}
			// Wait for response or timeout.
			select {
			case <-ctx.Done():
				return
			case <-pc.keepAliveAcked:
				// Got response, all good.
			case <-time.After(pc.keepAliveTimeout):
				// Timeout — force reconnect.
				if !pc.closed.Load() {
					_ = pc.reconnect(ctx)
				}
			}
		}
	}
}

func (pc *PersistentConn) sendKeepAlive(ctx context.Context) error {
	id := uint64(time.Now().UnixMilli())
	pc.pendingKeepAlive.Store(id)

	// Drain any stale ack.
	select {
	case <-pc.keepAliveAcked:
	default:
	}

	verb := "GET"
	path := "/v1/keepalive"
	msg := &proto.WebSocketMessage{
		Type: proto.WebSocketMessage_REQUEST.Enum(),
		Request: &proto.WebSocketRequestMessage{
			Id:   &id,
			Verb: &verb,
			Path: &path,
		},
	}

	pc.keepAliveSentAt.Store(time.Now().UnixMilli())

	pc.mu.Lock()
	conn := pc.conn
	pc.mu.Unlock()
	if conn == nil {
		return fmt.Errorf("signalws: no active connection")
	}
	return conn.WriteMessage(ctx, msg)
}

func (pc *PersistentConn) handleKeepAliveResponse() {
	if pc.keepAliveCallback != nil {
		sentAt := pc.keepAliveSentAt.Load()
		if sentAt > 0 {
			rtt := time.Duration(time.Now().UnixMilli()-sentAt) * time.Millisecond
			pc.keepAliveCallback(rtt)
		}
	}
	pc.pendingKeepAlive.Store(0)
	select {
	case pc.keepAliveAcked <- struct{}{}:
	default:
	}
}

func (pc *PersistentConn) reconnect(ctx context.Context) error {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	if pc.closed.Load() {
		return fmt.Errorf("signalws: persistent conn closed")
	}

	// Close old connection if any.
	if pc.conn != nil {
		pc.conn.CloseNow()
		pc.conn = nil
	}

	conn, err := Dial(ctx, pc.url, pc.tlsConf, pc.headers)
	if err != nil {
		return fmt.Errorf("signalws: reconnect: %w", err)
	}
	pc.conn = conn
	return nil
}
