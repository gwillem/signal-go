package signalws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

// wsURL converts an httptest server URL to a WebSocket URL.
func wsURL(srv *httptest.Server) string {
	return "ws" + strings.TrimPrefix(srv.URL, "http")
}

// writeProto marshals and writes a protobuf WebSocketMessage to a websocket.Conn.
func writeProto(ctx context.Context, ws *websocket.Conn, msg *proto.WebSocketMessage) error {
	data, err := pb.Marshal(msg)
	if err != nil {
		return err
	}
	return ws.Write(ctx, websocket.MessageBinary, data)
}

// readProto reads and unmarshals a protobuf WebSocketMessage from a websocket.Conn.
func readProto(ctx context.Context, ws *websocket.Conn) (*proto.WebSocketMessage, error) {
	_, data, err := ws.Read(ctx)
	if err != nil {
		return nil, err
	}
	msg := new(proto.WebSocketMessage)
	if err := pb.Unmarshal(data, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

func TestKeepAliveSendsRequest(t *testing.T) {
	var gotKeepAlive atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer ws.CloseNow()

		ctx := r.Context()
		for {
			msg, err := readProto(ctx, ws)
			if err != nil {
				return
			}
			if msg.GetType() == proto.WebSocketMessage_REQUEST &&
				msg.GetRequest().GetVerb() == "GET" &&
				msg.GetRequest().GetPath() == "/v1/keepalive" {
				gotKeepAlive.Store(true)
				// Send response to keep-alive.
				id := msg.GetRequest().GetId()
				resp := &proto.WebSocketMessage{
					Type: proto.WebSocketMessage_RESPONSE.Enum(),
					Response: &proto.WebSocketResponseMessage{
						Id:     &id,
						Status: pb.Uint32(200),
					},
				}
				if err := writeProto(ctx, ws, resp); err != nil {
					return
				}
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pc, err := DialPersistent(ctx, wsURL(srv), nil,
		WithKeepAliveInterval(100*time.Millisecond),
		WithKeepAliveTimeout(50*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// Wait enough time for at least one keep-alive to be sent.
	time.Sleep(250 * time.Millisecond)

	if !gotKeepAlive.Load() {
		t.Fatal("server did not receive a keep-alive request")
	}
}

func TestKeepAliveTimeoutTriggersReconnect(t *testing.T) {
	var connCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer ws.CloseNow()
		connCount.Add(1)

		// Read messages but never respond to keep-alives.
		ctx := r.Context()
		for {
			if _, err := readProto(ctx, ws); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pc, err := DialPersistent(ctx, wsURL(srv), nil,
		WithKeepAliveInterval(50*time.Millisecond),
		WithKeepAliveTimeout(50*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// Wait for keep-alive timeout + reconnect to happen.
	time.Sleep(400 * time.Millisecond)

	if n := connCount.Load(); n < 2 {
		t.Fatalf("expected at least 2 connections (reconnect), got %d", n)
	}
}

func TestKeepAliveResponseConsumed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer ws.CloseNow()

		ctx := r.Context()
		// Read the keep-alive request and respond.
		for {
			msg, err := readProto(ctx, ws)
			if err != nil {
				return
			}
			if msg.GetType() == proto.WebSocketMessage_REQUEST &&
				msg.GetRequest().GetPath() == "/v1/keepalive" {
				id := msg.GetRequest().GetId()
				resp := &proto.WebSocketMessage{
					Type: proto.WebSocketMessage_RESPONSE.Enum(),
					Response: &proto.WebSocketResponseMessage{
						Id:     &id,
						Status: pb.Uint32(200),
					},
				}
				if err := writeProto(ctx, ws, resp); err != nil {
					return
				}
				// Now send a real request for the client.
				verb := "PUT"
				path := "/v1/message"
				reqID := uint64(42)
				body := []byte("hello")
				reqMsg := &proto.WebSocketMessage{
					Type: proto.WebSocketMessage_REQUEST.Enum(),
					Request: &proto.WebSocketRequestMessage{
						Verb: &verb,
						Path: &path,
						Id:   &reqID,
						Body: body,
					},
				}
				if err := writeProto(ctx, ws, reqMsg); err != nil {
					return
				}
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pc, err := DialPersistent(ctx, wsURL(srv), nil,
		WithKeepAliveInterval(50*time.Millisecond),
		WithKeepAliveTimeout(500*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// ReadMessage should skip the keep-alive response and return the real request.
	msg, err := pc.ReadMessage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.GetType() != proto.WebSocketMessage_REQUEST {
		t.Fatalf("expected REQUEST, got %v", msg.GetType())
	}
	if msg.GetRequest().GetPath() != "/v1/message" {
		t.Fatalf("expected /v1/message, got %s", msg.GetRequest().GetPath())
	}
}

func TestReconnectOnDisconnect(t *testing.T) {
	var connCount atomic.Int32
	var mu sync.Mutex
	var conns []*websocket.Conn

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		n := connCount.Add(1)
		mu.Lock()
		conns = append(conns, ws)
		mu.Unlock()

		if n == 1 {
			// First connection: close immediately to trigger reconnect.
			time.Sleep(50 * time.Millisecond)
			ws.Close(websocket.StatusGoingAway, "bye")
			return
		}

		// Second connection: send a message, then keep alive.
		ctx := r.Context()
		verb := "PUT"
		path := "/v1/message"
		reqID := uint64(99)
		reqMsg := &proto.WebSocketMessage{
			Type: proto.WebSocketMessage_REQUEST.Enum(),
			Request: &proto.WebSocketRequestMessage{
				Verb: &verb,
				Path: &path,
				Id:   &reqID,
				Body: []byte("reconnected"),
			},
		}
		if err := writeProto(ctx, ws, reqMsg); err != nil {
			return
		}
		// Keep connection open for reads.
		for {
			if _, err := readProto(ctx, ws); err != nil {
				ws.CloseNow()
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	pc, err := DialPersistent(ctx, wsURL(srv), nil,
		WithKeepAliveInterval(5*time.Second), // long interval, don't interfere
		WithKeepAliveTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	// ReadMessage should reconnect after first connection closes, then read from second.
	msg, err := pc.ReadMessage(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.GetRequest().GetBody()) != "reconnected" {
		t.Fatalf("expected 'reconnected', got %q", string(msg.GetRequest().GetBody()))
	}
}

func TestReconnectPreservesURL(t *testing.T) {
	var urls []string
	var mu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		urls = append(urls, r.URL.String())
		mu.Unlock()

		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer ws.CloseNow()

		// Close after a short delay to trigger reconnect.
		time.Sleep(50 * time.Millisecond)
		ws.Close(websocket.StatusGoingAway, "bye")
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pc, err := DialPersistent(ctx, wsURL(srv)+"/test?foo=bar", nil,
		WithKeepAliveInterval(50*time.Millisecond),
		WithKeepAliveTimeout(50*time.Millisecond),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Start a ReadMessage in the background to trigger reconnect on disconnect.
	go func() { pc.ReadMessage(ctx) }()

	// Wait for reconnect to happen.
	time.Sleep(500 * time.Millisecond)
	pc.Close()

	mu.Lock()
	defer mu.Unlock()
	if len(urls) < 2 {
		t.Fatalf("expected at least 2 connections, got %d", len(urls))
	}
	for i, u := range urls {
		if u != "/test?foo=bar" {
			t.Fatalf("connection %d: expected /test?foo=bar, got %s", i, u)
		}
	}
}

func TestCloseStopsReconnect(t *testing.T) {
	var connCount atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		connCount.Add(1)
		defer ws.CloseNow()

		// Keep connection open.
		ctx := r.Context()
		for {
			if _, err := readProto(ctx, ws); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	pc, err := DialPersistent(ctx, wsURL(srv), nil,
		WithKeepAliveInterval(5*time.Second),
		WithKeepAliveTimeout(5*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}

	// Close and wait, verify no further connections.
	pc.Close()
	before := connCount.Load()
	time.Sleep(200 * time.Millisecond)
	after := connCount.Load()

	if after != before {
		t.Fatalf("expected no new connections after Close(), got %d -> %d", before, after)
	}
}
