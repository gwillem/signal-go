package signalws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/gwillem/signal-go/internal/proto"
	pb "google.golang.org/protobuf/proto"
)

func TestReadAndACK(t *testing.T) {
	// Server sends a request message; client reads it and sends an ACK.
	verb := "PUT"
	path := "/v1/address"
	reqID := uint64(1)
	bodyBytes := []byte("test-body")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept: %v", err)
			return
		}
		defer ws.CloseNow()

		// Send a request message.
		reqMsg := &proto.WebSocketMessage{
			Type: proto.WebSocketMessage_REQUEST.Enum(),
			Request: &proto.WebSocketRequestMessage{
				Verb: &verb,
				Path: &path,
				Id:   &reqID,
				Body: bodyBytes,
			},
		}
		data, err := pb.Marshal(reqMsg)
		if err != nil {
			t.Errorf("marshal: %v", err)
			return
		}
		if err := ws.Write(r.Context(), websocket.MessageBinary, data); err != nil {
			t.Errorf("write: %v", err)
			return
		}

		// Read the ACK response.
		_, respData, err := ws.Read(r.Context())
		if err != nil {
			t.Errorf("read: %v", err)
			return
		}
		respMsg := new(proto.WebSocketMessage)
		if err := pb.Unmarshal(respData, respMsg); err != nil {
			t.Errorf("unmarshal resp: %v", err)
			return
		}
		if respMsg.GetType() != proto.WebSocketMessage_RESPONSE {
			t.Errorf("expected RESPONSE, got %v", respMsg.GetType())
		}
		if respMsg.GetResponse().GetId() != reqID {
			t.Errorf("response id: got %d, want %d", respMsg.GetResponse().GetId(), reqID)
		}
		if respMsg.GetResponse().GetStatus() != 200 {
			t.Errorf("response status: got %d, want 200", respMsg.GetResponse().GetStatus())
		}

		ws.Close(websocket.StatusNormalClosure, "done")
	}))
	defer srv.Close()

	ctx := context.Background()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	conn, err := Dial(ctx, wsURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg, err := conn.ReadMessage(ctx)
	if err != nil {
		t.Fatal(err)
	}

	if msg.GetType() != proto.WebSocketMessage_REQUEST {
		t.Fatalf("expected REQUEST, got %v", msg.GetType())
	}
	if msg.GetRequest().GetVerb() != verb {
		t.Fatalf("verb: got %q, want %q", msg.GetRequest().GetVerb(), verb)
	}
	if msg.GetRequest().GetPath() != path {
		t.Fatalf("path: got %q, want %q", msg.GetRequest().GetPath(), path)
	}
	if string(msg.GetRequest().GetBody()) != string(bodyBytes) {
		t.Fatalf("body mismatch")
	}

	if err := conn.SendResponse(ctx, reqID, 200, "OK"); err != nil {
		t.Fatal(err)
	}
}
