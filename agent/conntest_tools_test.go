package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestConnectionSendsNoTools checks that the connection test request carries no
// tool schemas. The SDK adds its background-task tools unless they are disabled,
// and with tools present some models answer "ping" with tool calls instead of OK.
func TestConnectionSendsNoTools(t *testing.T) {
	var gotTools any
	var called bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		body, _ := io.ReadAll(r.Body)
		var req map[string]any
		_ = json.Unmarshal(body, &req)
		gotTools = req["tools"]
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer server.Close()

	cfg := ConfigFrom("openai", "m", server.URL, "k", "")
	cfg.Stream = false
	_, reply, err := TestConnection(context.Background(), cfg)
	if err != nil {
		t.Fatalf("TestConnection: %v", err)
	}
	if !called {
		t.Fatal("no request reached the server")
	}
	if reply != "OK" {
		t.Fatalf("reply = %q, want OK", reply)
	}
	if tools, ok := gotTools.([]any); ok && len(tools) > 0 {
		t.Fatalf("connection test sent %d tool(s), want none: %v", len(tools), tools)
	}
}
