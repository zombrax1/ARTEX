package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestOllamaContextVariantName(t *testing.T) {
	for _, tc := range []struct {
		model string
		ctx   int
		want  string
	}{
		{"qwen3:14b", 32 * 1024, "qwen3:14b-artex-ctx32k"},
		{"llama3.1", 64 * 1024, "llama3.1:latest-artex-ctx64k"},
		{"library/qwen3:8b", 32 * 1024, "library/qwen3:8b-artex-ctx32k"},
		{"hf.co/org/model-GGUF:Q4_K_M", 32 * 1024, "hf.co/org/model-GGUF:Q4_K_M-artex-ctx32k"},
		{"localhost:5000/org/model", 32 * 1024, "localhost:5000/org/model:latest-artex-ctx32k"},
	} {
		if got := ollamaContextVariant(tc.model, tc.ctx); got != tc.want {
			t.Errorf("ollamaContextVariant(%q) = %q, want %q", tc.model, got, tc.want)
		}
	}
}

func TestOllamaNumCtxFloorsAtCompactionWindow(t *testing.T) {
	if got := ollamaNumCtx(8); got != minWindowK*1024 {
		t.Fatalf("ollamaNumCtx(8) = %d, want %d", got, minWindowK*1024)
	}
	if got := ollamaNumCtx(64); got != 64*1024 {
		t.Fatalf("ollamaNumCtx(64) = %d, want %d", got, 64*1024)
	}
}

func TestOllamaContextTransportOnlyForPlainOllamaWithWindow(t *testing.T) {
	if _, ok := newOllamaContextTransport(http.DefaultTransport, "http://h:11434/v1", "m", 0); ok {
		t.Fatal("no context window set: transport must not be used")
	}
	if _, ok := newOllamaContextTransport(http.DefaultTransport, "http://gateway/openai", "m", 32); ok {
		t.Fatal("base URL without /v1: transport must not be used")
	}
	if _, ok := newOllamaContextTransport(http.DefaultTransport, "http://h:11434/v1/", "m", 32); !ok {
		t.Fatal("plain Ollama URL with a window: transport expected")
	}
}

// fakeOllama serves /api/create and /v1/chat/completions and records what it saw.
type fakeOllama struct {
	mu          sync.Mutex
	createCalls int
	createBody  map[string]any
	failCreate  bool
	chatModels  []string
}

func (f *fakeOllama) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/api/create":
			f.createCalls++
			_ = json.Unmarshal(body, &f.createBody)
			if f.failCreate {
				http.Error(w, `{"error":"unknown endpoint"}`, http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(`{"status":"success"}`))
		case "/v1/chat/completions":
			var req struct {
				Model string `json:"model"`
			}
			_ = json.Unmarshal(body, &req)
			f.chatModels = append(f.chatModels, req.Model)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
		default:
			http.NotFound(w, r)
		}
	})
}

func resetOllamaVariants() {
	ollamaVariantsMu.Lock()
	ollamaVariants = map[string]*ollamaVariantState{}
	ollamaVariantsMu.Unlock()
}

// An Ollama profile with a context window sends its chat requests to a variant
// created once with that num_ctx.
func TestOllamaProfileRunsWithItsContextWindow(t *testing.T) {
	resetOllamaVariants()
	f := &fakeOllama{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	cfg := ConfigFrom("ollama", "qwen3:14b", srv.URL, "", "")
	cfg.ContextWindowK = 32
	cfg.Stream = false
	for i := 0; i < 2; i++ {
		if _, reply, err := TestConnection(context.Background(), cfg); err != nil || reply != "OK" {
			t.Fatalf("TestConnection #%d: reply %q err %v", i, reply, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createCalls != 1 {
		t.Fatalf("create calls = %d, want 1", f.createCalls)
	}
	if f.createBody["from"] != "qwen3:14b" || f.createBody["model"] != "qwen3:14b-artex-ctx32k" {
		t.Fatalf("create body = %v", f.createBody)
	}
	params, _ := f.createBody["parameters"].(map[string]any)
	if params["num_ctx"] != float64(32*1024) {
		t.Fatalf("num_ctx = %v, want %d", params["num_ctx"], 32*1024)
	}
	for _, m := range f.chatModels {
		if m != "qwen3:14b-artex-ctx32k" {
			t.Fatalf("chat went to %q, want the variant", m)
		}
	}
}

// A server that cannot create models keeps working with the base model, and is
// not asked again on every request.
func TestOllamaContextFallsBackWhenCreateFails(t *testing.T) {
	resetOllamaVariants()
	f := &fakeOllama{failCreate: true}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	cfg := ConfigFrom("ollama", "llama3.1", srv.URL, "", "")
	cfg.ContextWindowK = 64
	cfg.Stream = false
	for i := 0; i < 2; i++ {
		if _, reply, err := TestConnection(context.Background(), cfg); err != nil || reply != "OK" {
			t.Fatalf("TestConnection #%d: reply %q err %v", i, reply, err)
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createCalls != 1 {
		t.Fatalf("create calls = %d, want 1 (failure must be remembered)", f.createCalls)
	}
	for _, m := range f.chatModels {
		if m != "llama3.1" {
			t.Fatalf("chat went to %q, want the base model", m)
		}
	}
}

func TestOllamaContextRetriesAfterBackoff(t *testing.T) {
	resetOllamaVariants()
	f := &fakeOllama{failCreate: true}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	ct, ok := newOllamaContextTransport(http.DefaultTransport, srv.URL+"/v1", "m", 32)
	if !ok {
		t.Fatal("transport expected")
	}
	now := time.Unix(1000, 0)
	ct.now = func() time.Time { return now }
	if ct.ensureVariant(context.Background()) {
		t.Fatal("create failed: want false")
	}
	f.mu.Lock()
	f.failCreate = false
	f.mu.Unlock()
	if ct.ensureVariant(context.Background()) {
		t.Fatal("inside the backoff: want false without a new create")
	}
	now = now.Add(ollamaCtxRetryAfter + time.Second)
	if !ct.ensureVariant(context.Background()) {
		t.Fatal("after the backoff the create succeeds: want true")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createCalls != 2 {
		t.Fatalf("create calls = %d, want 2", f.createCalls)
	}
}

// Other formats never get the transport, whatever their context window.
func TestContextWindowNotAppliedToOpenAIProfiles(t *testing.T) {
	resetOllamaVariants()
	f := &fakeOllama{}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()

	cfg := ConfigFrom("openai", "gpt-x", srv.URL+"/v1", "k", "")
	cfg.ContextWindowK = 128
	cfg.Stream = false
	if _, reply, err := TestConnection(context.Background(), cfg); err != nil || reply != "OK" {
		t.Fatalf("TestConnection: reply %q err %v", reply, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createCalls != 0 || len(f.chatModels) != 1 || f.chatModels[0] != "gpt-x" {
		t.Fatalf("create calls %d, chat models %v", f.createCalls, f.chatModels)
	}
}
