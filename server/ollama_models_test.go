package server

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParseOllamaShow(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		tools *bool
		ctx   int
	}{
		{"capabilities with tools", `{"capabilities":["completion","tools"],"model_info":{"qwen3.context_length":40960}}`, ptr(true), 40960},
		{"capabilities without tools", `{"capabilities":["completion","vision"],"model_info":{"gemma3.context_length":131072}}`, ptr(false), 131072},
		{"old server, tools template", `{"template":"{{- if .Tools }}...{{ end }}"}`, ptr(true), 0},
		{"old server, plain template", `{"template":"{{ .Prompt }}"}`, ptr(false), 0},
		{"nothing said", `{}`, nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tools, ctx, ok := parseOllamaShow([]byte(tc.body))
			if !ok {
				t.Fatal("parse failed")
			}
			if (tools == nil) != (tc.tools == nil) || (tools != nil && *tools != *tc.tools) {
				t.Fatalf("tools = %v, want %v", deref(tools), deref(tc.tools))
			}
			if ctx != tc.ctx {
				t.Fatalf("context length = %d, want %d", ctx, tc.ctx)
			}
		})
	}
}

func ptr(b bool) *bool { return &b }

func deref(b *bool) any {
	if b == nil {
		return nil
	}
	return *b
}

// Listing models from the default local Ollama adds tool support and size per
// model from the native API.
func TestListModelsOllamaDetails(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/models":
			_, _ = w.Write([]byte(`{"data":[{"id":"qwen3:14b"},{"id":"gemma3:12b"},{"id":"mystery:1b"}]}`))
		case "/api/tags":
			_, _ = w.Write([]byte(`{"models":[{"name":"qwen3:14b","size":9276198565,"details":{"parameter_size":"14.8B","quantization_level":"Q4_K_M"}},{"name":"gemma3:12b","size":8149190253,"details":{"parameter_size":"12.2B","quantization_level":"Q4_K_M"}}]}`))
		case "/api/show":
			body, _ := io.ReadAll(r.Body)
			var req struct {
				Model string `json:"model"`
			}
			_ = json.Unmarshal(body, &req)
			switch req.Model {
			case "qwen3:14b":
				_, _ = w.Write([]byte(`{"capabilities":["completion","tools","thinking"],"model_info":{"qwen3.context_length":40960}}`))
			case "gemma3:12b":
				_, _ = w.Write([]byte(`{"capabilities":["completion","vision"],"model_info":{"gemma3.context_length":131072}}`))
			default:
				http.Error(w, `{"error":"not found"}`, http.StatusNotFound)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(fake.Close)

	s := &Server{}
	s.modelDialContext = dialTestServerForHosts(
		map[string]string{"127.0.0.1:11434": fake.Listener.Addr().String()},
		(&net.Dialer{Control: newModelURLGuard(s).blockDial}).DialContext,
	)
	resp := postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{"provider": "ollama", "base_url": "", "api_key": ""})
	if resp["ok"] != true {
		t.Fatalf("ok = %v: %v", resp["ok"], resp)
	}
	details, _ := resp["details"].(map[string]any)
	qwen, _ := details["qwen3:14b"].(map[string]any)
	gemma, _ := details["gemma3:12b"].(map[string]any)
	if qwen["tools"] != true || qwen["size_bytes"] != float64(9276198565) || qwen["parameter_size"] != "14.8B" || qwen["context_length"] != float64(40960) {
		t.Fatalf("qwen3 details = %v", qwen)
	}
	if gemma["tools"] != false {
		t.Fatalf("gemma3 should be flagged without tools: %v", gemma)
	}
	if m, ok := details["mystery:1b"]; ok {
		if mm, _ := m.(map[string]any); mm["tools"] != nil {
			t.Fatalf("unknown model must not claim a tools value: %v", mm)
		}
	}
}

// Other providers' responses are unchanged: no details key.
func TestListModelsNoDetailsForOpenAI(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"gpt-x"}]}`))
	}))
	t.Cleanup(fake.Close)
	s := &Server{}
	s.modelDialContext = dialTestServerForHosts(
		map[string]string{"api.openai.com:443": fake.Listener.Addr().String()},
		(&net.Dialer{Control: newModelURLGuard(s).blockDial}).DialContext,
	)
	resp := postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{"provider": "openai", "base_url": "http://api.openai.com:443/v1", "api_key": "k"})
	if _, ok := resp["details"]; ok {
		t.Fatalf("openai response gained details: %v", resp)
	}
}
