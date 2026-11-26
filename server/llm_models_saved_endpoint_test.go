package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

// openAIModels is a fake OpenAI-compatible local server (Unsloth, vLLM, LM
// Studio, llama.cpp…) that lists one model for the expected bearer key.
func openAIModels(t *testing.T, key string) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer "+key {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"local-model-a"},{"id":"local-model-b"}]}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// Editing a saved profile that points at a local OpenAI-compatible server can
// list that server's models with the stored key, while a local URL typed into
// the form (no saved profile, or another host:port) keeps the strict policy.
func TestLLMModelsSavedLocalEndpoint(t *testing.T) {
	t.Setenv(LLMPrivateEndpointsEnv, "")
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	t.Cleanup(func() { m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	s.cfgMu.Lock()
	s.llmCfg = agent.Config{}
	s.cfgMu.Unlock()

	saved, savedHits := openAIModels(t, "local-secret")
	other, otherHits := openAIModels(t, "local-secret")
	pid, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: "saved-local", Format: "openai", Model: "local-model-a", BaseURL: saved.URL + "/v1", APIKey: "local-secret",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec("DELETE FROM llm_profiles WHERE id=$1", pid) })

	// The edit form: stored base URL, empty key, the profile id.
	resp := postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{
		"provider": "openai", "base_url": saved.URL + "/v1", "api_key": "", "proxy": "", "profile_id": pid,
	})
	if resp["ok"] != true || savedHits.Load() != 1 {
		t.Fatalf("saved local endpoint not listed: hits=%d resp=%v", savedHits.Load(), resp)
	}
	if ms, _ := resp["models"].([]any); len(ms) != 2 {
		t.Fatalf("models = %v, want the two listed", resp["models"])
	}

	// The same local URL without a saved profile stays refused.
	resp = postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{
		"provider": "openai", "base_url": saved.URL + "/v1", "api_key": "local-secret",
	})
	if resp["ok"] != false || resp["error"] != "endpoint URL host is not allowed" || savedHits.Load() != 1 {
		t.Fatalf("unsaved local endpoint: hits=%d resp=%v, want refused", savedHits.Load(), resp)
	}

	// A saved profile does not open another local host:port typed into the form.
	resp = postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{
		"provider": "openai", "base_url": other.URL + "/v1", "api_key": "local-secret", "profile_id": pid,
	})
	if resp["ok"] != false || otherHits.Load() != 0 {
		t.Fatalf("other local endpoint: hits=%d resp=%v, want refused", otherHits.Load(), resp)
	}

	// Metadata and link-local addresses stay blocked even when saved.
	mid, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: "saved-metadata", Format: "openai", Model: "m", BaseURL: "http://169.254.169.254/v1", APIKey: "k",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec("DELETE FROM llm_profiles WHERE id=$1", mid) })
	resp = postJSON(t, s.pgListModels, "/api/llm/models", map[string]any{
		"provider": "openai", "base_url": "http://169.254.169.254/v1", "api_key": "", "profile_id": mid,
	})
	if resp["ok"] != false || resp["error"] != "endpoint URL host is not allowed" {
		t.Fatalf("saved metadata endpoint answered %v, want refused", resp)
	}
}
