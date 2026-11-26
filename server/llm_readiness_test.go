package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestLLMReadinessHTTP runs the readiness test on a stored profile whose model
// writes its tool call as text, then reads the stored result back.
func TestLLMReadinessHTTP(t *testing.T) {
	skipWithoutDSN(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	defer stopTestServer(t, s, cancel)
	clear := func() { _, _ = m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingLLMReadiness) }
	clear()
	t.Cleanup(clear)

	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"{\"name\": \"record_port\", \"arguments\": {}}"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	}))
	defer fake.Close()
	id, err := m.pg.SaveProfile(&db.LLMProfile{Name: "t-readiness", Format: "openai", Model: "text-only", BaseURL: fake.URL, APIKey: "k", Streaming: false})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.pg.Exec(`DELETE FROM llm_profiles WHERE id=$1`, id) })
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string) (int, string) {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec.Code, rec.Body.String()
	}
	key := strconv.FormatInt(id, 10)
	code, body := do(http.MethodPost, "/api/llm/profiles/"+key+"/readiness")
	if code != 200 || !strings.Contains(body, `"verdict":"not_ready"`) || !strings.Contains(body, "as text") {
		t.Fatalf("POST readiness: %d %s", code, body)
	}
	code, body = do(http.MethodGet, "/api/llm/readiness")
	var all map[string]readinessEntry
	if code != 200 || json.Unmarshal([]byte(body), &all) != nil {
		t.Fatalf("GET readiness: %d %s", code, body)
	}
	if e, ok := all[key]; !ok || e.Verdict != "not_ready" || e.Stale {
		t.Fatalf("stored result = %+v (present %v)", e, ok)
	}
	// Changing the model marks the result stale.
	if _, err := m.pg.Exec(`UPDATE llm_profiles SET model='other' WHERE id=$1`, id); err != nil {
		t.Fatal(err)
	}
	_, body = do(http.MethodGet, "/api/llm/readiness")
	_ = json.Unmarshal([]byte(body), &all)
	if !all[key].Stale {
		t.Fatalf("result not stale after a model change: %s", body)
	}
	if code, _ := do(http.MethodPost, "/api/llm/profiles/999999999/readiness"); code != 404 {
		t.Fatalf("unknown profile: %d, want 404", code)
	}
}
