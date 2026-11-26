package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

type fakeMCPStore struct {
	mu      sync.Mutex
	enabled bool
	tokens  map[string]*db.APIToken // by hash
	audit   []db.MCPAuditEntry
	touched int
}

func (f *fakeMCPStore) GetBool(key string, def bool) bool {
	if key == db.SettingMCPServerEnabled {
		return f.enabled
	}
	return def
}

func (f *fakeMCPStore) APITokenByHash(hash string) (*db.APIToken, error) { return f.tokens[hash], nil }

func (f *fakeMCPStore) TouchAPIToken(int64) error {
	f.mu.Lock()
	f.touched++
	f.mu.Unlock()
	return nil
}

func (f *fakeMCPStore) InsertMCPAudit(e db.MCPAuditEntry) error {
	f.mu.Lock()
	f.audit = append(f.audit, e)
	f.mu.Unlock()
	return nil
}

const (
	testMCPReadToken = db.APITokenPrefix + "read-only-token"
	testMCPAllToken  = db.APITokenPrefix + "all-scopes-token"
	testMCPOldToken  = db.APITokenPrefix + "revoked-token"
)

func newMCPTestServer(enabled bool) (*Server, *fakeMCPStore) {
	revoked := time.Now().Add(-time.Hour)
	store := &fakeMCPStore{enabled: enabled, tokens: map[string]*db.APIToken{
		db.HashAPIToken(testMCPReadToken): {ID: 1, Name: "reader", Scopes: []string{db.APIScopeRead}},
		db.HashAPIToken(testMCPAllToken):  {ID: 2, Name: "all", Scopes: db.APIScopes},
		db.HashAPIToken(testMCPOldToken):  {ID: 3, Name: "old", Scopes: db.APIScopes, RevokedAt: &revoked},
	}}
	return &Server{mcpStoreOverride: store}, store
}

func mcpCall(t *testing.T, s *Server, token, body string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, mcpEndpointPath, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.serveMCP(rec, req)
	return rec
}

func decodeRPC(t *testing.T, rec *httptest.ResponseRecorder) mcpRPCResponse {
	t.Helper()
	var out mcpRPCResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode %q: %v", rec.Body.String(), err)
	}
	return out
}

func TestMCPServerOffAnswersNotFound(t *testing.T) {
	s, _ := newMCPTestServer(false)
	rec := mcpCall(t, s, testMCPAllToken, `{"jsonrpc":"2.0","id":1,"method":"ping"}`, nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled endpoint: status %d, want 404", rec.Code)
	}
}

func TestMCPServerAuthentication(t *testing.T) {
	s, _ := newMCPTestServer(true)
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	for name, token := range map[string]string{
		"missing":    "",
		"wrong form": "not-an-artex-token",
		"unknown":    db.APITokenPrefix + "nope",
		"revoked":    testMCPOldToken,
	} {
		rec := mcpCall(t, s, token, ping, nil)
		if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%s token: status %d (header %q), want 401 with WWW-Authenticate", name, rec.Code, rec.Header().Get("WWW-Authenticate"))
		}
	}
	// A token in the query string or a cookie is ignored.
	req := httptest.NewRequest(http.MethodPost, mcpEndpointPath+"?access_token="+testMCPAllToken, strings.NewReader(ping))
	req.AddCookie(&http.Cookie{Name: "artex_token", Value: testMCPAllToken})
	rec := httptest.NewRecorder()
	s.serveMCP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("token outside the Authorization header: status %d, want 401", rec.Code)
	}
	if rec := mcpCall(t, s, testMCPReadToken, ping, nil); rec.Code != 200 {
		t.Fatalf("valid token: status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestMCPServerRefusesCrossOriginBrowsers(t *testing.T) {
	s, _ := newMCPTestServer(true)
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	if rec := mcpCall(t, s, testMCPAllToken, ping, map[string]string{"Origin": "https://evil.example"}); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign Origin: status %d, want 403", rec.Code)
	}
	if rec := mcpCall(t, s, testMCPAllToken, ping, map[string]string{"Origin": "http://example.com"}); rec.Code != 200 {
		// httptest requests carry Host example.com.
		t.Fatalf("same-origin request: status %d", rec.Code)
	}
}

func TestMCPServerInitializeAndProtocolErrors(t *testing.T) {
	s, _ := newMCPTestServer(true)
	rec := mcpCall(t, s, testMCPReadToken, `{"jsonrpc":"2.0","id":"a","method":"initialize","params":{"protocolVersion":"2025-03-26"}}`, nil)
	resp := decodeRPC(t, rec)
	res, _ := resp.Result.(map[string]any)
	if resp.Error != nil || res["protocolVersion"] != "2025-03-26" || string(resp.ID) != `"a"` {
		t.Fatalf("initialize: %s", rec.Body.String())
	}
	rec = mcpCall(t, s, testMCPReadToken, `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`, nil)
	if res, _ := decodeRPC(t, rec).Result.(map[string]any); res["protocolVersion"] != mcpProtocolVersions[0] {
		t.Fatalf("unknown version must get the newest: %s", rec.Body.String())
	}
	if rec := mcpCall(t, s, testMCPReadToken, `{"jsonrpc":"2.0","method":"notifications/initialized"}`, nil); rec.Code != http.StatusAccepted || rec.Body.Len() != 0 {
		t.Fatalf("notification: status %d body %q", rec.Code, rec.Body.String())
	}
	if resp := decodeRPC(t, mcpCall(t, s, testMCPReadToken, `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`, nil)); resp.Error == nil || resp.Error.Code != rpcMethodNotFound {
		t.Fatalf("unknown method: %+v", resp)
	}
	if resp := decodeRPC(t, mcpCall(t, s, testMCPReadToken, `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, nil)); resp.Error == nil || resp.Error.Code != rpcInvalidRequest {
		t.Fatalf("batch: %+v", resp)
	}
	if resp := decodeRPC(t, mcpCall(t, s, testMCPReadToken, `{not json`, nil)); resp.Error == nil || resp.Error.Code != rpcParseError {
		t.Fatalf("bad JSON: %+v", resp)
	}
	req := httptest.NewRequest(http.MethodGet, mcpEndpointPath, nil)
	req.Header.Set("Authorization", "Bearer "+testMCPReadToken)
	rec = httptest.NewRecorder()
	s.serveMCP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: status %d, want 405", rec.Code)
	}
}

func mcpToolNames(t *testing.T, s *Server, token string) map[string]bool {
	t.Helper()
	resp := decodeRPC(t, mcpCall(t, s, token, `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil))
	res, _ := resp.Result.(map[string]any)
	list, _ := res["tools"].([]any)
	names := map[string]bool{}
	for _, item := range list {
		m, _ := item.(map[string]any)
		name, _ := m["name"].(string)
		if _, ok := m["inputSchema"].(map[string]any); !ok {
			t.Errorf("tool %s has no inputSchema", name)
		}
		names[name] = true
	}
	return names
}

func TestMCPServerToolsFollowScopes(t *testing.T) {
	s, _ := newMCPTestServer(true)
	read := mcpToolNames(t, s, testMCPReadToken)
	all := mcpToolNames(t, s, testMCPAllToken)
	for _, name := range []string{"list_tasks", "list_task_findings", "get_task_node_detail", "list_llm_profiles"} {
		if !read[name] || !all[name] {
			t.Errorf("read tool %s missing (read=%v all=%v)", name, read[name], all[name])
		}
	}
	for _, name := range []string{"spawn_task", "pause_task", "resume_task", "add_task_hint"} {
		if read[name] {
			t.Errorf("read-only token sees %s", name)
		}
		if !all[name] {
			t.Errorf("full token misses %s", name)
		}
	}
	if len(all) != len(s.mcpTools()) {
		t.Fatalf("full token sees %d of %d tools", len(all), len(s.mcpTools()))
	}
}

func TestMCPServerToolCallRefusalsAreAudited(t *testing.T) {
	s, store := newMCPTestServer(true)
	rec := mcpCall(t, s, testMCPReadToken, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"spawn_task","arguments":{"description":"x","goal":"y"}}}`, nil)
	resp := decodeRPC(t, rec)
	res, _ := resp.Result.(map[string]any)
	if resp.Error != nil || res["isError"] != true || !strings.Contains(rec.Body.String(), "task:create") {
		t.Fatalf("spawn_task with a read token must be refused as a tool error: %s", rec.Body.String())
	}
	resp = decodeRPC(t, mcpCall(t, s, testMCPAllToken, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"pause_task","arguments":[1]}}`, nil))
	if res, _ := resp.Result.(map[string]any); res["isError"] != true {
		t.Fatalf("array arguments must be refused: %+v", resp)
	}
	resp = decodeRPC(t, mcpCall(t, s, testMCPAllToken, `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"edit_settings"}}`, nil))
	if resp.Error == nil || resp.Error.Code != rpcInvalidParams {
		t.Fatalf("a tool outside the allowlist must be unknown: %+v", resp)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.audit) != 2 {
		t.Fatalf("audit rows = %d, want 2 (the unknown tool is not a call): %+v", len(store.audit), store.audit)
	}
	if a := store.audit[0]; a.Tool != "spawn_task" || a.OK || a.TokenName != "reader" || !strings.Contains(a.Args, `"goal":"y"`) {
		t.Fatalf("first audit row: %+v", a)
	}
}

func TestMCPServerBodyLimit(t *testing.T) {
	s, _ := newMCPTestServer(true)
	big := `{"jsonrpc":"2.0","id":1,"method":"ping","params":{"x":"` + strings.Repeat("a", mcpMaxBodyBytes) + `"}}`
	if rec := mcpCall(t, s, testMCPAllToken, big, nil); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: status %d", rec.Code)
	}
}

func TestTruncateRunesKeepsCharactersWhole(t *testing.T) {
	if got := truncateRunes("ééé", 2); got != "éé…" {
		t.Fatalf("got %q", got)
	}
	if got := compactJSONText([]byte("{ \"a\" : 1 }")); got != `{"a":1}` {
		t.Fatalf("compact: %q", got)
	}
}

// End to end against PostgreSQL: the admin API creates a token, the switch
// turns /mcp on, and the token lists tasks through the real handler tree,
// outside the console login.
func TestMCPServerEndToEnd(t *testing.T) {
	skipWithoutDSN(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { m.Close() })
	if m.pg == nil {
		db.SkipNoPG(t)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	t.Cleanup(func() { _ = m.pg.SetBool(db.SettingMCPServerEnabled, false) })
	h := s.Handler()

	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	post := func(path, auth, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if err := m.pg.SetBool(db.SettingMCPServerEnabled, false); err != nil {
		t.Fatal(err)
	}
	if rec := post(mcpEndpointPath, "", ping); rec.Code != http.StatusNotFound {
		t.Fatalf("off: status %d", rec.Code)
	}

	// The admin API stays behind the console login.
	if rec := post("/api/mcp-server/tokens", "", `{"name":"x","scopes":["read"]}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("token creation without login: status %d", rec.Code)
	}
	rec := httptest.NewRecorder()
	s.createMCPServerToken(rec, httptest.NewRequest(http.MethodPost, "/api/mcp-server/tokens", strings.NewReader(`{"name":"e2e","scopes":["read"],"expires_in_days":1}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("create token: %d %s", rec.Code, rec.Body.String())
	}
	var created struct {
		Token string      `json:"token"`
		Item  db.APIToken `json:"item"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.Token == "" {
		t.Fatalf("create token body: %s", rec.Body.String())
	}
	t.Cleanup(func() { _ = m.pg.DeleteAPIToken(created.Item.ID) })

	rec = httptest.NewRecorder()
	s.putMCPServerSettings(rec, httptest.NewRequest(http.MethodPut, "/api/mcp-server", strings.NewReader(`{"enabled":true}`)))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("enable: %d %s", rec.Code, rec.Body.String())
	}

	if rec := post(mcpEndpointPath, created.Token, ping); rec.Code != 200 {
		t.Fatalf("ping with a fresh token: %d %s", rec.Code, rec.Body.String())
	}
	rec = post(mcpEndpointPath, created.Token, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_tasks","arguments":{}}}`)
	resp := decodeRPC(t, rec)
	res, _ := resp.Result.(map[string]any)
	if resp.Error != nil || res["isError"] != false {
		t.Fatalf("list_tasks: %s", rec.Body.String())
	}
	audit, err := m.pg.ListMCPAudit(5)
	if err != nil || len(audit) == 0 || audit[0].Tool != "list_tasks" || audit[0].TokenID != created.Item.ID || !audit[0].OK {
		t.Fatalf("audit after list_tasks: %+v %v", audit, err)
	}

	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/mcp-server/tokens/x/revoke", nil)
	req.SetPathValue("id", strconv.FormatInt(created.Item.ID, 10))
	s.revokeMCPServerToken(rec, req)
	if rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	if rec := post(mcpEndpointPath, created.Token, ping); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token: status %d", rec.Code)
	}
}
