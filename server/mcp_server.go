package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// ARTEX as an MCP server: a stateless Streamable HTTP endpoint at /mcp that lets
// an outside agent (Claude Code, Claude Desktop, any MCP client) list and read
// tasks and findings, start tasks, pause and resume them and add hints.
//
//   - Off by default (setting mcp_server_enabled). While off, /mcp answers 404
//     like any unknown path.
//   - Authentication is an access token only (Authorization: Bearer artex_mcp_…),
//     created on the Settings page. The admin session (JWT cookie or header) is
//     not accepted here, so a browser that is logged in to the console cannot be
//     used to call /mcp. Tokens are 256 random bits, stored as SHA-256.
//   - Each token has scopes (read, task:create, task:control); tools/list shows
//     and tools/call runs only the tools its scopes allow.
//   - Only the tools in mcpTools are exposed. Nothing that edits settings, tools,
//     skills, agents, MCP servers, workspace files or LLM profiles is reachable.
//   - Every tools/call is recorded in mcp_audit_log, refusals included.
//   - Only initialize, ping, tools/list and tools/call are implemented. Responses
//     are plain application/json: no SSE stream and no session state.

const (
	mcpEndpointPath = "/mcp"
	mcpMaxBodyBytes = 1 << 20
	mcpCallTimeout  = 2 * time.Minute
	mcpAuditArgsMax = 2000
	mcpAuditResMax  = 500
)

// Protocol revisions this server speaks, newest first. Only the tools
// capability is implemented, which is the same in all of them.
var mcpProtocolVersions = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

const mcpInstructions = "ARTEX is an autonomous security testing platform. Use list_tasks to see tasks and their status, " +
	"list_task_findings and get_task_node_detail to read confirmed findings with evidence, and the worker trace tools to see how a task worked. " +
	"With the task:create scope, spawn_task starts a new task (description + goal); only target systems the operator is authorized to test. " +
	"With task:control, pause_task / resume_task control a task and add_task_hint steers its planner."

const (
	rpcParseError     = -32700
	rpcInvalidRequest = -32600
	rpcMethodNotFound = -32601
	rpcInvalidParams  = -32602
)

// mcpStore is the persistence /mcp needs; *db.DB satisfies it.
type mcpStore interface {
	GetBool(key string, def bool) bool
	APITokenByHash(hash string) (*db.APIToken, error)
	TouchAPIToken(id int64) error
	InsertMCPAudit(e db.MCPAuditEntry) error
}

func (s *Server) mcpServerStore() mcpStore {
	if s.mcpStoreOverride != nil {
		return s.mcpStoreOverride
	}
	if s.m == nil || s.m.pg == nil {
		return nil
	}
	return s.m.pg
}

type mcpRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type mcpRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type mcpRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpRPCError    `json:"error,omitempty"`
}

func writeMCPResult(w http.ResponseWriter, id json.RawMessage, result any) {
	writeJSON(w, http.StatusOK, mcpRPCResponse{JSONRPC: "2.0", ID: id, Result: result})
}

func writeMCPError(w http.ResponseWriter, status int, id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	writeJSON(w, status, mcpRPCResponse{JSONRPC: "2.0", ID: id, Error: &mcpRPCError{Code: code, Message: msg}})
}

// mcpOriginAllowed refuses cross-origin browser requests (DNS rebinding, a page
// on another site). MCP clients that are not browsers send no Origin.
func mcpOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	return strings.EqualFold(u.Host, r.Host)
}

// mcpBearerToken reads the access token from the Authorization header only:
// a cookie or a query parameter would let a browser or a logged URL carry it.
func mcpBearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func (s *Server) serveMCP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	store := s.mcpServerStore()
	if store == nil || !store.GetBool(db.SettingMCPServerEnabled, false) {
		http.NotFound(w, r)
		return
	}
	if !mcpOriginAllowed(r) {
		writeErr(w, http.StatusForbidden, "origin not allowed")
		return
	}
	token, authErr := authenticateMCP(store, r)
	if authErr != "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="artex-mcp"`)
		writeErr(w, http.StatusUnauthorized, authErr)
		return
	}
	if r.Method != http.MethodPost {
		// No server-initiated stream (GET) and no session to end (DELETE).
		w.Header().Set("Allow", http.MethodPost)
		writeErr(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, mcpMaxBodyBytes))
	if err != nil {
		writeMCPError(w, http.StatusRequestEntityTooLarge, nil, rpcInvalidRequest, "request body too large")
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		writeMCPError(w, http.StatusBadRequest, nil, rpcInvalidRequest, "batch requests are not supported")
		return
	}
	var req mcpRPCRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeMCPError(w, http.StatusBadRequest, nil, rpcParseError, "parse error")
		return
	}
	if req.JSONRPC != "2.0" {
		writeMCPError(w, http.StatusBadRequest, req.ID, rpcInvalidRequest, `jsonrpc must be "2.0"`)
		return
	}
	// A notification or a client response has no id (or no method): no body.
	if len(req.ID) == 0 || bytes.Equal(req.ID, []byte("null")) || req.Method == "" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		version := mcpProtocolVersions[0]
		for _, v := range mcpProtocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		writeMCPResult(w, req.ID, map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "artex", "title": "ARTEX", "version": BuildVersion},
			"instructions":    mcpInstructions,
		})
	case "ping":
		writeMCPResult(w, req.ID, map[string]any{})
	case "tools/list":
		out := make([]map[string]any, 0)
		for _, t := range s.mcpTools() {
			if !token.HasScope(t.scope) {
				continue
			}
			out = append(out, map[string]any{
				"name":        t.tool.Name(),
				"description": t.tool.Description(),
				"inputSchema": t.tool.InputSchema(),
				"annotations": map[string]any{"readOnlyHint": t.scope == db.APIScopeRead, "destructiveHint": false},
			})
		}
		writeMCPResult(w, req.ID, map[string]any{"tools": out})
	case "tools/call":
		s.serveMCPToolCall(r.Context(), w, store, token, req, clientIP(r, s.trustedProxies))
	default:
		writeMCPError(w, http.StatusOK, req.ID, rpcMethodNotFound, "method not found: "+req.Method)
	}
}

// authenticateMCP resolves the bearer token; a non-empty message means refuse.
func authenticateMCP(store mcpStore, r *http.Request) (*db.APIToken, string) {
	plaintext := mcpBearerToken(r)
	if plaintext == "" {
		return nil, "missing access token: send Authorization: Bearer <token>"
	}
	if !strings.HasPrefix(plaintext, db.APITokenPrefix) {
		return nil, "invalid access token"
	}
	token, err := store.APITokenByHash(db.HashAPIToken(plaintext))
	if err != nil {
		log.Printf("[mcp-server] token lookup failed: %v", err)
		return nil, "access token could not be verified"
	}
	if token == nil {
		return nil, "invalid access token"
	}
	if !token.Usable(time.Now()) {
		return nil, "access token revoked or expired"
	}
	if err := store.TouchAPIToken(token.ID); err != nil {
		log.Printf("[mcp-server] recording token use failed: %v", err)
	}
	return token, ""
}

func (s *Server) serveMCPToolCall(ctx context.Context, w http.ResponseWriter, store mcpStore, token *db.APIToken, req mcpRPCRequest, remote string) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		writeMCPError(w, http.StatusOK, req.ID, rpcInvalidParams, "params.name is required")
		return
	}
	var picked *mcpExposedTool
	for _, t := range s.mcpTools() {
		if t.tool.Name() == p.Name {
			picked = &t
			break
		}
	}
	if picked == nil {
		writeMCPError(w, http.StatusOK, req.ID, rpcInvalidParams, "unknown tool: "+p.Name)
		return
	}
	args := bytes.TrimSpace(p.Arguments)
	if len(args) == 0 || bytes.Equal(args, []byte("null")) {
		args = []byte("{}")
	}
	start := time.Now()
	var result actool.Result
	switch {
	case !token.HasScope(picked.scope):
		result = actool.Errorf(fmt.Sprintf("this access token lacks the %s scope needed for %s", picked.scope, p.Name))
	case args[0] != '{':
		result = actool.Errorf("arguments must be a JSON object")
	default:
		result = runMCPTool(ctx, picked.tool, args)
	}
	text := result.Flatten()
	if err := store.InsertMCPAudit(db.MCPAuditEntry{
		TokenID: token.ID, TokenName: token.Name, Tool: p.Name,
		Args: truncateRunes(compactJSONText(args), mcpAuditArgsMax), OK: !result.IsError,
		Result: truncateRunes(text, mcpAuditResMax), RemoteAddr: remote,
		DurationMS: time.Since(start).Milliseconds(),
	}); err != nil {
		log.Printf("[mcp-server] audit write failed (token=%d tool=%s): %v", token.ID, p.Name, err)
	}
	writeMCPResult(w, req.ID, map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": result.IsError,
	})
}

// runMCPTool runs one tool under a deadline. A failure or a panic becomes an
// isError result for the caller, never a transport error.
func runMCPTool(ctx context.Context, t actool.CoreTool, args json.RawMessage) (result actool.Result) {
	ctx, cancel := context.WithTimeout(ctx, mcpCallTimeout)
	defer cancel()
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("[mcp-server] tool %s panicked: %v", t.Name(), rec)
			result = actool.Errorf("the tool failed")
		}
	}()
	res, err := t.Call(ctx, args, nil)
	if err != nil {
		return actool.Errorf(err.Error())
	}
	return res
}

func compactJSONText(raw []byte) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max]) + "…"
}

// --- exposed tools ---

type mcpExposedTool struct {
	tool  actool.CoreTool
	scope string
}

// mcpTools is the whole allowlist. The tools are the same host tools the
// orchestration agent uses, so they behave exactly as they do in chat.
func (s *Server) mcpTools() []mcpExposedTool {
	return []mcpExposedTool{
		{s.toolListTasks(), db.APIScopeRead},
		{s.toolListLLMProfiles(), db.APIScopeRead},
		{s.toolGetTaskGraph(), db.APIScopeRead},
		{s.toolListTaskFindings(), db.APIScopeRead},
		{s.toolGetTaskNodeDetail(), db.APIScopeRead},
		{s.toolListWorkerTraces(), db.APIScopeRead},
		{s.toolGetWorkerTrace(), db.APIScopeRead},
		{s.toolSearchWorkerTraces(), db.APIScopeRead},
		{s.toolSpawnTask(), db.APIScopeTaskCreate},
		{s.toolPauseTask(), db.APIScopeTaskControl},
		{s.toolResumeTask(), db.APIScopeTaskControl},
		{s.toolAddHint(), db.APIScopeTaskControl},
	}
}

// toolResumeTask resumes a paused task. Only the MCP server exposes it.
func (s *Server) toolResumeTask() actool.CoreTool {
	return wrTool("resume_task", "Resume a paused task (restarts its planner/worker loops). Only a paused task can be resumed.",
		objSchema(map[string]any{"task_id": strParam("the id of the task to resume")}, "task_id"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			var a struct {
				TaskID string `json:"task_id"`
			}
			_ = json.Unmarshal(in, &a)
			t, ok := s.m.Task(a.TaskID)
			if !ok {
				return actool.Errorf("task not found: " + a.TaskID), nil
			}
			if _, err := s.applyTaskControlWithCause(t, "resume", agent.AbortPausedByUser); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			return actool.Text("task resumed: " + a.TaskID), nil
		})
}

// --- admin API (behind the console login like every other /api route) ---

func (s *Server) getMCPServerSettings(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	tokens, err := pg.ListAPITokens()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	tools := make([]map[string]string, 0)
	for _, t := range s.mcpTools() {
		tools = append(tools, map[string]string{"name": t.tool.Name(), "scope": t.scope})
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{
		"enabled": pg.GetBool(db.SettingMCPServerEnabled, false),
		"path":    mcpEndpointPath,
		"scopes":  db.APIScopes,
		"tools":   tools,
		"tokens":  tokens,
	})
}

func (s *Server) putMCPServerSettings(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decode(w, r, &req); err != nil || req.Enabled == nil {
		writeErr(w, 400, "send {\"enabled\": true|false}")
		return
	}
	if err := pg.SetBool(db.SettingMCPServerEnabled, *req.Enabled); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[mcp-server] MCP server endpoint %s", map[bool]string{true: "enabled", false: "disabled"}[*req.Enabled])
	s.getMCPServerSettings(w, r)
}

func (s *Server) createMCPServerToken(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Name          string   `json:"name"`
		Scopes        []string `json:"scopes"`
		ExpiresInDays int      `json:"expires_in_days"` // 0 = never
	}
	if err := decode(w, r, &req); err != nil {
		writeErr(w, 400, "invalid request")
		return
	}
	if req.ExpiresInDays < 0 || req.ExpiresInDays > 3650 {
		writeErr(w, 400, "expires_in_days must be between 0 (never) and 3650")
		return
	}
	var expires *time.Time
	if req.ExpiresInDays > 0 {
		e := time.Now().Add(time.Duration(req.ExpiresInDays) * 24 * time.Hour)
		expires = &e
	}
	token, plaintext, err := pg.CreateAPIToken(req.Name, req.Scopes, expires)
	if err != nil {
		if errors.Is(err, db.ErrAPITokenInvalid) {
			writeErr(w, 400, strings.TrimPrefix(err.Error(), db.ErrAPITokenInvalid.Error()+": "))
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[mcp-server] access token #%d %q created, scopes %v", token.ID, token.Name, token.Scopes)
	w.Header().Set("Cache-Control", "no-store")
	// The plaintext is returned this once; only its hash is stored.
	writeJSON(w, 201, map[string]any{"token": plaintext, "item": token})
}

func (s *Server) revokeMCPServerToken(w http.ResponseWriter, r *http.Request) {
	s.changeMCPServerToken(w, r, "revoked", (*db.DB).RevokeAPIToken)
}

func (s *Server) deleteMCPServerToken(w http.ResponseWriter, r *http.Request) {
	s.changeMCPServerToken(w, r, "deleted", (*db.DB).DeleteAPIToken)
}

func (s *Server) changeMCPServerToken(w http.ResponseWriter, r *http.Request, verb string, apply func(*db.DB, int64) error) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	id, ok := pathInt(r, "id")
	if !ok || id <= 0 {
		writeErr(w, 400, "invalid token id")
		return
	}
	if err := apply(pg, id); err != nil {
		if errors.Is(err, db.ErrAPITokenNotFound) {
			writeErr(w, 404, "access token not found")
			return
		}
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[mcp-server] access token #%d %s", id, verb)
	writeJSON(w, 200, map[string]any{"ok": true})
}

func (s *Server) listMCPServerAudit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	rows, err := pg.ListMCPAudit(limit)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"entries": rows})
}
