package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Multiple-account testing: compare_access replays one request as each test
// account that has session headers saved (and without a session), and flags
// accounts that get the owner's response although their role or organisation
// differs. The replay runs in the server, which owns the HTTP client set-up
// (target gate, recording proxy, egress pacing); agents reach it through the
// source below.

// AccessCheckRequest is one compare_access call.
type AccessCheckRequest struct {
	Method           string            `json:"method"`
	URL              string            `json:"url"`
	Body             string            `json:"body,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Accounts         []int64           `json:"accounts,omitempty"`
	Owner            int64             `json:"owner,omitempty"`
	IncludeAnonymous *bool             `json:"include_anonymous,omitempty"`
	AllowStateChange bool              `json:"allow_state_change,omitempty"`
	CheckedBy        string            `json:"-"`
}

// Anonymous reports whether the request is also replayed without a session
// (the default).
func (r AccessCheckRequest) Anonymous() bool {
	return r.IncludeAnonymous == nil || *r.IncludeAnonymous
}

// AccessCheckSource is how agent tools reach the server's replay.
type AccessCheckSource struct {
	Run func(ctx context.Context, toolName string, taskID int64, req AccessCheckRequest) (db.AccessCheck, error)
}

var accessCheckSource atomic.Pointer[AccessCheckSource]

// SetAccessCheckSource installs the replay source (a nil Run removes it).
func SetAccessCheckSource(src AccessCheckSource) {
	if src.Run == nil {
		accessCheckSource.Store(nil)
		return
	}
	accessCheckSource.Store(&src)
}

// accessTaskID resolves the PG task id of this tool set, caching it.
func (t *ToolSet) accessTaskID() (int64, bool) {
	if t.taskID > 0 {
		return t.taskID, true
	}
	if t.ts == nil {
		return 0, false
	}
	id, err := t.ts.TaskID()
	if err != nil || id <= 0 {
		return 0, false
	}
	t.taskID = id
	return id, true
}

func (t *ToolSet) compareAccess() actool.CoreTool {
	return writeTool(
		"compare_access",
		"Replay one HTTP request as each of this task's test accounts that has session headers saved (see save_task_credential auth_headers), and once without any session, then compare the responses. Flags an account that gets the owner's successful response although it is anonymous, in another organisation, has another role, or is another user with the same role (a possible IDOR). Use it on endpoints that return one account's or one organisation's data, and on admin-only endpoints with owner set to the admin account. Redirects are not followed, so a redirect to a login page shows as 3xx. GET, HEAD and OPTIONS run as is; any other method is sent once per account, so it needs allow_state_change=true and should only target data that is safe to change.\n"+
			"Returns: {id, results:[{credential_id, account, role, org, status, length, snippet, error}], flags:[{kind, account, match, detail}]}.",
		obj(map[string]any{
			"method":             str("HTTP method (default GET)"),
			"url":                str("absolute URL of the request, e.g. an object that belongs to the owner account"),
			"body":               str("optional request body"),
			"headers":            map[string]any{"type": "object", "additionalProperties": map[string]any{"type": "string"}, "description": "optional extra headers, e.g. Content-Type; session headers come from each account"},
			"accounts":           map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "credential ids to compare (default: every account with session headers)"},
			"owner":              map[string]any{"type": "integer", "description": "credential id of the account the resource belongs to, or the only role that should reach it; without it only anonymous access is checked"},
			"include_anonymous":  map[string]any{"type": "boolean", "description": "also send the request without a session (default true)"},
			"allow_state_change": map[string]any{"type": "boolean", "description": "required for methods other than GET, HEAD and OPTIONS"},
		}, "url"),
		func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
			src := accessCheckSource.Load()
			taskID, ok := t.accessTaskID()
			if src == nil || !ok {
				return actool.Errorf("compare_access is only available inside a task"), nil
			}
			var req AccessCheckRequest
			if err := json.Unmarshal(in, &req); err != nil {
				return actool.Errorf("invalid input: " + err.Error()), nil
			}
			req.CheckedBy = t.worker
			if req.CheckedBy == "" {
				req.CheckedBy = "agent"
			}
			c, err := src.Run(ctx, "compare_access", taskID, req)
			if err != nil {
				return actool.Errorf("compare_access failed: " + err.Error()), nil
			}
			out := map[string]any{"id": c.ID, "method": c.Method, "url": c.URL, "results": c.Results, "flags": c.Flags}
			if len(c.Flags) > 0 {
				out["note"] = "a flag is a lead, not a finding: confirm the response really contains the other account's data before reporting it"
			}
			return jsonResult(out)
		})
}

// StateChangingMethod reports whether a method may change data on the target.
func StateChangingMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "", "GET", "HEAD", "OPTIONS":
		return false
	}
	return true
}
