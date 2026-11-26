package agent

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Imported API definitions (OpenAPI, Swagger, Postman) give a task a list of
// operations to cover. The server computes each operation's status from captured
// traffic and manual marks; agents read it through list_api_operations and mark
// operations they covered without captured traffic, or chose not to test.

// APICoverageSource is how agent tools reach the server's coverage computation.
type APICoverageSource struct {
	List func(taskID int64) ([]db.APIOperationStatus, error)
	Mark func(taskID, id int64, mark, note, by string) error
}

var apiCoverageSource atomic.Pointer[APICoverageSource]

// SetAPICoverageSource installs the coverage source (nil removes it).
func SetAPICoverageSource(src APICoverageSource) {
	if src.List == nil {
		apiCoverageSource.Store(nil)
		return
	}
	apiCoverageSource.Store(&src)
}

func (t *ToolSet) apiTaskID() (int64, bool) {
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

const maxListedAPIOperations = 100

func (t *ToolSet) listAPIOperations() actool.CoreTool {
	return writeTool(
		"list_api_operations",
		"List the operations of the API definitions (OpenAPI, Swagger, Postman) imported into this task, with their parameters and coverage status: tested (captured traffic matched it, or it was marked tested), skipped (marked with a reason) or untested. Use it to pick operations nobody has exercised yet and to see each one's parameters and whether it requires authentication.",
		obj(map[string]any{
			"status": map[string]any{"type": "string", "enum": []string{"untested", "tested", "skipped", "all"}, "description": "which operations to list (default untested)"},
			"path":   str("optional substring filter on the path"),
		}),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			src := apiCoverageSource.Load()
			taskID, ok := t.apiTaskID()
			if src == nil || !ok {
				return actool.Errorf("list_api_operations is only available inside a task"), nil
			}
			var req struct {
				Status string `json:"status"`
				Path   string `json:"path"`
			}
			_ = json.Unmarshal(in, &req)
			status := strings.ToLower(strings.TrimSpace(req.Status))
			if status == "" {
				status = db.APIStatusUntested
			}
			ops, err := src.List(taskID)
			if err != nil {
				return actool.Errorf("list_api_operations failed: " + err.Error()), nil
			}
			counts := map[string]int{}
			var out []map[string]any
			for _, o := range ops {
				counts[o.Status]++
				if status != "all" && o.Status != status {
					continue
				}
				if req.Path != "" && !strings.Contains(strings.ToLower(o.Path), strings.ToLower(req.Path)) {
					continue
				}
				if len(out) >= maxListedAPIOperations {
					continue
				}
				m := map[string]any{"id": o.ID, "method": o.Method, "path": o.Path, "base_url": o.BaseURL, "status": o.Status, "auth": o.Auth, "params": o.Params}
				if o.Summary != "" {
					m["summary"] = o.Summary
				}
				if o.Requests > 0 {
					m["requests"], m["last_traffic_id"] = o.Requests, o.LastExchange
				}
				if o.MarkNote != "" {
					m["note"] = o.MarkNote
				}
				out = append(out, m)
			}
			if len(ops) == 0 {
				return jsonResult(map[string]any{"operations": []any{}, "note": "no API definition has been imported into this task"})
			}
			res := map[string]any{"operations": out, "counts": counts, "total": len(ops)}
			if len(out) == maxListedAPIOperations {
				res["note"] = "list truncated; filter by path to see the rest"
			}
			return jsonResult(res)
		})
}

func (t *ToolSet) markAPIOperation() actool.CoreTool {
	return writeTool(
		"mark_api_operation",
		"Mark an imported API operation as tested (you exercised it but the request was not captured, e.g. traffic capture is off) or skipped (you decided not to test it; the reason is required, e.g. destructive, out of scope, needs an account you do not have). Operations whose requests were captured count as tested automatically.",
		obj(map[string]any{
			"id":   map[string]any{"type": "integer", "description": "operation id from list_api_operations"},
			"mark": map[string]any{"type": "string", "enum": []string{"tested", "skipped"}},
			"note": str("what you did, or why you skipped it"),
		}, "id", "mark"),
		func(_ context.Context, in json.RawMessage) (actool.Result, error) {
			src := apiCoverageSource.Load()
			taskID, ok := t.apiTaskID()
			if src == nil || src.Mark == nil || !ok {
				return actool.Errorf("mark_api_operation is only available inside a task"), nil
			}
			var req struct {
				ID   int64  `json:"id"`
				Mark string `json:"mark"`
				Note string `json:"note"`
			}
			if err := json.Unmarshal(in, &req); err != nil {
				return actool.Errorf(err.Error()), nil
			}
			if req.Mark != db.APIStatusTested && req.Mark != db.APIStatusSkipped {
				return actool.Errorf("mark must be tested or skipped"), nil
			}
			by := t.worker
			if by == "" {
				by = "agent"
			}
			if err := src.Mark(taskID, req.ID, req.Mark, req.Note, by); err != nil {
				return actool.Errorf("mark_api_operation failed: " + err.Error()), nil
			}
			return jsonResult(map[string]any{"ok": true, "id": req.ID, "mark": req.Mark})
		})
}

// apiOperationsOverview summarizes imported API coverage for the graph overview
// (nil when the task has no imported definition).
func (t *ToolSet) apiOperationsOverview() map[string]any {
	src := apiCoverageSource.Load()
	taskID, ok := t.apiTaskID()
	if src == nil || !ok {
		return nil
	}
	ops, err := src.List(taskID)
	if err != nil || len(ops) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, o := range ops {
		counts[o.Status]++
	}
	return map[string]any{
		"total": len(ops), "tested": counts[db.APIStatusTested], "skipped": counts[db.APIStatusSkipped], "untested": counts[db.APIStatusUntested],
		"note": "operations from imported API definitions; list_api_operations shows the untested ones with their parameters; mark_api_operation records ones you tested without captured traffic, or skipped with a reason",
	}
}
