package server

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/apidef"
	"github.com/Autumn-27/artex/db"
)

// API definition import (OpenAPI 3, Swagger 2, Postman v2). Operations are
// stored per task; an operation counts as tested when the recording proxy saw a
// matching request after the import, or when an agent or the user marked it.

// apiCoverageTrafficLimit caps how many captured exchanges one coverage pass reads.
const apiCoverageTrafficLimit = 50000

// apiCoverage returns a task's operations with their computed status.
func (s *Server) apiCoverage(taskID int64) ([]db.APIOperationStatus, error) {
	ops, err := s.m.PG().APIOperations(taskID)
	if err != nil || len(ops) == 0 {
		return []db.APIOperationStatus{}, err
	}
	var exchanges []db.APIExchange
	if tr := s.m.Traffic(); tr != nil {
		since := ops[0].ImportedAt
		hostSet := map[string]bool{}
		anyHost := false
		for _, op := range ops {
			if op.ImportedAt.Before(since) {
				since = op.ImportedAt
			}
			u, err := url.Parse(op.BaseURL)
			if err != nil || u.Hostname() == "" || strings.Contains(u.Host, "{{") {
				anyHost = true
				continue
			}
			hostSet[strings.ToLower(u.Hostname())] = true
		}
		var hosts []string
		if !anyHost {
			for h := range hostSet {
				hosts = append(hosts, h)
			}
		}
		rows, err := tr.Since(hosts, since.Unix(), apiCoverageTrafficLimit)
		if err != nil {
			log.Printf("[api-import] reading traffic for task %d coverage failed: %v", taskID, err)
		}
		for _, r := range rows {
			exchanges = append(exchanges, db.APIExchange{ID: r.ID, TS: r.TS, Method: r.Method, URL: r.URL})
		}
	}
	return db.APICoverage(ops, exchanges), nil
}

type apiCoverageSummary struct {
	Total    int `json:"total"`
	Tested   int `json:"tested"`
	Skipped  int `json:"skipped"`
	Untested int `json:"untested"`
}

func summarizeAPICoverage(ops []db.APIOperationStatus) apiCoverageSummary {
	var s apiCoverageSummary
	for _, o := range ops {
		s.Total++
		switch o.Status {
		case db.APIStatusTested:
			s.Tested++
		case db.APIStatusSkipped:
			s.Skipped++
		default:
			s.Untested++
		}
	}
	return s
}

// installAPICoverage lets agent tools read and mark a task's imported operations.
func (s *Server) installAPICoverage() {
	agent.SetAPICoverageSource(agent.APICoverageSource{
		List: s.apiCoverage,
		Mark: func(taskID, id int64, mark, note, by string) error {
			return s.m.PG().MarkAPIOperation(taskID, id, mark, note, by)
		},
	})
}

// GET /api/tasks/{id}/api-definitions
func (s *Server) listAPIDefinitions(w http.ResponseWriter, r *http.Request) {
	id, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	defs, err := s.m.PG().APIDefinitions(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	ops, err := s.apiCoverage(id)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{
		"definitions":     defs,
		"operations":      ops,
		"summary":         summarizeAPICoverage(ops),
		"traffic_capture": s.m.TrafficEnabled(),
	})
}

// POST /api/tasks/{id}/api-definitions {name, content}
func (s *Server) importAPIDefinition(w http.ResponseWriter, r *http.Request) {
	id, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2*apidef.MaxBytes+4096) // JSON string escaping can double the size
	var req struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeErr(w, http.StatusRequestEntityTooLarge, "the definition is too large")
			return
		}
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	def, err := apidef.Parse([]byte(req.Content))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	saved, err := s.m.PG().CreateAPIDefinition(id, req.Name, def)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	log.Printf("[api-import] task %d: imported %s definition %q with %d operations", id, def.Format, saved.Name, saved.Operations)
	writeJSON(w, 201, saved)
}

// DELETE /api/tasks/{id}/api-definitions/{did}
func (s *Server) deleteAPIDefinition(w http.ResponseWriter, r *http.Request) {
	id, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	did, ok := pathInt(r, "did")
	if !ok {
		writeErr(w, 400, "invalid definition id")
		return
	}
	found, err := s.m.PG().DeleteAPIDefinition(id, did)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	if !found {
		writeErr(w, 404, "definition not found")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true})
}

// PUT /api/tasks/{id}/api-operations/{oid} {mark, note}: "" clears the mark.
func (s *Server) markAPIOperation(w http.ResponseWriter, r *http.Request) {
	id, ok := s.taskCredentialTaskID(w, r)
	if !ok {
		return
	}
	oid, ok := pathInt(r, "oid")
	if !ok {
		writeErr(w, 400, "invalid operation id")
		return
	}
	var req struct {
		Mark string `json:"mark"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, 400, "bad json: "+err.Error())
		return
	}
	if err := s.m.PG().MarkAPIOperation(id, oid, req.Mark, req.Note, "user"); err != nil {
		if errors.Is(err, db.ErrAPIOperationNotFound) {
			writeErr(w, 404, err.Error())
			return
		}
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "marked_at": time.Now().UTC()})
}
