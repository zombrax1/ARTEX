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
	"github.com/Autumn-27/artex/traffic"
)

// API definition import (OpenAPI 3, Swagger 2, Postman v2). Operations are
// stored per task; an operation counts as tested when the recording proxy saw a
// matching request after the import, or when an agent or the user marked it.

// Coverage reads captured traffic incrementally: each definition keeps a cursor
// on the last capture already counted, and one pass reads at most
// apiCoveragePages pages of apiCoveragePageSize newer captures per definition.
// What a pass does not reach, the next one does; nothing counted is lost.
var (
	apiCoveragePageSize = 20000
	apiCoveragePages    = 5
)

func (s *Server) apiCoverage(taskID int64) ([]db.APIOperationStatus, error) {
	pg := s.m.PG()
	ops, err := pg.APIOperations(taskID)
	if err != nil || len(ops) == 0 {
		return []db.APIOperationStatus{}, err
	}
	if tr := s.m.Traffic(); tr != nil {
		byDef := map[int64][]db.APIOperation{}
		var order []int64
		for _, op := range ops {
			if _, ok := byDef[op.DefinitionID]; !ok {
				order = append(order, op.DefinitionID)
			}
			byDef[op.DefinitionID] = append(byDef[op.DefinitionID], op)
		}
		scanned := false
		for _, id := range order {
			if s.scanAPIDefinition(tr, id, byDef[id]) {
				scanned = true
			}
		}
		if scanned {
			if ops, err = pg.APIOperations(taskID); err != nil {
				return nil, err
			}
		}
	}
	return db.APICoverage(ops), nil
}

// scanAPIDefinition counts the captures newer than a definition's cursor and
// reports whether it recorded anything.
func (s *Server) scanAPIDefinition(tr *traffic.Traffic, defID int64, ops []db.APIOperation) bool {
	hostSet := map[string]bool{}
	anyHost := false
	for _, op := range ops {
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
	seq, since := ops[0].ScanSeq, ops[0].ImportedAt.Unix()
	recorded := false
	for page := 0; page < apiCoveragePages; page++ {
		rows, err := tr.After(hosts, seq, since, apiCoveragePageSize)
		if err != nil {
			log.Printf("[api-import] reading traffic for definition %d coverage failed: %v", defID, err)
			return recorded
		}
		if len(rows) == 0 {
			return recorded
		}
		exchanges := make([]db.APIExchange, 0, len(rows))
		for _, r := range rows {
			exchanges = append(exchanges, db.APIExchange{ID: r.ID, TS: r.TS, Method: r.Method, URL: r.URL})
		}
		last := rows[len(rows)-1].Seq
		ok, err := s.m.PG().RecordAPIScan(defID, seq, last, db.MatchAPIExchanges(ops, exchanges))
		if err != nil {
			log.Printf("[api-import] saving coverage for definition %d failed: %v", defID, err)
			return recorded
		}
		if !ok {
			// Another pass moved the cursor first and counted these.
			return true
		}
		recorded, seq = true, last
		if len(rows) < apiCoveragePageSize {
			return recorded
		}
	}
	return recorded
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
