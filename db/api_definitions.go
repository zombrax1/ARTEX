package db

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/Autumn-27/artex/apidef"
)

// APIDefinition is an imported API definition of a task.
type APIDefinition struct {
	ID         int64     `json:"id"`
	TaskID     int64     `json:"task_id"`
	Name       string    `json:"name"`
	Format     string    `json:"format"`
	BaseURL    string    `json:"base_url"`
	ImportedAt time.Time `json:"imported_at"`
	Operations int       `json:"operations"`
}

// APIOperation is one imported operation with its manual mark.
type APIOperation struct {
	ID           int64          `json:"id"`
	DefinitionID int64          `json:"definition_id"`
	Method       string         `json:"method"`
	Path         string         `json:"path"`
	BaseURL      string         `json:"base_url"`
	OperationID  string         `json:"operation_id,omitempty"`
	Summary      string         `json:"summary,omitempty"`
	Params       []apidef.Param `json:"params"`
	Auth         bool           `json:"auth"`
	Mark         string         `json:"mark"` // "" | tested | skipped
	MarkNote     string         `json:"mark_note,omitempty"`
	MarkBy       string         `json:"mark_by,omitempty"`
	MarkedAt     *time.Time     `json:"marked_at,omitempty"`
	ImportedAt   time.Time      `json:"imported_at"` // of its definition
}

// Operation returns the parsed form, for matching.
func (o APIOperation) Operation() apidef.Operation {
	return apidef.Operation{Method: o.Method, Path: o.Path, BaseURL: o.BaseURL, Params: o.Params, Auth: o.Auth}
}

var ErrAPIOperationNotFound = errors.New("API operation not found in this task")

// CreateAPIDefinition stores a parsed definition and its operations for a task.
func (d *DB) CreateAPIDefinition(taskID int64, name string, def *apidef.Definition) (*APIDefinition, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = def.Title
	}
	if len([]rune(name)) > 200 {
		name = string([]rune(name)[:200])
	}
	tx, err := d.Begin()
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	out := &APIDefinition{TaskID: taskID, Name: name, Format: def.Format, BaseURL: def.BaseURL, Operations: len(def.Operations)}
	if err := tx.QueryRow(`INSERT INTO api_definitions (task_id, name, format, base_url) VALUES ($1,$2,$3,$4) RETURNING id, imported_at`,
		taskID, name, def.Format, def.BaseURL).Scan(&out.ID, &out.ImportedAt); err != nil {
		return nil, err
	}
	stmt, err := tx.Prepare(`INSERT INTO api_operations (definition_id, task_id, method, path, base_url, operation_id, summary, params, auth)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()
	for _, op := range def.Operations {
		params, _ := json.Marshal(op.Params)
		if _, err := stmt.Exec(out.ID, taskID, op.Method, op.Path, op.BaseURL, op.OperationID, op.Summary, params, op.Auth); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}

// APIDefinitions lists a task's imported definitions, newest first.
func (d *DB) APIDefinitions(taskID int64) ([]APIDefinition, error) {
	rows, err := d.Query(`SELECT d.id, d.task_id, d.name, d.format, d.base_url, d.imported_at,
		(SELECT count(*) FROM api_operations o WHERE o.definition_id = d.id)
		FROM api_definitions d WHERE d.task_id = $1 ORDER BY d.imported_at DESC, d.id DESC`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIDefinition{}
	for rows.Next() {
		var a APIDefinition
		if err := rows.Scan(&a.ID, &a.TaskID, &a.Name, &a.Format, &a.BaseURL, &a.ImportedAt, &a.Operations); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteAPIDefinition removes a definition (and its operations) from a task.
func (d *DB) DeleteAPIDefinition(taskID, id int64) (bool, error) {
	res, err := d.Exec(`DELETE FROM api_definitions WHERE id = $1 AND task_id = $2`, id, taskID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// APIOperations lists every imported operation of a task.
func (d *DB) APIOperations(taskID int64) ([]APIOperation, error) {
	rows, err := d.Query(`SELECT o.id, o.definition_id, o.method, o.path, o.base_url, o.operation_id, o.summary, o.params, o.auth,
		o.mark, o.mark_note, o.mark_by, o.marked_at, d.imported_at
		FROM api_operations o JOIN api_definitions d ON d.id = o.definition_id
		WHERE o.task_id = $1 ORDER BY d.imported_at DESC, o.id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []APIOperation{}
	for rows.Next() {
		var o APIOperation
		var params []byte
		var marked sql.NullTime
		if err := rows.Scan(&o.ID, &o.DefinitionID, &o.Method, &o.Path, &o.BaseURL, &o.OperationID, &o.Summary, &params, &o.Auth,
			&o.Mark, &o.MarkNote, &o.MarkBy, &marked, &o.ImportedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(params, &o.Params)
		if o.Params == nil {
			o.Params = []apidef.Param{}
		}
		if marked.Valid {
			t := marked.Time
			o.MarkedAt = &t
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// MarkAPIOperation sets (or with mark "" clears) the manual mark of an operation.
func (d *DB) MarkAPIOperation(taskID, id int64, mark, note, by string) error {
	mark = strings.ToLower(strings.TrimSpace(mark))
	switch mark {
	case "", "tested", "skipped":
	default:
		return errors.New("mark must be tested, skipped or empty")
	}
	note = strings.TrimSpace(note)
	if len([]rune(note)) > 1000 {
		note = string([]rune(note)[:1000])
	}
	if mark == "skipped" && note == "" {
		return errors.New("a skipped operation needs a reason")
	}
	res, err := d.Exec(`UPDATE api_operations SET mark=$3, mark_note=$4, mark_by=$5,
		marked_at = CASE WHEN $3 = '' THEN NULL ELSE now() END
		WHERE id=$1 AND task_id=$2`, id, taskID, mark, note, by)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAPIOperationNotFound
	}
	return nil
}

// API operation coverage statuses.
const (
	APIStatusTested   = "tested"   // captured traffic matched it, or it was marked tested
	APIStatusSkipped  = "skipped"  // marked skipped, with a reason
	APIStatusUntested = "untested" // neither
)

// APIExchange is the part of a captured exchange that coverage needs.
type APIExchange struct {
	ID     string
	TS     int64 // unix seconds
	Method string
	URL    string
}

// APIOperationStatus is an operation with its computed coverage.
type APIOperationStatus struct {
	APIOperation
	Status       string `json:"status"`
	Requests     int    `json:"requests"`                // matching captured requests since the import
	LastExchange string `json:"last_exchange,omitempty"` // newest matching traffic id
}

// APICoverage computes each operation's status from its mark and the captured
// exchanges (newest first). An exchange counts for an operation only when it
// was recorded after that operation's definition was imported. A manual mark
// wins over traffic: skipped stays skipped even if a request was seen.
func APICoverage(ops []APIOperation, exchanges []APIExchange) []APIOperationStatus {
	type parsed struct {
		method, host, path string
		ts                 int64
		id                 string
	}
	ps := make([]parsed, 0, len(exchanges))
	for _, e := range exchanges {
		u, err := url.Parse(e.URL)
		if err != nil {
			continue
		}
		ps = append(ps, parsed{method: e.Method, host: u.Host, path: u.EscapedPath(), ts: e.TS, id: e.ID})
	}
	out := make([]APIOperationStatus, 0, len(ops))
	for _, op := range ops {
		st := APIOperationStatus{APIOperation: op, Status: APIStatusUntested}
		m := apidef.NewMatcher(op.Operation())
		since := op.ImportedAt.Unix()
		for _, e := range ps {
			if e.ts < since || !m.Match(e.method, e.host, e.path) {
				continue
			}
			if st.Requests == 0 {
				st.LastExchange = e.id
			}
			st.Requests++
		}
		switch {
		case op.Mark == APIStatusSkipped:
			st.Status = APIStatusSkipped
		case op.Mark == APIStatusTested || st.Requests > 0:
			st.Status = APIStatusTested
		}
		out = append(out, st)
	}
	return out
}
