package db

import (
	"errors"
	"strings"
	"time"
)

// TaskCredential is a per-task test account (#3): either declared by the user at
// task creation (source=user, e.g. a program-provided alias account) or registered
// by the agent itself and recorded so it is not forgotten (source=agent).
//
// Passwords are encrypted at rest (secrets.go) and masked by the HTTP API; the
// agent tools read them decrypted. Anything injected into agent context transits to the LLM
// provider, so only dedicated test accounts belong here.
type TaskCredential struct {
	ID       int64  `json:"id"`
	TaskID   int64  `json:"task_id"`
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Password string `json:"password"`
	Source   string `json:"source"` // "user" | "agent"
	Note     string `json:"note,omitempty"`
	// Role and Org describe the account for access comparisons, e.g. "admin" in
	// "org-a". Free text: ARTEX compares them, it does not interpret them.
	Role string `json:"role,omitempty"`
	Org  string `json:"org,omitempty"`
	// AuthHeaders holds the headers of a logged-in request, one "Name: value"
	// per line (Cookie, Authorization, ...). Encrypted at rest like the password.
	AuthHeaders string    `json:"auth_headers,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TaskCredentialInput validates and normalizes one upsert. Empty username or
// domain is rejected; an empty password is allowed only for source=user (the
// "agent generates and records it later" mode from #3).
type TaskCredentialInput struct {
	Domain      string
	Username    string
	Password    string
	Source      string
	Note        string
	Role        string
	Org         string
	AuthHeaders string // empty = keep the stored headers
}

var ErrTaskCredentialInvalid = errors.New("credential domain and username are required")

func (in TaskCredentialInput) normalize() (TaskCredentialInput, error) {
	in.Domain = strings.TrimSpace(in.Domain)
	in.Username = strings.TrimSpace(in.Username)
	in.Password = strings.TrimSpace(in.Password)
	in.Note = strings.TrimSpace(in.Note)
	in.Role = clipRunes(strings.TrimSpace(in.Role), 64)
	in.Org = clipRunes(strings.TrimSpace(in.Org), 128)
	in.AuthHeaders = strings.TrimSpace(in.AuthHeaders)
	if in.AuthHeaders != "" {
		if _, err := ParseAuthHeaders(in.AuthHeaders); err != nil {
			return in, err
		}
	}
	if in.Source != "agent" {
		in.Source = "user"
	}
	if in.Domain == "" || in.Username == "" {
		return in, ErrTaskCredentialInvalid
	}
	if in.Password == "" && in.Source == "agent" {
		return in, errors.New("agent-recorded credentials need the password that was set")
	}
	return in, nil
}

// UpsertTaskCredential inserts or updates the (task, domain, username) entry: an
// agent re-registering the same account overwrites the password in place instead
// of piling up a second row.
func (d *DB) UpsertTaskCredential(taskID int64, in TaskCredentialInput) (TaskCredential, error) {
	in, err := in.normalize()
	if err != nil {
		return TaskCredential{}, err
	}
	pass, err := sealSecret(colCredPass, in.Password)
	if err != nil {
		return TaskCredential{}, err
	}
	headers := ""
	if in.AuthHeaders != "" {
		if headers, err = sealSecret(colCredHeaders, in.AuthHeaders); err != nil {
			return TaskCredential{}, err
		}
	}
	var c TaskCredential
	err = d.QueryRow(`
		INSERT INTO task_credentials (task_id, domain, username, password, source, note, role, org, auth_headers)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (task_id, domain, username) DO UPDATE
		SET password = EXCLUDED.password,
		    source   = EXCLUDED.source,
		    note     = CASE WHEN EXCLUDED.note = '' THEN task_credentials.note ELSE EXCLUDED.note END,
		    role     = CASE WHEN EXCLUDED.role = '' THEN task_credentials.role ELSE EXCLUDED.role END,
		    org      = CASE WHEN EXCLUDED.org = '' THEN task_credentials.org ELSE EXCLUDED.org END,
		    auth_headers = CASE WHEN EXCLUDED.auth_headers = '' THEN task_credentials.auth_headers ELSE EXCLUDED.auth_headers END,
		    updated_at = now()
		RETURNING id, task_id, domain, username, password, source, note, role, org, auth_headers, created_at, updated_at`,
		taskID, in.Domain, in.Username, pass, in.Source, in.Note, in.Role, in.Org, headers).
		Scan(&c.ID, &c.TaskID, &c.Domain, &c.Username, &c.Password, &c.Source, &c.Note, &c.Role, &c.Org, &c.AuthHeaders, &c.CreatedAt, &c.UpdatedAt)
	if err != nil {
		return c, err
	}
	c.Password = in.Password
	c.AuthHeaders, err = openSecret(colCredHeaders, c.AuthHeaders)
	return c, err
}

// TaskCredentials lists a task's credentials, oldest first (the user-declared
// ones keep their position ahead of agent-discovered ones).
func (d *DB) TaskCredentials(taskID int64) ([]TaskCredential, error) {
	rows, err := d.Query(`
		SELECT id, task_id, domain, username, password, source, note, role, org, auth_headers, created_at, updated_at
		FROM task_credentials WHERE task_id = $1 ORDER BY id`, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TaskCredential
	for rows.Next() {
		var c TaskCredential
		if err := rows.Scan(&c.ID, &c.TaskID, &c.Domain, &c.Username, &c.Password, &c.Source, &c.Note, &c.Role, &c.Org, &c.AuthHeaders, &c.CreatedAt, &c.UpdatedAt); err != nil {
			return nil, err
		}
		if c.Password, err = openSecret(colCredPass, c.Password); err != nil {
			return nil, err
		}
		if c.AuthHeaders, err = openSecret(colCredHeaders, c.AuthHeaders); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteTaskCredential removes one entry; taskID scopes the delete so a stale
// request cannot cross tasks.
func (d *DB) DeleteTaskCredential(taskID, id int64) error {
	tag, err := d.Exec(`DELETE FROM task_credentials WHERE id = $1 AND task_id = $2`, id, taskID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return errors.New("credential not found")
	}
	return nil
}

// SetTaskCredentialSession replaces a credential's session headers, or clears
// them when raw is empty, and changes nothing else (sessions expire; the
// password and role stay).
func (d *DB) SetTaskCredentialSession(taskID, id int64, raw string) error {
	raw = strings.TrimSpace(raw)
	sealed := ""
	if raw != "" {
		if _, err := ParseAuthHeaders(raw); err != nil {
			return err
		}
		var err error
		if sealed, err = sealSecret(colCredHeaders, raw); err != nil {
			return err
		}
	}
	tag, err := d.Exec(`UPDATE task_credentials SET auth_headers = $1, updated_at = now() WHERE id = $2 AND task_id = $3`, sealed, id, taskID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return errors.New("credential not found")
	}
	return nil
}

// Thin wrappers on ExplorationStore: the ToolSet already holds the task's
// exploration store, so credential tools need no extra wiring.

func (s *ExplorationStore) UpsertTaskCredential(taskID int64, in TaskCredentialInput) (TaskCredential, error) {
	return s.db.UpsertTaskCredential(taskID, in)
}

func (s *ExplorationStore) TaskCredentials(taskID int64) ([]TaskCredential, error) {
	return s.db.TaskCredentials(taskID)
}

func clipRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// ParseAuthHeaders parses "Name: value" lines into header pairs. Lines that are
// blank are skipped; anything else without a colon, or a header name with
// characters a header cannot carry, is an error.
func ParseAuthHeaders(raw string) ([][2]string, error) {
	var out [][2]string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, value, ok := strings.Cut(line, ":")
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		if !ok || name == "" || strings.ContainsAny(name, " \t\r()<>@,;\\\"/[]?={}") {
			return nil, errors.New("auth headers must be one \"Name: value\" per line")
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, errors.New("auth header values cannot contain line breaks")
		}
		out = append(out, [2]string{name, value})
	}
	if len(out) > 20 {
		return nil, errors.New("at most 20 auth headers")
	}
	return out, nil
}
