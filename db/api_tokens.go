package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Access tokens let an outside MCP client call ARTEX's MCP endpoint (/mcp).
// The plaintext is shown once when the token is created; only its SHA-256 is
// stored. A token carries scopes that decide which MCP tools it may call.

// SettingMCPServerEnabled turns the /mcp endpoint on. Off by default.
const SettingMCPServerEnabled = "mcp_server_enabled"

// APITokenPrefix starts every token, so a leaked one is easy to recognise and
// grep for.
const APITokenPrefix = "artex_mcp_"

// Token scopes.
const (
	APIScopeRead        = "read"         // list and read tasks, findings, traces, LLM profiles
	APIScopeTaskCreate  = "task:create"  // start new tasks
	APIScopeTaskControl = "task:control" // pause, resume, add hints
)

// APIScopes lists every valid scope in display order.
var APIScopes = []string{APIScopeRead, APIScopeTaskCreate, APIScopeTaskControl}

const (
	apiTokenNameMax = 80
	// mcpAuditKeep is how many audit rows are kept; older ones are pruned.
	mcpAuditKeep = 5000
	// apiTokenTouchEvery throttles last_used_at writes to one per token per minute.
	apiTokenTouchEvery = time.Minute
)

var (
	ErrAPITokenInvalid  = errors.New("invalid access token settings")
	ErrAPITokenNotFound = errors.New("access token not found")
)

// APIToken is a stored token without its secret.
type APIToken struct {
	ID         int64      `json:"id"`
	Name       string     `json:"name"`
	Hint       string     `json:"hint"` // last characters of the plaintext
	Scopes     []string   `json:"scopes"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RevokedAt  *time.Time `json:"revoked_at,omitempty"`
}

// HasScope reports whether the token grants scope.
func (t *APIToken) HasScope(scope string) bool {
	return t != nil && slices.Contains(t.Scopes, scope)
}

// Usable reports whether the token is neither revoked nor expired at now.
func (t *APIToken) Usable(now time.Time) bool {
	if t == nil || t.RevokedAt != nil {
		return false
	}
	return t.ExpiresAt == nil || now.Before(*t.ExpiresAt)
}

// HashAPIToken returns the hex SHA-256 stored for a plaintext token.
func HashAPIToken(plaintext string) string {
	sum := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(sum[:])
}

// NormalizeAPITokenScopes deduplicates scopes, keeps the canonical order and
// rejects unknown ones. At least one scope is required.
func NormalizeAPITokenScopes(scopes []string) ([]string, error) {
	want := map[string]bool{}
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if !slices.Contains(APIScopes, s) {
			return nil, fmt.Errorf("%w: unknown scope %q", ErrAPITokenInvalid, s)
		}
		want[s] = true
	}
	var out []string
	for _, s := range APIScopes {
		if want[s] {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: pick at least one scope", ErrAPITokenInvalid)
	}
	return out, nil
}

const apiTokenCols = `id,name,token_hint,scopes,created_at,last_used_at,expires_at,revoked_at`

func scanAPIToken(sc interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	var scopes string
	var lastUsed, expires, revoked sql.NullTime
	if err := sc.Scan(&t.ID, &t.Name, &t.Hint, &scopes, &t.CreatedAt, &lastUsed, &expires, &revoked); err != nil {
		return nil, err
	}
	t.Scopes = []string{}
	for _, sc := range strings.Split(scopes, ",") {
		if sc = strings.TrimSpace(sc); sc != "" {
			t.Scopes = append(t.Scopes, sc)
		}
	}
	if lastUsed.Valid {
		t.LastUsedAt = &lastUsed.Time
	}
	if expires.Valid {
		t.ExpiresAt = &expires.Time
	}
	if revoked.Valid {
		t.RevokedAt = &revoked.Time
	}
	return &t, nil
}

// CreateAPIToken stores a new token and returns it with its plaintext, which
// is never retrievable again. expiresAt nil means it never expires.
func (d *DB) CreateAPIToken(name string, scopes []string, expiresAt *time.Time) (*APIToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, "", fmt.Errorf("%w: a name is required", ErrAPITokenInvalid)
	}
	if utf8.RuneCountInString(name) > apiTokenNameMax {
		return nil, "", fmt.Errorf("%w: the name is longer than %d characters", ErrAPITokenInvalid, apiTokenNameMax)
	}
	scopes, err := NormalizeAPITokenScopes(scopes)
	if err != nil {
		return nil, "", err
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, "", fmt.Errorf("generate token: %w", err)
	}
	plaintext := APITokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
	hint := plaintext[len(plaintext)-4:]
	var exp any
	if expiresAt != nil {
		exp = *expiresAt
	}
	row := d.QueryRow(`INSERT INTO api_tokens(name,token_hash,token_hint,scopes,expires_at) VALUES($1,$2,$3,$4,$5) RETURNING `+apiTokenCols,
		name, HashAPIToken(plaintext), hint, strings.Join(scopes, ","), exp)
	t, err := scanAPIToken(row)
	if err != nil {
		return nil, "", err
	}
	return t, plaintext, nil
}

// APITokenByHash returns the token with that hash, or nil when none matches.
func (d *DB) APITokenByHash(hash string) (*APIToken, error) {
	t, err := scanAPIToken(d.QueryRow(`SELECT `+apiTokenCols+` FROM api_tokens WHERE token_hash=$1`, hash))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return t, err
}

// ListAPITokens returns every token, newest first.
func (d *DB) ListAPITokens() ([]*APIToken, error) {
	rows, err := d.Query(`SELECT ` + apiTokenCols + ` FROM api_tokens ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*APIToken{}
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// TouchAPIToken records a use, at most once a minute per token.
func (d *DB) TouchAPIToken(id int64) error {
	_, err := d.Exec(`UPDATE api_tokens SET last_used_at=now()
WHERE id=$1 AND (last_used_at IS NULL OR last_used_at < now() - $2::interval)`,
		id, fmt.Sprintf("%d seconds", int(apiTokenTouchEvery/time.Second)))
	return err
}

// RevokeAPIToken stops a token from working and keeps its row for the audit trail.
func (d *DB) RevokeAPIToken(id int64) error {
	res, err := d.Exec(`UPDATE api_tokens SET revoked_at=COALESCE(revoked_at, now()) WHERE id=$1`, id)
	return affectedOrNotFound(res, err)
}

// DeleteAPIToken removes a token. Its audit rows stay, with its name.
func (d *DB) DeleteAPIToken(id int64) error {
	res, err := d.Exec(`DELETE FROM api_tokens WHERE id=$1`, id)
	return affectedOrNotFound(res, err)
}

func affectedOrNotFound(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrAPITokenNotFound
	}
	return nil
}

// MCPAuditEntry is one tools/call made through /mcp.
type MCPAuditEntry struct {
	ID         int64     `json:"id"`
	TS         time.Time `json:"ts"`
	TokenID    int64     `json:"token_id"`
	TokenName  string    `json:"token_name"`
	Tool       string    `json:"tool"`
	Args       string    `json:"args"`
	OK         bool      `json:"ok"`
	Result     string    `json:"result"`
	RemoteAddr string    `json:"remote_addr"`
	DurationMS int64     `json:"duration_ms"`
}

// InsertMCPAudit records a call and prunes rows beyond the newest mcpAuditKeep.
func (d *DB) InsertMCPAudit(e MCPAuditEntry) error {
	var id int64
	if err := d.QueryRow(`INSERT INTO mcp_audit_log(token_id,token_name,tool,args,ok,result,remote_addr,duration_ms)
VALUES($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		e.TokenID, e.TokenName, e.Tool, e.Args, e.OK, e.Result, e.RemoteAddr, e.DurationMS).Scan(&id); err != nil {
		return err
	}
	if id%100 == 0 { // prune now and then, not on every call
		_, err := d.Exec(`DELETE FROM mcp_audit_log WHERE id <= $1`, id-mcpAuditKeep)
		return err
	}
	return nil
}

// ListMCPAudit returns the newest audit rows, at most limit (1..500).
func (d *DB) ListMCPAudit(limit int) ([]MCPAuditEntry, error) {
	limit = max(1, min(limit, 500))
	rows, err := d.Query(`SELECT id,ts,COALESCE(token_id,0),token_name,tool,args,ok,result,remote_addr,duration_ms
FROM mcp_audit_log ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []MCPAuditEntry{}
	for rows.Next() {
		var e MCPAuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.TokenID, &e.TokenName, &e.Tool, &e.Args, &e.OK, &e.Result, &e.RemoteAddr, &e.DurationMS); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
