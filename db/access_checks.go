package db

import (
	"encoding/json"
	"fmt"
	"time"
)

// AccessResult is one account's response to a replayed request.
type AccessResult struct {
	CredentialID *int64 `json:"credential_id"` // nil = anonymous (no session headers)
	Account      string `json:"account"`       // username, or "anonymous"
	Role         string `json:"role,omitempty"`
	Org          string `json:"org,omitempty"`
	Status       int    `json:"status"`
	Length       int    `json:"length"`
	BodyHash     string `json:"body_hash,omitempty"`
	Snippet      string `json:"snippet,omitempty"`
	Error        string `json:"error,omitempty"`
}

// Access flag kinds: an account got the owner's response although it should not.
const (
	AccessUnauthenticated = "unauthenticated_access" // no session at all
	AccessCrossOrg        = "cross_org_access"       // another organisation
	AccessCrossRole       = "cross_role_access"      // same organisation, another role
	AccessCrossUser       = "cross_user_access"      // same role and organisation, another account
)

// AccessFlag marks a response that matches the owner's and may be broken access control.
type AccessFlag struct {
	Kind    string `json:"kind"`
	Account string `json:"account"`
	Match   string `json:"match"` // identical | similar
	Detail  string `json:"detail"`
}

// AccessCheck is one stored comparison.
type AccessCheck struct {
	ID        int64          `json:"id"`
	TaskID    int64          `json:"task_id"`
	Method    string         `json:"method"`
	URL       string         `json:"url"`
	OwnerID   *int64         `json:"owner_id,omitempty"`
	Results   []AccessResult `json:"results"`
	Flags     []AccessFlag   `json:"flags"`
	CheckedBy string         `json:"checked_by,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

func ok2xx(s int) bool { return s >= 200 && s < 300 }

// sameResponse compares two successful responses: identical bodies, or the same
// status with lengths within 5% (pages that embed a token or a timestamp).
func sameResponse(a, b AccessResult) string {
	if a.Status != b.Status || a.Error != "" || b.Error != "" {
		return ""
	}
	if a.BodyHash != "" && a.BodyHash == b.BodyHash {
		return "identical"
	}
	if a.Length == 0 || b.Length == 0 {
		return ""
	}
	lo, hi := a.Length, b.Length
	if lo > hi {
		lo, hi = hi, lo
	}
	if float64(lo)/float64(hi) >= 0.95 {
		return "similar"
	}
	return ""
}

// AnalyzeAccess flags accounts that got the owner's successful response.
// ownerIdx < 0 means no owner was named: then only anonymous access to a
// response an authenticated account also got is flagged.
func AnalyzeAccess(results []AccessResult, ownerIdx int) []AccessFlag {
	flags := []AccessFlag{}
	if ownerIdx < 0 {
		var anon *AccessResult
		for i := range results {
			if results[i].CredentialID == nil {
				anon = &results[i]
			}
		}
		if anon == nil || !ok2xx(anon.Status) {
			return flags
		}
		for _, r := range results {
			if r.CredentialID == nil || !ok2xx(r.Status) {
				continue
			}
			if m := sameResponse(*anon, r); m != "" {
				flags = append(flags, AccessFlag{Kind: AccessUnauthenticated, Account: anon.Account, Match: m,
					Detail: fmt.Sprintf("without a session the response matches %s's (%d, %d bytes)", r.Account, r.Status, r.Length)})
				break
			}
		}
		return flags
	}
	if ownerIdx >= len(results) {
		return flags
	}
	owner := results[ownerIdx]
	if !ok2xx(owner.Status) {
		return flags
	}
	for i, r := range results {
		if i == ownerIdx || !ok2xx(r.Status) {
			continue
		}
		m := sameResponse(owner, r)
		if m == "" {
			continue
		}
		f := AccessFlag{Account: r.Account, Match: m}
		switch {
		case r.CredentialID == nil:
			f.Kind = AccessUnauthenticated
			f.Detail = fmt.Sprintf("without a session the response matches the owner %s's", owner.Account)
		case r.Org != owner.Org && r.Org != "" && owner.Org != "":
			f.Kind = AccessCrossOrg
			f.Detail = fmt.Sprintf("%s (org %s) gets the response of %s (org %s)", r.Account, r.Org, owner.Account, owner.Org)
		case r.Role != owner.Role:
			f.Kind = AccessCrossRole
			f.Detail = fmt.Sprintf("%s (role %s) gets the response of %s (role %s)", r.Account, orDash(r.Role), owner.Account, orDash(owner.Role))
		default:
			f.Kind = AccessCrossUser
			f.Detail = fmt.Sprintf("%s gets the response of %s, with the same role and organisation; fine for shared data, an IDOR for private data", r.Account, owner.Account)
		}
		flags = append(flags, f)
	}
	return flags
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// CreateAccessCheck stores one comparison.
func (d *DB) CreateAccessCheck(c *AccessCheck) error {
	results, _ := json.Marshal(c.Results)
	flags, _ := json.Marshal(c.Flags)
	return d.QueryRow(`INSERT INTO access_checks (task_id, method, url, owner_id, results, flags, checked_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`,
		c.TaskID, c.Method, c.URL, c.OwnerID, results, flags, c.CheckedBy).Scan(&c.ID, &c.CreatedAt)
}

// AccessChecks lists a task's comparisons, newest first.
func (d *DB) AccessChecks(taskID int64, limit int) ([]AccessCheck, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	rows, err := d.Query(`SELECT id, task_id, method, url, owner_id, results, flags, checked_by, created_at
		FROM access_checks WHERE task_id = $1 ORDER BY id DESC LIMIT $2`, taskID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AccessCheck{}
	for rows.Next() {
		var c AccessCheck
		var results, flags []byte
		if err := rows.Scan(&c.ID, &c.TaskID, &c.Method, &c.URL, &c.OwnerID, &results, &flags, &c.CheckedBy, &c.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(results, &c.Results)
		_ = json.Unmarshal(flags, &c.Flags)
		if c.Flags == nil {
			c.Flags = []AccessFlag{}
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
