package db

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestAPITokenLifecycle(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()

	if _, _, err := d.CreateAPIToken(" ", []string{APIScopeRead}, nil); !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("empty name: %v", err)
	}
	if _, _, err := d.CreateAPIToken("x", nil, nil); !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("no scopes: %v", err)
	}
	if _, _, err := d.CreateAPIToken("x", []string{"admin"}, nil); !errors.Is(err, ErrAPITokenInvalid) {
		t.Fatalf("unknown scope: %v", err)
	}

	exp := time.Now().Add(24 * time.Hour)
	tok, plain, err := d.CreateAPIToken("  laptop  ", []string{APIScopeTaskControl, APIScopeRead, APIScopeRead}, &exp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM api_tokens WHERE id=$1`, tok.ID) })
	if !strings.HasPrefix(plain, APITokenPrefix) || len(plain) < len(APITokenPrefix)+40 {
		t.Fatalf("plaintext %q", plain)
	}
	if tok.Name != "laptop" || tok.Hint != plain[len(plain)-4:] || strings.Join(tok.Scopes, ",") != "read,task:control" {
		t.Fatalf("created token: %+v", tok)
	}
	var stored string
	if err := d.QueryRow(`SELECT token_hash FROM api_tokens WHERE id=$1`, tok.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == plain || stored != HashAPIToken(plain) {
		t.Fatal("only the SHA-256 of the token may be stored")
	}

	got, err := d.APITokenByHash(HashAPIToken(plain))
	if err != nil || got == nil || got.ID != tok.ID || !got.Usable(time.Now()) || !got.HasScope(APIScopeTaskControl) || got.HasScope(APIScopeTaskCreate) {
		t.Fatalf("lookup: %+v %v", got, err)
	}
	if got.Usable(exp.Add(time.Second)) {
		t.Fatal("token usable after its expiry")
	}
	if none, err := d.APITokenByHash(HashAPIToken(plain + "x")); none != nil || err != nil {
		t.Fatalf("unknown hash: %+v %v", none, err)
	}

	if err := d.TouchAPIToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	list, err := d.ListAPITokens()
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, x := range list {
		if x.ID == tok.ID {
			found = x.LastUsedAt != nil
		}
	}
	if !found {
		t.Fatal("listed token without last_used_at after a touch")
	}

	if err := d.RevokeAPIToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := d.APITokenByHash(HashAPIToken(plain)); got == nil || got.Usable(time.Now()) {
		t.Fatalf("revoked token still usable: %+v", got)
	}
	if err := d.DeleteAPIToken(tok.ID); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteAPIToken(tok.ID); !errors.Is(err, ErrAPITokenNotFound) {
		t.Fatalf("second delete: %v", err)
	}
	if err := d.RevokeAPIToken(tok.ID); !errors.Is(err, ErrAPITokenNotFound) {
		t.Fatalf("revoke of a deleted token: %v", err)
	}
}

func TestMCPAuditInsertAndList(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		SkipPGUnavailable(t, err)
	}
	defer d.Close()
	marker := "audit-test-" + time.Now().Format("150405.000000")
	if err := d.InsertMCPAudit(MCPAuditEntry{TokenID: 42, TokenName: marker, Tool: "list_tasks", Args: "{}", OK: true, Result: "[]", RemoteAddr: "127.0.0.1", DurationMS: 3}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Exec(`DELETE FROM mcp_audit_log WHERE token_name=$1`, marker) })
	rows, err := d.ListMCPAudit(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 || rows[0].TokenName != marker || rows[0].Tool != "list_tasks" || !rows[0].OK || rows[0].TokenID != 42 {
		t.Fatalf("newest audit row: %+v", rows)
	}
}
