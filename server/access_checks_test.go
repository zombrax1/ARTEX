package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
)

func TestCompareAccessFlagsCrossOrgResponse(t *testing.T) {
	s, _, request := trafficEvidenceServer(t)
	var taskID string
	for _, tk := range s.m.List() {
		if tk.Description == "traffic evidence API" {
			taskID = tk.ID
		}
	}
	tid, _ := strconv.ParseInt(taskID, 10, 64)

	// alice owns order 1; bob (another organisation) also gets it: the bug.
	var sawAnonCookie bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/huge" {
			// Same prefix for everyone, then a per-session tail past the cap.
			_, _ = w.Write(bytes.Repeat([]byte("a"), maxAccessBody))
			_, _ = w.Write([]byte("|" + r.Header.Get("Cookie")))
			return
		}
		if r.URL.Path == "/truncated" {
			w.Header().Set("Content-Length", "100")
			_, _ = w.Write([]byte(`{"order":1`))
			return
		}
		switch r.Header.Get("Cookie") {
		case "session=alice", "session=bob":
			_, _ = w.Write([]byte(`{"order":1,"owner":"alice","total":42}`))
		case "session=carol":
			w.WriteHeader(http.StatusForbidden)
		default:
			if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
				sawAnonCookie = true
			}
			http.Redirect(w, r, "/login", http.StatusFound)
		}
	}))
	defer target.Close()

	pg := s.m.PG()
	host := strings.TrimPrefix(target.URL, "http://") // 127.0.0.1:port; the port is ignored
	addFor := func(domain, user, role, org, headers string) int64 {
		c, err := pg.UpsertTaskCredential(tid, db.TaskCredentialInput{Domain: domain, Username: user, Password: "pw-" + user,
			Role: role, Org: org, AuthHeaders: headers})
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	add := func(user, role, org, headers string) int64 { return addFor(host, user, role, org, headers) }
	// A session for another site is never sent to this one.
	elsewhere := addFor("other.example", "mallory", "admin", "org-a", "Cookie: session=alice")
	alice := add("alice", "user", "org-a", "Cookie: session=alice")
	bob := add("bob", "user", "org-b", "Cookie: session=bob")
	add("carol", "user", "org-a", "Cookie: session=carol")
	add("dave", "user", "org-a", "") // no session: skipped by default

	ctx := context.Background()
	if _, err := s.runAccessCheck(ctx, "compare_access", tid, agent.AccessCheckRequest{URL: strings.Replace(target.URL, "http://", "http://alice:pw@", 1) + "/orders/1"}); err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Fatalf("URL with userinfo: %v", err)
	}
	if _, err := s.runAccessCheck(ctx, "compare_access", tid, agent.AccessCheckRequest{Method: "DELETE", URL: target.URL + "/orders/1"}); err == nil {
		t.Fatal("DELETE ran without allow_state_change")
	}
	c, err := s.runAccessCheck(ctx, "compare_access", tid, agent.AccessCheckRequest{
		URL: target.URL + "/orders/1", Owner: alice, Headers: map[string]string{"Cookie": "session=alice", "Accept": "application/json"}, CheckedBy: "test",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Results) != 4 {
		t.Fatalf("results = %+v, want alice, bob, carol and anonymous", c.Results)
	}
	if sawAnonCookie {
		t.Fatal("the anonymous request carried a session header")
	}
	anon := c.Results[3]
	if anon.CredentialID != nil || anon.Status != http.StatusFound || !strings.Contains(anon.Snippet, "/login") {
		t.Fatalf("anonymous result = %+v", anon)
	}
	if len(c.Flags) != 1 || c.Flags[0].Kind != db.AccessCrossOrg || c.Flags[0].Account != "bob" || c.Flags[0].Match != "identical" {
		t.Fatalf("flags = %+v", c.Flags)
	}

	if _, err := s.runAccessCheck(ctx, "compare_access", tid, agent.AccessCheckRequest{URL: target.URL + "/orders/1", Accounts: []int64{alice, elsewhere}}); err == nil || !strings.Contains(err.Error(), "not sent to another host") {
		t.Fatalf("account of another domain: %v", err)
	}

	// A body cut short is recorded as an error and never compared.
	tc, err := s.runAccessCheck(ctx, "compare_access", tid, agent.AccessCheckRequest{URL: target.URL + "/truncated", Owner: alice})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range tc.Results {
		if r.Error == "" {
			t.Fatalf("truncated body without an error: %+v", r)
		}
	}
	if len(tc.Flags) != 0 {
		t.Fatalf("flags on truncated bodies: %+v", tc.Flags)
	}

	// A body past the cap is recorded as an error and never compared.
	tc, err = s.runAccessCheck(ctx, "compare_access", tid, agent.AccessCheckRequest{URL: target.URL + "/huge", Owner: alice})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range tc.Results {
		if r.Error == "" || r.BodyHash != "" {
			t.Fatalf("oversized body compared: %+v", r)
		}
	}
	if len(tc.Flags) != 0 {
		t.Fatalf("flags on oversized bodies: %+v", tc.Flags)
	}

	// A named account without session headers is refused, not silently anonymous.
	if _, err := s.runAccessCheck(ctx, "compare_access", tid, agent.AccessCheckRequest{URL: target.URL + "/orders/1", Accounts: []int64{alice, alice + 3}}); err == nil || !strings.Contains(err.Error(), "no session headers") {
		t.Fatalf("account without headers: %v", err)
	}

	w := request("GET", "/api/tasks/"+taskID+"/access-checks", "")
	var list []db.AccessCheck
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list) != 3 || len(list[2].Flags) != 1 {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}

	// The credential API reports role, org and whether headers are set, never the headers.
	w = request("GET", "/api/tasks/"+taskID+"/credentials", "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "session=alice") || !strings.Contains(w.Body.String(), `"auth_headers_set":true`) || !strings.Contains(w.Body.String(), `"org":"org-b"`) {
		t.Fatalf("credentials: %s", w.Body.String())
	}

	// Replacing a session keeps the password; an empty value clears it.
	base := "/api/tasks/" + taskID + "/credentials/" + strconv.FormatInt(bob, 10) + "/session"
	if w := request("PUT", base, `{"auth_headers":"not a header"}`); w.Code != http.StatusBadRequest {
		t.Fatalf("bad headers: %d", w.Code)
	}
	if w := request("PUT", base, `{"auth_headers":""}`); w.Code != 200 {
		t.Fatalf("clear: %d %s", w.Code, w.Body.String())
	}
	creds, _ := pg.TaskCredentials(tid)
	for _, c := range creds {
		if c.ID == bob && (c.AuthHeaders != "" || c.Password != "pw-bob") {
			t.Fatalf("after clear: %+v", c)
		}
	}
}

func TestCredentialCovers(t *testing.T) {
	for _, c := range []struct {
		domain, host string
		want         bool
	}{
		{"example.com", "example.com", true},
		{"https://Example.com:8443/login", "example.com", true},
		{"example.com", "api.example.com", true},
		{"*.example.com", "api.example.com", true},
		{"api.example.com", "example.com", false},
		{"example.com", "badexample.com", false},
		{"other.example", "127.0.0.1", false},
		{"127.0.0.1:8080", "127.0.0.1", true},
		{"", "example.com", false},
	} {
		if got := credentialCovers(c.domain, c.host); got != c.want {
			t.Errorf("credentialCovers(%q, %q) = %v, want %v", c.domain, c.host, got, c.want)
		}
	}
}

func TestRefreshCredentialToolSchema(t *testing.T) {
	s, _, _ := trafficEvidenceServer(t)
	pg := s.m.PG()
	// An installation seeded before multiple-account testing.
	if _, err := pg.Exec(`UPDATE tools SET schema='{"type":"object","properties":{"password":{"type":"string"}}}'::jsonb WHERE key='save_task_credential'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pg.Exec(`DELETE FROM settings WHERE key='tool_schema_refresh_save_task_credential_v2'`); err != nil {
		t.Fatal(err)
	}
	s.refreshCredentialToolSchema()
	var schema string
	if err := pg.QueryRow(`SELECT schema::text FROM tools WHERE key='save_task_credential'`).Scan(&schema); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"auth_headers", "role", "org"} {
		if !strings.Contains(schema, want) {
			t.Errorf("schema %s misses %s", schema, want)
		}
	}
}
