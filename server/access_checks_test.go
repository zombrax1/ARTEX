package server

import (
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
	add := func(user, role, org, headers string) int64 {
		c, err := pg.UpsertTaskCredential(tid, db.TaskCredentialInput{Domain: "lab.example", Username: user, Password: "pw-" + user,
			Role: role, Org: org, AuthHeaders: headers})
		if err != nil {
			t.Fatal(err)
		}
		return c.ID
	}
	alice := add("alice", "user", "org-a", "Cookie: session=alice")
	bob := add("bob", "user", "org-b", "Cookie: session=bob")
	add("carol", "user", "org-a", "Cookie: session=carol")
	add("dave", "user", "org-a", "") // no session: skipped by default

	ctx := context.Background()
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

	// A named account without session headers is refused, not silently anonymous.
	if _, err := s.runAccessCheck(ctx, "compare_access", tid, agent.AccessCheckRequest{URL: target.URL + "/orders/1", Accounts: []int64{alice, alice + 3}}); err == nil || !strings.Contains(err.Error(), "no session headers") {
		t.Fatalf("account without headers: %v", err)
	}

	w := request("GET", "/api/tasks/"+taskID+"/access-checks", "")
	var list []db.AccessCheck
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &list) != nil || len(list) != 1 || len(list[0].Flags) != 1 {
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
