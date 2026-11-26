package db

import "testing"

func TestAnalyzeAccess(t *testing.T) {
	id := func(n int64) *int64 { return &n }
	results := []AccessResult{
		{CredentialID: id(1), Account: "alice", Role: "user", Org: "a", Status: 200, Length: 1000, BodyHash: "h1"},
		{CredentialID: id(2), Account: "bob", Role: "user", Org: "b", Status: 200, Length: 1000, BodyHash: "h1"},
		{CredentialID: id(3), Account: "carol", Role: "admin", Org: "a", Status: 200, Length: 980, BodyHash: "h2"},
		{CredentialID: id(4), Account: "dave", Role: "user", Org: "a", Status: 403, Length: 20},
		{CredentialID: id(5), Account: "erin", Role: "user", Org: "a", Status: 200, Length: 300, BodyHash: "h3"},
		{Account: "anonymous", Status: 401},
	}
	got := AnalyzeAccess(results, 0)
	want := map[string]string{"bob": AccessCrossOrg, "carol": AccessCrossRole}
	if len(got) != len(want) {
		t.Fatalf("flags = %+v", got)
	}
	for _, f := range got {
		if want[f.Account] != f.Kind {
			t.Errorf("%s flagged %s, want %s", f.Account, f.Kind, want[f.Account])
		}
	}
	if got[1].Match != "similar" || got[0].Match != "identical" {
		t.Errorf("matches = %+v", got)
	}
	// The owner's request failing means nothing to compare against.
	results[0].Status = 404
	if got := AnalyzeAccess(results, 0); len(got) != 0 {
		t.Fatalf("owner failed, flags = %+v", got)
	}
	// No owner: only anonymous access to an authenticated response is flagged.
	results[0].Status = 200
	results[5] = AccessResult{Account: "anonymous", Status: 200, Length: 1000, BodyHash: "h1"}
	if got := AnalyzeAccess(results, -1); len(got) != 1 || got[0].Kind != AccessUnauthenticated {
		t.Fatalf("no owner, flags = %+v", got)
	}
	if got := AnalyzeAccess(results, 0); got[len(got)-1].Kind != AccessUnauthenticated {
		t.Fatalf("anonymous with owner, flags = %+v", got)
	}
}

func TestParseAuthHeaders(t *testing.T) {
	h, err := ParseAuthHeaders("Cookie: sid=1; x=2\n\nAuthorization: Bearer abc\n")
	if err != nil || len(h) != 2 || h[0][0] != "Cookie" || h[1][1] != "Bearer abc" {
		t.Fatalf("parsed %v, %v", h, err)
	}
	for _, bad := range []string{"no colon here", "Bad Name: x", ": empty"} {
		if _, err := ParseAuthHeaders(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
