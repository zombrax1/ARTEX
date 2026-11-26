package db

import (
	"testing"
	"time"
)

func TestMatchAPIExchanges(t *testing.T) {
	imported := time.Unix(1000, 0)
	ops := []APIOperation{
		{ID: 1, Method: "GET", Path: "/users/{id}", BaseURL: "https://api.example/v1", ImportedAt: imported},
		{ID: 2, Method: "DELETE", Path: "/users/{id}", BaseURL: "https://api.example/v1", ImportedAt: imported},
		{ID: 3, Method: "POST", Path: "/admin", BaseURL: "https://api.example/v1", ImportedAt: imported},
		{ID: 5, Method: "GET", Path: "/users/me", BaseURL: "https://api.example/v1", ImportedAt: imported},
	}
	ex := []APIExchange{
		{ID: "e1", TS: 900, Method: "DELETE", URL: "https://api.example/v1/users/6"}, // before the import
		{ID: "e2", TS: 1100, Method: "GET", URL: "https://api.example/v1/users/6"},
		{ID: "e3", TS: 1200, Method: "GET", URL: "https://api.example/v1/users/7?x=1"},
		{ID: "e4", TS: 1250, Method: "GET", URL: "https://api.example/v1/users/me"}, // the concrete operation only
		{ID: "e0", TS: 1300, Method: "POST", URL: "https://api.example/v1/admin"},
	}
	got := MatchAPIExchanges(ops, ex)
	want := map[int64]APIObservation{1: {Requests: 2, Last: "e3"}, 3: {Requests: 1, Last: "e0"}, 5: {Requests: 1, Last: "e4"}}
	if len(got) != len(want) {
		t.Fatalf("got %+v", got)
	}
	for id, w := range want {
		if got[id].Requests != w.Requests || got[id].Last != w.Last {
			t.Errorf("op %d: %+v, want %+v", id, got[id], w)
		}
	}
}

func TestAPICoverage(t *testing.T) {
	ops := []APIOperation{
		{ID: 1, SeenRequests: 2, SeenLast: "e3"},
		{ID: 2},
		{ID: 3, Mark: "skipped", MarkNote: "destructive", SeenRequests: 1, SeenLast: "e0"},
		{ID: 4, Mark: "tested"},
	}
	got := APICoverage(ops)
	want := []struct {
		status string
		n      int
		last   string
	}{{"tested", 2, "e3"}, {"untested", 0, ""}, {"skipped", 1, "e0"}, {"tested", 0, ""}}
	for i, w := range want {
		if got[i].Status != w.status || got[i].Requests != w.n || got[i].LastExchange != w.last {
			t.Errorf("op %d: %+v, want %+v", ops[i].ID, got[i], w)
		}
	}
}
