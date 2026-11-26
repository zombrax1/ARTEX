package db

import (
	"testing"
	"time"

	"github.com/Autumn-27/artex/apidef"
)

func TestAPICoverage(t *testing.T) {
	imported := time.Unix(1000, 0)
	ops := []APIOperation{
		{ID: 1, Method: "GET", Path: "/users/{id}", BaseURL: "https://api.example/v1", ImportedAt: imported},
		{ID: 2, Method: "DELETE", Path: "/users/{id}", BaseURL: "https://api.example/v1", ImportedAt: imported},
		{ID: 3, Method: "POST", Path: "/admin", BaseURL: "https://api.example/v1", ImportedAt: imported, Mark: "skipped", MarkNote: "destructive"},
		{ID: 4, Method: "GET", Path: "/health", BaseURL: "https://api.example/v1", ImportedAt: imported, Mark: "tested"},
	}
	ex := []APIExchange{
		{ID: "e3", TS: 1200, Method: "GET", URL: "https://api.example/v1/users/7?x=1"},
		{ID: "e2", TS: 1100, Method: "GET", URL: "https://api.example/v1/users/6"},
		{ID: "e1", TS: 900, Method: "DELETE", URL: "https://api.example/v1/users/6"}, // before the import
		{ID: "e0", TS: 1300, Method: "POST", URL: "https://api.example/v1/admin"},
	}
	got := APICoverage(ops, ex)
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
	_ = apidef.Param{}
}
