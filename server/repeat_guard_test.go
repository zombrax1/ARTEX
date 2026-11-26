package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestRepeatGuardSettingHTTP(t *testing.T) {
	skipWithoutDSN(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	clear := func() {
		if _, err := m.pg.Exec(`DELETE FROM settings WHERE key=$1`, settingRepeatGuard); err != nil {
			t.Error(err)
		}
	}
	clear()
	defer clear()
	if got := repeatGuardLimits(m.pg); got != agent.DefaultRepeatGuardLimits() {
		t.Fatalf("unset: %+v, want defaults", got)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	defer stopTestServer(t, s, cancel)
	t.Cleanup(func() { agent.SetRepeatGuardSource(nil) })
	token, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, body string) (int, map[string]any) {
		t.Helper()
		req := httptest.NewRequest(method, "/api/settings", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	// A partial update keeps the other limits; out-of-range values are clamped.
	code, out := do(http.MethodPut, `{"repeat_guard":{"fail_repeats":3,"stop_after":500}}`)
	if code != 200 {
		t.Fatalf("PUT: %d %v", code, out)
	}
	rg, _ := out["repeat_guard"].(map[string]any)
	if rg["fail_repeats"] != float64(3) || rg["stop_after"] != float64(100) || rg["enabled"] != true ||
		rg["identical_repeats"] != float64(agent.DefaultRepeatGuardLimits().IdenticalRepeats) {
		t.Fatalf("after PUT: %v", rg)
	}
	if code, _ := do(http.MethodPut, `{"repeat_guard":{"fail_repeats":"x"}}`); code != 400 {
		t.Fatalf("bad PUT: %d, want 400", code)
	}
	if code, out := do(http.MethodPut, `{"repeat_guard":{"enabled":false}}`); code != 200 {
		t.Fatalf("disable: %d", code)
	} else if rg, _ := out["repeat_guard"].(map[string]any); rg["enabled"] != false || rg["fail_repeats"] != float64(3) {
		t.Fatalf("after disable: %v", rg)
	}
	// New agent runs read the stored setting: the guard is now off.
	if h := agent.RepeatGuardHooks(nil); h != nil {
		t.Fatal("guard still wraps hooks after it was disabled")
	}
}
