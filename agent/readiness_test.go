package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// scriptedModel answers OpenAI chat completions from a list of replies, one per
// request. A reply is either text or a single tool call.
type scriptedReply struct {
	text string
	tool string
	args string
}

func scriptedServer(t *testing.T, replies []scriptedReply) (*httptest.Server, *int) {
	t.Helper()
	var mu sync.Mutex
	n := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		i := n
		n++
		mu.Unlock()
		rep := scriptedReply{text: "ok"}
		if i < len(replies) {
			rep = replies[i]
		}
		msg := map[string]any{"role": "assistant", "content": rep.text}
		finish := "stop"
		if rep.tool != "" {
			msg["content"] = nil
			msg["tool_calls"] = []any{map[string]any{"id": "call_" + rep.tool, "type": "function",
				"function": map[string]any{"name": rep.tool, "arguments": rep.args}}}
			finish = "tool_calls"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "x", "object": "chat.completion", "model": "m",
			"choices": []any{map[string]any{"index": 0, "message": msg, "finish_reason": finish}},
			"usage":   map[string]any{"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func runScripted(t *testing.T, replies []scriptedReply) ReadinessReport {
	t.Helper()
	srv, _ := scriptedServer(t, replies)
	cfg := ConfigFrom("openai", "m", srv.URL, "k", "")
	cfg.Stream = false
	prov, err := cfg.NewProvider()
	if err != nil {
		t.Fatal(err)
	}
	return RunReadiness(context.Background(), prov, cfg)
}

func TestReadinessReady(t *testing.T) {
	r := runScripted(t, []scriptedReply{
		{tool: "record_port", args: `{"host":"192.0.2.10","port":8443,"protocol":"tcp","state":"open"}`},
		{text: "DONE"},
		{tool: "run_command", args: `{"command":"curl -sI http://192.0.2.20/"}`},
		{tool: "report_observation", args: `{"title":"Server version disclosed: Apache/2.4.49","severity":"low","evidence":"Server: Apache/2.4.49 (Unix)"}`},
		{text: "The server discloses Apache 2.4.49."},
	})
	if r.Verdict != ReadinessReady || len(r.Checks) != 2 {
		t.Fatalf("verdict %s: %+v", r.Verdict, r.Checks)
	}
}

func TestReadinessTextToolCall(t *testing.T) {
	r := runScripted(t, []scriptedReply{
		{text: `{"name": "record_port", "arguments": {"host": "192.0.2.10", "port": 8443}}`},
	})
	if r.Verdict != ReadinessNotReady || len(r.Checks) != 1 {
		t.Fatalf("verdict %s: %+v", r.Verdict, r.Checks)
	}
	if p := strings.Join(r.Checks[0].Problems, " "); !strings.Contains(p, "as text") {
		t.Fatalf("problems = %q", p)
	}
}

func TestReadinessWrongArgumentTypes(t *testing.T) {
	r := runScripted(t, []scriptedReply{
		{tool: "record_port", args: `{"host":"192.0.2.10","port":"8443","protocol":"TCP","state":"open"}`},
		{text: "DONE"},
	})
	if r.Verdict != ReadinessNotReady {
		t.Fatalf("verdict %s", r.Verdict)
	}
	p := strings.Join(r.Checks[0].Problems, " ")
	// An enum value in another case is not the declared value.
	for _, want := range []string{"as a string", "protocol is TCP"} {
		if !strings.Contains(p, want) {
			t.Errorf("problems %q miss %q", p, want)
		}
	}
}

func TestReadinessLimited(t *testing.T) {
	r := runScripted(t, []scriptedReply{
		{tool: "record_port", args: `{"host":"192.0.2.10","port":8443,"protocol":"tcp","state":"open"}`},
		{text: "DONE"},
		// reports without fetching, and invents the version
		{tool: "report_observation", args: `{"title":"Server version","severity":"urgent","evidence":"Server: nginx"}`},
		{text: "Done."},
	})
	if r.Verdict != ReadinessLimited {
		t.Fatalf("verdict %s: %+v", r.Verdict, r.Checks)
	}
	p := strings.Join(r.Checks[1].Problems, " ")
	for _, want := range []string{"did not fetch", "2.4.49", "severity"} {
		if !strings.Contains(p, want) {
			t.Errorf("problems %q miss %q", p, want)
		}
	}
}

func TestReadinessMissingRequiredReportField(t *testing.T) {
	r := runScripted(t, []scriptedReply{
		{tool: "record_port", args: `{"host":"192.0.2.10","port":8443,"protocol":"tcp","state":"open"}`},
		{text: "DONE"},
		{tool: "run_command", args: `{"command":"curl -sI http://192.0.2.20/"}`},
		{tool: "report_observation", args: `{"title":"Apache/2.4.49","severity":"low"}`},
		{text: "Done."},
	})
	if r.Verdict != ReadinessLimited {
		t.Fatalf("verdict %s: %+v", r.Verdict, r.Checks)
	}
	if p := strings.Join(r.Checks[1].Problems, " "); !strings.Contains(p, "evidence is missing") {
		t.Fatalf("problems = %q", p)
	}
}

func TestReadinessTaskNeedsHTTPFetch(t *testing.T) {
	r := runScripted(t, []scriptedReply{
		{tool: "record_port", args: `{"host":"192.0.2.10","port":8443,"protocol":"tcp","state":"open"}`},
		{text: "DONE"},
		// names the host but runs no HTTP request, then reports anyway
		{tool: "run_command", args: `{"command":"192.0.2.20"}`},
		{tool: "report_observation", args: `{"title":"Apache/2.4.49","severity":"low","evidence":"Server: Apache/2.4.49 (Unix)"}`},
		{text: "Done."},
	})
	if r.Verdict == ReadinessReady {
		t.Fatalf("verdict %s without an HTTP fetch: %+v", r.Verdict, r.Checks)
	}
	if p := strings.Join(r.Checks[1].Problems, " "); !strings.Contains(p, "did not fetch") {
		t.Fatalf("problems = %q", p)
	}
	for _, cmd := range []string{"curl -sI http://192.0.2.20/", "wget -S -O- 192.0.2.20", "http HEAD 192.0.2.20"} {
		if !headerFetch(json.RawMessage(`{"command":"` + cmd + `"}`)) {
			t.Errorf("%q is a fetch", cmd)
		}
	}
}
