package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/llm"
	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
	"github.com/Autumn-27/norma/transcript"
)

// Model readiness test.
//
// ARTEX agents work only through tool calls. A model can advertise tool support
// and still be unusable: it writes the call as text, sends a port number as a
// string, invents a tool name, or stops after the first result. The readiness test
// measures what the model actually does, with two short checks run on the
// profile's own provider (so its rate limits and concurrency cap apply):
//
//   - tool_call: one tool with a typed schema; the model must call it with the
//     exact values from the prompt, then answer after the tool result.
//   - task: a small representative security task with two tools; the model must
//     fetch a response with one tool, read the result and report it with the other.
//
// Nothing leaves ARTEX except the model requests: the tools are stubs that return
// canned output and never run a command.

// ReadinessCheck is the result of one check.
type ReadinessCheck struct {
	ID        string   `json:"id"`
	Passed    bool     `json:"passed"`
	LatencyMS int64    `json:"latency_ms"`
	Problems  []string `json:"problems,omitempty"` // why it failed, in plain words
	Reply     string   `json:"reply,omitempty"`    // the model's final text, clipped
	Calls     []string `json:"calls,omitempty"`    // the tool calls it made, clipped
}

// ReadinessReport is the outcome of a readiness test.
type ReadinessReport struct {
	Model     string           `json:"model"`
	Verdict   string           `json:"verdict"` // ready | limited | not_ready
	Summary   string           `json:"summary"`
	Checks    []ReadinessCheck `json:"checks"`
	TestedAt  time.Time        `json:"tested_at"`
	LatencyMS int64            `json:"latency_ms"`
}

// Readiness verdicts.
const (
	ReadinessReady    = "ready"
	ReadinessLimited  = "limited"
	ReadinessNotReady = "not_ready"
)

// readinessCallTimeout bounds one check. Local models on modest GPUs can take a
// while to load, so this is generous; the whole test runs at most two checks.
const readinessCallTimeout = 3 * time.Minute

type recordedCall struct {
	name  string
	input json.RawMessage
}

type callLog struct {
	mu    sync.Mutex
	calls []recordedCall
}

func (l *callLog) add(name string, in json.RawMessage) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls = append(l.calls, recordedCall{name: name, input: append(json.RawMessage(nil), in...)})
}

func (l *callLog) snapshot() []recordedCall {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]recordedCall(nil), l.calls...)
}

func (l *callLog) labels() []string {
	var out []string
	for _, c := range l.snapshot() {
		s := c.name + " " + string(c.input)
		if len(s) > 300 {
			s = s[:300] + "…"
		}
		out = append(out, s)
	}
	return out
}

func readinessTool(log *callLog, name, desc string, schema map[string]any, reply func(json.RawMessage) string) actool.CoreTool {
	return actool.Build(actool.Spec{
		Name: name, Description: desc, Schema: schema, RawInput: true, // validated here, so bad arguments are measured, not rejected
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(_ context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			log.add(name, in)
			return actool.Text(reply(in)), nil
		},
	})
}

// runReadinessPrompt runs one check: a fresh session with only the given tools.
func runReadinessPrompt(ctx context.Context, prov llm.Provider, c Config, system, prompt string, tools []actool.CoreTool, maxTurns int) (string, time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, readinessCallTimeout)
	defer cancel()
	ctx = transcript.WithSessionID(ctx, "readiness-"+transcript.NewSessionID())
	start := time.Now()
	reply, err := agentcore.Run(ctx, agentcore.Options{
		Provider:               prov,
		SystemPrompt:           []string{system},
		Tools:                  tools,
		DisableBackgroundTasks: true, // only the test's own tools are offered
		PermissionMode:         acperm.ModeBypass,
		MaxTurns:               maxTurns,
		MaxTokens:              8192, // reasoning models think before acting; see TestConnection
		NonStreaming:           !c.Stream,
	}, prompt)
	return strings.TrimSpace(reply), time.Since(start), err
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// textToolCall reports whether a reply looks like a tool call written as text,
// which is how models without working tool support usually fail.
func textToolCall(reply string, names ...string) bool {
	low := strings.ToLower(reply)
	for _, n := range names {
		if strings.Contains(low, `"`+n+`"`) || strings.Contains(low, n+"(") || strings.Contains(low, "<tool_call>") {
			return true
		}
	}
	return strings.Contains(low, `"arguments"`) && strings.Contains(low, `"name"`)
}

const readinessSystem = "You are a security testing agent. You act only through the tools you are given. When a tool fits the request, call it; do not describe the call in text."

func checkToolCall(ctx context.Context, prov llm.Provider, c Config) ReadinessCheck {
	ch := ReadinessCheck{ID: "tool_call"}
	log := &callLog{}
	schema := obj(map[string]any{
		"host":     str("IP address or hostname"),
		"port":     map[string]any{"type": "integer", "minimum": 1, "maximum": 65535, "description": "port number"},
		"protocol": map[string]any{"type": "string", "enum": []string{"tcp", "udp"}},
		"state":    map[string]any{"type": "string", "enum": []string{"open", "closed", "filtered"}},
	}, "host", "port", "protocol", "state")
	tool := readinessTool(log, "record_port", "Record the state of one network port.", schema, func(json.RawMessage) string {
		return "Recorded."
	})
	reply, lat, err := runReadinessPrompt(ctx, prov, c, readinessSystem,
		"A scan of 192.0.2.10 found TCP port 8443 open. Record it with the record_port tool, then reply with the single word DONE.",
		[]actool.CoreTool{tool}, 3)
	ch.LatencyMS, ch.Reply, ch.Calls = lat.Milliseconds(), clip(reply, 300), log.labels()
	if err != nil {
		ch.Problems = append(ch.Problems, "The request failed: "+err.Error())
	}
	calls := log.snapshot()
	if len(calls) == 0 {
		if textToolCall(reply, "record_port") {
			ch.Problems = append(ch.Problems, "The model wrote the tool call as text instead of calling the tool. Its tool support does not work through this endpoint.")
		} else if err == nil {
			ch.Problems = append(ch.Problems, "The model did not call the tool.")
		}
		return ch
	}
	var in map[string]any
	if json.Unmarshal(calls[0].input, &in) != nil {
		ch.Problems = append(ch.Problems, "The tool arguments are not valid JSON.")
		return ch
	}
	if h, _ := in["host"].(string); strings.TrimSpace(h) != "192.0.2.10" {
		ch.Problems = append(ch.Problems, fmt.Sprintf("host is %v, expected 192.0.2.10.", in["host"]))
	}
	switch p := in["port"].(type) {
	case float64:
		if p != 8443 {
			ch.Problems = append(ch.Problems, fmt.Sprintf("port is %v, expected 8443.", p))
		}
	case string:
		ch.Problems = append(ch.Problems, "port was sent as a string, not as the integer the schema asks for.")
	default:
		ch.Problems = append(ch.Problems, "port is missing.")
	}
	if p, _ := in["protocol"].(string); strings.ToLower(p) != "tcp" {
		ch.Problems = append(ch.Problems, fmt.Sprintf("protocol is %v, expected tcp.", in["protocol"]))
	}
	if s, _ := in["state"].(string); strings.ToLower(s) != "open" {
		ch.Problems = append(ch.Problems, fmt.Sprintf("state is %v, expected open.", in["state"]))
	}
	if len(calls) > 1 {
		ch.Problems = append(ch.Problems, fmt.Sprintf("The tool was called %d times for one port.", len(calls)))
	}
	if reply == "" {
		ch.Problems = append(ch.Problems, "The model gave no answer after the tool result.")
	}
	ch.Passed = len(ch.Problems) == 0
	return ch
}

const readinessHTTPResponse = "HTTP/1.1 200 OK\nDate: Tue, 05 Oct 2021 10:00:00 GMT\nServer: Apache/2.4.49 (Unix)\nContent-Type: text/html\nContent-Length: 45\n\n<html><body><h1>It works!</h1></body></html>"

func checkTask(ctx context.Context, prov llm.Provider, c Config) ReadinessCheck {
	ch := ReadinessCheck{ID: "task"}
	log := &callLog{}
	run := readinessTool(log, "run_command", "Run a shell command and return its output.",
		obj(map[string]any{"command": str("the command line to run")}, "command"),
		func(json.RawMessage) string { return readinessHTTPResponse })
	report := readinessTool(log, "report_observation", "Report one security-relevant observation.",
		obj(map[string]any{
			"title":    str("short title"),
			"severity": map[string]any{"type": "string", "enum": []string{"info", "low", "medium", "high", "critical"}},
			"evidence": str("the exact output that shows it"),
		}, "title", "severity", "evidence"),
		func(json.RawMessage) string { return "Reported." })
	reply, lat, err := runReadinessPrompt(ctx, prov, c, readinessSystem,
		"Check whether http://192.0.2.20/ discloses its web server version. First fetch its response headers with run_command (for example curl -sI). Then report what the headers show with report_observation, quoting the relevant header as evidence. Finish with one sentence.",
		[]actool.CoreTool{run, report}, 6)
	ch.LatencyMS, ch.Reply, ch.Calls = lat.Milliseconds(), clip(reply, 300), log.labels()
	if err != nil {
		ch.Problems = append(ch.Problems, "The request failed: "+err.Error())
	}
	calls := log.snapshot()
	ranAt, reportedAt := -1, -1
	var reported map[string]any
	for i, call := range calls {
		switch call.name {
		case "run_command":
			var in struct {
				Command string `json:"command"`
			}
			if json.Unmarshal(call.input, &in) == nil && strings.Contains(in.Command, "192.0.2.20") && ranAt < 0 {
				ranAt = i
			}
		case "report_observation":
			if reportedAt < 0 {
				reportedAt = i
				_ = json.Unmarshal(call.input, &reported)
			}
		}
	}
	switch {
	case len(calls) == 0 && textToolCall(reply, "run_command", "report_observation"):
		ch.Problems = append(ch.Problems, "The model wrote the tool calls as text instead of calling the tools.")
		return ch
	case ranAt < 0:
		ch.Problems = append(ch.Problems, "The model did not fetch the target with run_command.")
	}
	if reportedAt < 0 {
		ch.Problems = append(ch.Problems, "The model did not report the observation with report_observation.")
	} else {
		if ranAt < 0 || reportedAt < ranAt {
			ch.Problems = append(ch.Problems, "The model reported before it looked at the response.")
		}
		if reported == nil {
			ch.Problems = append(ch.Problems, "The report arguments are not valid JSON.")
		} else {
			// The stub takes raw input, so the schema is checked here: every
			// required field must be a non-empty string.
			for _, f := range []string{"title", "severity", "evidence"} {
				if v, ok := reported[f].(string); !ok || strings.TrimSpace(v) == "" {
					ch.Problems = append(ch.Problems, fmt.Sprintf("The required report field %s is missing or not a string.", f))
				}
			}
			title, _ := reported["title"].(string)
			evidence, _ := reported["evidence"].(string)
			if !strings.Contains(title+" "+evidence, "2.4.49") {
				ch.Problems = append(ch.Problems, "The report does not quote the server version from the tool result (Apache/2.4.49).")
			}
			switch sev, _ := reported["severity"].(string); strings.ToLower(sev) {
			case "info", "low", "medium", "high", "critical":
			default:
				ch.Problems = append(ch.Problems, fmt.Sprintf("severity %v is not one of the allowed values.", reported["severity"]))
			}
		}
	}
	if reply == "" && err == nil {
		ch.Problems = append(ch.Problems, "The model gave no final answer.")
	}
	ch.Passed = len(ch.Problems) == 0
	return ch
}

// RunReadiness runs the readiness checks on prov (built from c). The task check
// runs only when the basic tool call works.
func RunReadiness(ctx context.Context, prov llm.Provider, c Config) ReadinessReport {
	start := time.Now()
	r := ReadinessReport{Model: c.Model, TestedAt: start.UTC()}
	tc := checkToolCall(ctx, prov, c)
	r.Checks = append(r.Checks, tc)
	if tc.Passed {
		r.Checks = append(r.Checks, checkTask(ctx, prov, c))
	}
	r.LatencyMS = time.Since(start).Milliseconds()
	switch {
	case !tc.Passed:
		r.Verdict = ReadinessNotReady
		r.Summary = "The model cannot make a correct tool call, so ARTEX agents cannot work with it."
	case !r.Checks[1].Passed:
		r.Verdict = ReadinessLimited
		r.Summary = "The model can call tools, but it did not complete a short multi-step task. Expect stalls and wasted turns on real targets."
	default:
		r.Verdict = ReadinessReady
		r.Summary = "The model called tools with valid arguments and completed a short multi-step task."
	}
	return r
}
