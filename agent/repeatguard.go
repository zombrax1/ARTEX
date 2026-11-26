package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"unicode/utf8"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// Repeated-failure detection.
//
// A model that is stuck tends to send the same failing command again, with at most
// cosmetic changes, or to keep firing commands that all fail. Every such call costs
// a model turn and a tool run and teaches it nothing. The repeat guard watches one
// agent run's tool calls and steps in at three levels:
//
//   - The same call (same tool, same arguments after normalization) failed
//     FailRepeats times: the next identical call is refused with a summary of the
//     earlier failure and an instruction to change approach.
//   - The same call succeeded IdenticalRepeats times in a row of identical calls:
//     the next identical call is refused (its result will not change).
//   - FailureStreak tool calls failed in a row, whatever they were: the next call
//     is refused once with an instruction to step back and change direction.
//
// After StopAfter refusals the run is told to stop: every tool except the
// write-back ones is refused with an instruction to record what failed and end.
// A zero limit turns its check off; all zero turns the guard off.

// RepeatGuardLimits configures the guard. Zero disables a check.
type RepeatGuardLimits struct {
	Enabled          bool `json:"enabled"`
	FailRepeats      int  `json:"fail_repeats"`      // identical failing calls before the next is refused
	IdenticalRepeats int  `json:"identical_repeats"` // identical successful calls before the next is refused
	FailureStreak    int  `json:"failure_streak"`    // consecutive failed calls (any) before a change of direction is forced
	StopAfter        int  `json:"stop_after"`        // refusals before the run is told to wrap up
}

// DefaultRepeatGuardLimits is the out-of-the-box policy.
func DefaultRepeatGuardLimits() RepeatGuardLimits {
	return RepeatGuardLimits{Enabled: true, FailRepeats: 2, IdenticalRepeats: 4, FailureStreak: 8, StopAfter: 5}
}

// Clamped bounds each limit to a sane range (0 = off, max 100).
func (l RepeatGuardLimits) Clamped() RepeatGuardLimits {
	c := func(n int) int {
		if n < 0 {
			return 0
		}
		if n > 100 {
			return 100
		}
		return n
	}
	return RepeatGuardLimits{Enabled: l.Enabled, FailRepeats: c(l.FailRepeats), IdenticalRepeats: c(l.IdenticalRepeats), FailureStreak: c(l.FailureStreak), StopAfter: c(l.StopAfter)}
}

func (l RepeatGuardLimits) active() bool {
	return l.Enabled && (l.FailRepeats > 0 || l.IdenticalRepeats > 0 || l.FailureStreak > 0)
}

var repeatGuardSource atomic.Pointer[func() RepeatGuardLimits]

// SetRepeatGuardSource installs the function each new agent run reads its limits
// from (the server reads the stored setting). nil restores the defaults.
func SetRepeatGuardSource(f func() RepeatGuardLimits) {
	if f == nil {
		repeatGuardSource.Store(nil)
		return
	}
	repeatGuardSource.Store(&f)
}

func currentRepeatGuardLimits() RepeatGuardLimits {
	if p := repeatGuardSource.Load(); p != nil {
		return (*p)().Clamped()
	}
	return DefaultRepeatGuardLimits()
}

// repeatExempt lists tools that are expected to repeat (polling, planning
// scratch) or that persist results; they are never refused and never counted.
func repeatExempt(tool string) bool {
	switch tool {
	case "TaskOutput", "TaskList", "TaskStop", "Monitor", "Sleep", "TodoWrite", "Read", "LS":
		return true
	}
	return !BudgetWrapupBlocks(tool)
}

// repeatCallKey normalizes a tool call so cosmetic differences (key order, JSON
// formatting, the free-text description) do not hide a repeat.
func repeatCallKey(tool string, input []byte) string {
	var m map[string]any
	if json.Unmarshal(input, &m) != nil {
		return tool + "\x00" + string(input)
	}
	delete(m, "description")
	// String values are kept byte for byte: whitespace can be significant (an edit's
	// old_string indentation, a quoted shell argument), so a call that differs only
	// in whitespace is a different call.
	b, _ := json.Marshal(m) // map keys marshal sorted
	return tool + "\x00" + string(b)
}

// failureSummary extracts a short, readable reason from a tool result.
func failureSummary(result []byte) string {
	text := string(result)
	var s string
	if json.Unmarshal(result, &s) == nil {
		text = s
	} else {
		var blocks []struct {
			Text string `json:"text"`
		}
		if json.Unmarshal(result, &blocks) == nil {
			var b strings.Builder
			for _, bl := range blocks {
				b.WriteString(bl.Text)
				b.WriteString("\n")
			}
			text = b.String()
		}
	}
	var lines []string
	for _, ln := range strings.Split(text, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "<") { // skip framing tags of untrusted output
			continue
		}
		lines = append(lines, ln)
	}
	// The exit code line usually comes last; the cause is usually right before it.
	if n := len(lines); n > 3 {
		lines = append(lines[:1], lines[n-2:]...)
	}
	out := strings.Join(lines, " | ")
	if utf8.RuneCountInString(out) > 300 {
		out = string([]rune(out)[:300]) + "…"
	}
	if out == "" {
		out = "(no output)"
	}
	return out
}

func describeCall(tool string, input []byte) string {
	var in struct {
		Command string `json:"command"`
		URL     string `json:"url"`
	}
	_ = json.Unmarshal(input, &in)
	target := in.Command
	if target == "" {
		target = in.URL
	}
	if target == "" {
		target = string(bytes.TrimSpace(input))
	}
	if utf8.RuneCountInString(target) > 160 {
		target = string([]rune(target)[:160]) + "…"
	}
	return fmt.Sprintf("%s %s", tool, target)
}

type repeatCallStat struct {
	failures  int
	successes int
	lastError string
	label     string
}

type repeatGuardState struct {
	mu        sync.Mutex
	limits    RepeatGuardLimits
	calls     map[string]*repeatCallStat
	lastKey   string
	streak    int      // consecutive failed calls
	streakLog []string // the calls in the current streak, newest last
	refusals  int
	stopped   bool
}

// RepeatGuardStop is returned for every non-write-back tool once the run was told to stop.
const RepeatGuardStop = "[Repeated failures] This run keeps repeating calls that fail or return the same result, so it was stopped to save time and tokens; the tool call was not executed. Do not run any more commands or probes. Write back what you established (record_fact, insert_assets, report_finding, record_coverage), including a record_fact that names the approach that failed and why, so the planner can choose a different direction. Then, in a single standalone sentence of plain text, summarize what you tried and why it did not work."

// repeatGuardHooks wraps a hook runner with the repeat guard. State is shared
// through a pointer: the harness holds a copy of the runner.
type repeatGuardHooks struct {
	inner harness.HookRunner
	st    *repeatGuardState
}

// RepeatGuardHooks wraps hooks (which may be nil) with repeated-failure
// detection using the configured limits. It returns hooks unchanged when the
// guard is off.
func RepeatGuardHooks(hooks harness.HookRunner) harness.HookRunner {
	return repeatGuardWith(hooks, currentRepeatGuardLimits())
}

func repeatGuardWith(hooks harness.HookRunner, l RepeatGuardLimits) harness.HookRunner {
	if !l.active() {
		return hooks
	}
	return repeatGuardHooks{inner: hooks, st: &repeatGuardState{limits: l, calls: map[string]*repeatCallStat{}}}
}

func (h repeatGuardHooks) check(name string, input []byte) (bool, string) {
	st := h.st
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.stopped {
		if BudgetWrapupBlocks(name) {
			return true, RepeatGuardStop
		}
		return false, ""
	}
	if repeatExempt(name) {
		return false, ""
	}
	l := st.limits
	key := repeatCallKey(name, input)
	var msg string
	if c := st.calls[key]; c != nil {
		switch {
		case l.FailRepeats > 0 && c.failures >= l.FailRepeats:
			msg = fmt.Sprintf("[Repeated failure] This exact call already failed %d times (%s); last error: %s. It was not run again. Do not retry it unchanged: work out why it fails (wrong path, missing parameter, blocked by the target, wrong tool) and try a different approach, or record the blocker with record_fact and move on.", c.failures, c.label, c.lastError)
		case l.IdenticalRepeats > 0 && key == st.lastKey && c.successes >= l.IdenticalRepeats:
			msg = fmt.Sprintf("[Identical repeat] This exact call already ran %d times in a row with success (%s); running it again will return the same result. It was not run. Use the output you already have, or change the request.", c.successes, c.label)
		}
	}
	if msg == "" && l.FailureStreak > 0 && st.streak >= l.FailureStreak {
		msg = fmt.Sprintf("[Failing approach] The last %d tool calls all failed:\n- %s\nThis call was not run. Step back: state in one sentence why these attempts fail, then either change direction (different tool, endpoint, technique or input) or record the blocker with record_fact and end this intent.", st.streak, strings.Join(st.streakLog, "\n- "))
		st.streak, st.streakLog = 0, nil // one forced pause per streak
	}
	if msg == "" {
		return false, ""
	}
	st.refusals++
	log.Printf("[repeat-guard] refused %s (%d refusals)", describeCall(name, input), st.refusals)
	if l.StopAfter > 0 && st.refusals >= l.StopAfter {
		st.stopped = true
		return true, msg + "\n\n" + RepeatGuardStop
	}
	return true, msg
}

func (h repeatGuardHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if block, msg := h.check(name, input); block {
		return true, msg, nil
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (h repeatGuardHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	h.record(name, input, result, isErr)
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (h repeatGuardHooks) record(name string, input, result []byte, isErr bool) {
	if repeatExempt(name) {
		return
	}
	st := h.st
	st.mu.Lock()
	defer st.mu.Unlock()
	key := repeatCallKey(name, input)
	c := st.calls[key]
	if c == nil {
		c = &repeatCallStat{label: describeCall(name, input)}
		st.calls[key] = c
	}
	if isErr {
		c.successes = 0 // the identical-success count covers consecutive successes only
		c.failures++
		c.lastError = failureSummary(result)
		st.streak++
		st.streakLog = append(st.streakLog, c.label+": "+c.lastError)
		if len(st.streakLog) > 5 {
			st.streakLog = st.streakLog[len(st.streakLog)-5:]
		}
	} else {
		if key != st.lastKey {
			c.successes = 0
		}
		c.successes++
		c.failures = 0 // it works now; a later failure starts a new count
		st.streak, st.streakLog = 0, nil
	}
	st.lastKey = key
}

func (h repeatGuardHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}
