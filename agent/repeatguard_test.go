package agent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func bashIn(cmd string) []byte {
	b, _ := json.Marshal(map[string]any{"command": cmd, "description": "x"})
	return b
}

func errResult(s string) []byte {
	b, _ := json.Marshal(s)
	return b
}

func TestRepeatGuardRefusesIdenticalFailures(t *testing.T) {
	h := repeatGuardWith(nil, RepeatGuardLimits{Enabled: true, FailRepeats: 2})
	ctx := context.Background()
	cmd := "curl -s http://t.example/api"
	for i := 0; i < 2; i++ {
		if block, _, _ := h.PreToolUse(ctx, "Bash", bashIn(cmd)); block {
			t.Fatalf("call %d refused too early", i+1)
		}
		h.PostToolUse(ctx, "Bash", bashIn(cmd), errResult("curl: (7) Failed to connect\n\n[exit code 7]"), true)
	}
	// whitespace and description changes are still the same call
	block, msg, _ := h.PreToolUse(ctx, "Bash", []byte(`{"command":"curl  -s http://t.example/api","description":"retry"}`))
	if !block || !strings.Contains(msg, "Failed to connect") || !strings.Contains(msg, "failed 2 times") {
		t.Fatalf("third identical failing call: block=%v msg=%q", block, msg)
	}
	// a different command still runs
	if block, _, _ := h.PreToolUse(ctx, "Bash", bashIn("curl -s http://t.example/other")); block {
		t.Fatal("a different call was refused")
	}
}

func TestRepeatGuardSuccessResetsFailures(t *testing.T) {
	h := repeatGuardWith(nil, RepeatGuardLimits{Enabled: true, FailRepeats: 2})
	ctx := context.Background()
	in := bashIn("nmap -p 80 host")
	h.PostToolUse(ctx, "Bash", in, errResult("timeout"), true)
	h.PostToolUse(ctx, "Bash", in, errResult("ok"), false)
	h.PostToolUse(ctx, "Bash", in, errResult("timeout"), true)
	if block, _, _ := h.PreToolUse(ctx, "Bash", in); block {
		t.Fatal("refused after only one failure since the last success")
	}
}

func TestRepeatGuardIdenticalSuccesses(t *testing.T) {
	h := repeatGuardWith(nil, RepeatGuardLimits{Enabled: true, IdenticalRepeats: 3})
	ctx := context.Background()
	in := bashIn("cat /etc/hosts")
	for i := 0; i < 3; i++ {
		h.PostToolUse(ctx, "Bash", in, errResult("127.0.0.1 localhost"), false)
	}
	if block, msg, _ := h.PreToolUse(ctx, "Bash", in); !block || !strings.Contains(msg, "Identical repeat") {
		t.Fatalf("4th identical successful call: block=%v msg=%q", block, msg)
	}
	// interleaving another call breaks the run of identical calls
	h2 := repeatGuardWith(nil, RepeatGuardLimits{Enabled: true, IdenticalRepeats: 2})
	h2.PostToolUse(ctx, "Bash", in, errResult("a"), false)
	h2.PostToolUse(ctx, "Bash", bashIn("id"), errResult("b"), false)
	h2.PostToolUse(ctx, "Bash", in, errResult("a"), false)
	if block, _, _ := h2.PreToolUse(ctx, "Bash", in); block {
		t.Fatal("non-consecutive identical calls were refused")
	}
}

func TestRepeatGuardFailureStreakAndStop(t *testing.T) {
	h := repeatGuardWith(nil, RepeatGuardLimits{Enabled: true, FailureStreak: 3, StopAfter: 2})
	ctx := context.Background()
	fail := func(cmd string) { h.PostToolUse(ctx, "Bash", bashIn(cmd), errResult("denied"), true) }
	fail("a")
	fail("b")
	fail("c")
	block, msg, _ := h.PreToolUse(ctx, "Bash", bashIn("d"))
	if !block || !strings.Contains(msg, "last 3 tool calls all failed") {
		t.Fatalf("streak not caught: block=%v msg=%q", block, msg)
	}
	// the streak resets after one forced pause
	if block, _, _ := h.PreToolUse(ctx, "Bash", bashIn("d")); block {
		t.Fatal("refused twice for one streak")
	}
	fail("e")
	fail("f")
	fail("g")
	block, msg, _ = h.PreToolUse(ctx, "Bash", bashIn("h"))
	if !block || !strings.Contains(msg, RepeatGuardStop) {
		t.Fatalf("second refusal should stop the run: block=%v msg=%q", block, msg)
	}
	// stopped: commands are refused, write-back tools still run
	if block, _, _ := h.PreToolUse(ctx, "Bash", bashIn("anything")); !block {
		t.Fatal("command ran after stop")
	}
	if block, _, _ := h.PreToolUse(ctx, "record_fact", []byte(`{}`)); block {
		t.Fatal("write-back tool refused after stop")
	}
}

func TestRepeatGuardOffAndExempt(t *testing.T) {
	if h := repeatGuardWith(nil, RepeatGuardLimits{Enabled: false, FailRepeats: 1}); h != nil {
		t.Fatal("disabled guard should return the inner hooks (nil)")
	}
	h := repeatGuardWith(nil, RepeatGuardLimits{Enabled: true, FailRepeats: 1, IdenticalRepeats: 1})
	ctx := context.Background()
	in := []byte(`{"task_id":"x"}`)
	for i := 0; i < 3; i++ {
		if block, _, _ := h.PreToolUse(ctx, "TaskOutput", in); block {
			t.Fatal("polling tool refused")
		}
		h.PostToolUse(ctx, "TaskOutput", in, errResult("still running"), true)
	}
}

func TestRepeatGuardLimitsClamped(t *testing.T) {
	got := RepeatGuardLimits{Enabled: true, FailRepeats: -1, IdenticalRepeats: 1000}.Clamped()
	if got.FailRepeats != 0 || got.IdenticalRepeats != 100 {
		t.Fatalf("clamped = %+v", got)
	}
}
