package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/norma/llm"
)

// withFakePath makes lookPath find only the given programs and resets the
// cached inventory around the test.
func withFakePath(t *testing.T, installed ...string) {
	t.Helper()
	have := map[string]bool{}
	for _, n := range installed {
		have[n] = true
	}
	prev := lookPath
	lookPath = func(name string) (string, error) {
		if have[name] {
			return "/usr/bin/" + name, nil
		}
		return "", errors.New("not found")
	}
	resetInventory := func() {
		inventoryMu.Lock()
		inventoryAt = time.Time{}
		inventoryMu.Unlock()
	}
	resetInventory()
	t.Cleanup(func() {
		lookPath = prev
		resetInventory()
	})
}

func TestMissingToolIn(t *testing.T) {
	withFakePath(t, "nuclei", "curl", "nmap", "timeout")
	for _, tc := range []struct {
		cmd  string
		want string
	}{
		{"nikto -h https://example.com", "nikto"},
		{"nuclei -u https://example.com", ""},
		{"cd /tmp && nikto -h x", "nikto"},
		{"curl -s x | jq .", "jq"},
		{"FOO=1 sudo -E masscan -p80 10.0.0.0/8", "masscan"},
		{"timeout 60 nikto -h x", "nikto"},
		{"(nikto -h x)", "nikto"},
		{"echo 'run nikto; later'", ""},
		{`echo "a | nikto"`, ""},
		{"echo $(nikto -Version)", ""},
		{"which nikto || echo missing", ""},
		{"command -v nikto", ""},
		{"./nikto -h x", ""},
		{"/opt/nikto/nikto.pl -h x", ""},
		{"cat <<EOF > s.sh\nnikto -h x\nEOF", ""},
		{"my-custom-tool --flag", ""},
		{"nmap -sV x 2>&1 | tee out.txt", ""},
		{"nmap -sV x\nsqlmap -u x", "sqlmap"},
	} {
		if got := missingToolIn(tc.cmd); got != tc.want {
			t.Errorf("missingToolIn(%q) = %q, want %q", tc.cmd, got, tc.want)
		}
	}
}

func TestMissingToolHooksRefusesOnlyBash(t *testing.T) {
	withFakePath(t, "nuclei")
	h := MissingToolHooks(nil)
	block, msg, _ := h.PreToolUse(context.Background(), "Bash", []byte(`{"command":"nikto -h https://example.com"}`))
	if !block {
		t.Fatal("nikto is missing: want the command refused")
	}
	if !strings.Contains(msg, "nikto is not installed") || !strings.Contains(msg, "nuclei") {
		t.Fatalf("message should name the missing tool and the installed alternative: %q", msg)
	}
	if block, _, _ := h.PreToolUse(context.Background(), "Bash", []byte(`{"command":"nuclei -u x"}`)); block {
		t.Fatal("installed tool refused")
	}
	if block, _, _ := h.PreToolUse(context.Background(), "Read", []byte(`{"command":"nikto"}`)); block {
		t.Fatal("only Bash is checked")
	}
}

type countingHooks struct{ pre int }

func (r *countingHooks) PreToolUse(context.Context, string, []byte) (bool, string, []byte) {
	r.pre++
	return false, "", nil
}
func (r *countingHooks) PostToolUse(context.Context, string, []byte, []byte, bool) {}
func (r *countingHooks) Stop(context.Context, []llm.Message) (bool, []string, string) {
	return false, nil, ""
}

func TestMissingToolHooksDelegates(t *testing.T) {
	withFakePath(t, "nmap")
	inner := &countingHooks{}
	h := MissingToolHooks(inner)
	h.PreToolUse(context.Background(), "Bash", []byte(`{"command":"nmap x"}`))
	if inner.pre != 1 {
		t.Fatalf("inner PreToolUse calls = %d, want 1", inner.pre)
	}
	// A refused command never reaches the inner hooks (no approval prompt for a
	// command that cannot run).
	h.PreToolUse(context.Background(), "Bash", []byte(`{"command":"nikto x"}`))
	if inner.pre != 1 {
		t.Fatalf("inner PreToolUse calls = %d, want still 1", inner.pre)
	}
}

func TestMissingToolMessageWithoutAlternative(t *testing.T) {
	withFakePath(t)
	msg := missingToolMessage("sqlmap")
	if !strings.Contains(msg, "No other tool for SQL injection testing is installed") {
		t.Fatalf("message = %q", msg)
	}
}

func TestToolInventoryBlock(t *testing.T) {
	all := make([]string, 0, len(knownTools))
	for _, k := range knownTools {
		all = append(all, k.name)
	}
	withFakePath(t, all...)
	if got := toolInventoryBlock(); got != "" {
		t.Fatalf("every tool installed: want no block, got %q", got)
	}

	withFakePath(t, "nmap", "nuclei")
	got := toolInventoryBlock()
	if !strings.Contains(got, toolInventoryHeader) || !strings.Contains(got, "Available: nmap, nuclei\n") || !strings.Contains(got, "nikto") {
		t.Fatalf("block = %q", got)
	}
}
