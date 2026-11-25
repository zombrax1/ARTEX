package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
)

// Agents pick security tools by name, and a model has no way to know which ones
// this host actually has. Outside the Docker image (a native install, a trimmed
// image) a worker would run `nikto ...`, get exit code 127, and often try the
// same missing tool again, burning turns. Two code-owned pieces fix that:
//
//   - every prompt that can launch Bash lists which well-known tools are on PATH
//     and which are not (toolInventoryBlock), so the model plans with what exists;
//   - a Bash command whose program is a well-known tool that is not on PATH is
//     refused before it runs, with the installed tools for the same job
//     (MissingToolHooks), instead of failing as "command not found".
//
// Only names in knownTools are ever checked or refused. Any other command, a path
// such as ./nikto, or a tool installed after startup that is on PATH runs as before.

// knownTool is a well-known external program and the job it does. Tools with the
// same job are offered as alternatives to each other.
type knownTool struct {
	name string
	job  string
}

var knownTools = []knownTool{
	{"nmap", "port scanning"}, {"masscan", "port scanning"}, {"naabu", "port scanning"}, {"rustscan", "port scanning"},
	{"subfinder", "subdomain discovery"}, {"amass", "subdomain discovery"}, {"assetfinder", "subdomain discovery"}, {"bbot", "subdomain discovery"},
	{"dnsx", "DNS resolution"}, {"dig", "DNS resolution"},
	{"httpx", "HTTP probing"}, {"whatweb", "web fingerprinting"}, {"wafw00f", "web fingerprinting"},
	{"katana", "crawling and URL collection"}, {"gau", "crawling and URL collection"}, {"waybackurls", "crawling and URL collection"},
	{"hakrawler", "crawling and URL collection"}, {"gospider", "crawling and URL collection"},
	{"ffuf", "content discovery"}, {"gobuster", "content discovery"}, {"feroxbuster", "content discovery"}, {"dirsearch", "content discovery"},
	{"nuclei", "web vulnerability scanning"}, {"nikto", "web vulnerability scanning"}, {"wpscan", "web vulnerability scanning"},
	{"sqlmap", "SQL injection testing"}, {"dalfox", "XSS testing"}, {"commix", "command injection testing"},
	{"testssl.sh", "TLS testing"}, {"testssl", "TLS testing"}, {"sslscan", "TLS testing"}, {"sslyze", "TLS testing"},
	{"hydra", "credential brute force"}, {"ncrack", "credential brute force"}, {"medusa", "credential brute force"},
	{"netexec", "SMB and AD enumeration"}, {"nxc", "SMB and AD enumeration"}, {"crackmapexec", "SMB and AD enumeration"},
	{"enum4linux", "SMB and AD enumeration"}, {"enum4linux-ng", "SMB and AD enumeration"}, {"smbclient", "SMB and AD enumeration"},
	{"gowitness", "screenshots"},
	{"curl", "HTTP requests"}, {"wget", "HTTP requests"},
	{"jq", "JSON processing"}, {"python3", "scripting"}, {"git", "source checkout"},
}

var knownToolJob = func() map[string]string {
	m := make(map[string]string, len(knownTools))
	for _, t := range knownTools {
		m[t.name] = t.job
	}
	return m
}()

// lookPath is exec.LookPath; tests replace it.
var lookPath = exec.LookPath

// toolInventory is a snapshot of which known tools are on PATH.
type toolInventory struct {
	installed []string // in knownTools order
	missing   []string
}

// toolInventoryTTL bounds how stale the prompt list can be: a tool installed
// while the server runs shows up in prompts built after this long.
const toolInventoryTTL = time.Minute

var (
	inventoryMu   sync.Mutex
	inventoryAt   time.Time
	inventorySnap toolInventory
)

func scanToolInventory() toolInventory {
	var inv toolInventory
	for _, t := range knownTools {
		if _, err := lookPath(t.name); err == nil {
			inv.installed = append(inv.installed, t.name)
		} else {
			inv.missing = append(inv.missing, t.name)
		}
	}
	return inv
}

func currentToolInventory() toolInventory {
	inventoryMu.Lock()
	defer inventoryMu.Unlock()
	if inventoryAt.IsZero() || time.Since(inventoryAt) > toolInventoryTTL {
		inventorySnap = scanToolInventory()
		inventoryAt = time.Now()
	}
	return inventorySnap
}

// ToolInventory reports the known tools found and not found on PATH, for the
// startup log.
func ToolInventory() (installed, missing []string) {
	inv := currentToolInventory()
	return append([]string(nil), inv.installed...), append([]string(nil), inv.missing...)
}

// toolInventoryHeader starts the code-owned tool inventory block.
const toolInventoryHeader = "[Installed tools: "

// toolInventoryBlock is appended to every prompt that can launch Bash. It is ""
// when every known tool is installed, so a full image keeps its prompts unchanged.
func toolInventoryBlock() string { return renderToolInventory(currentToolInventory()) }

func renderToolInventory(inv toolInventory) string {
	if len(inv.missing) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n")
	b.WriteString(toolInventoryHeader)
	b.WriteString("checked on this host's PATH]\n")
	if len(inv.installed) > 0 {
		b.WriteString("Available: ")
		b.WriteString(strings.Join(inv.installed, ", "))
		b.WriteString("\n")
	}
	b.WriteString("Not installed: ")
	b.WriteString(strings.Join(inv.missing, ", "))
	b.WriteString("\nPlan with the available tools. A Bash command that runs a tool that is not installed is refused before it starts; use an available tool for the same job, or a short script, instead. Do not install tools unless the operator asked you to.")
	return b.String()
}

// missingToolIn returns the first well-known tool that a Bash command runs as a
// program and that is not on PATH, or "". It is conservative: it only looks at
// the program of each simple command (after env assignments and wrappers such as
// sudo or timeout), honours quotes, and gives up on heredocs, whose body is not
// commands.
func missingToolIn(command string) string {
	if strings.Contains(command, "<<") {
		return ""
	}
	for _, seg := range splitShellCommands(command) {
		prog := commandProgram(seg)
		if prog == "" {
			continue
		}
		if _, known := knownToolJob[prog]; !known {
			continue
		}
		if _, err := lookPath(prog); err != nil {
			return prog
		}
	}
	return ""
}

// splitShellCommands splits a command line at unquoted ; & | and newlines.
// Text inside quotes, $(...) and backticks is kept in the segment it appears in.
func splitShellCommands(s string) []string {
	var out []string
	var cur strings.Builder
	var quote byte // 0, '\'' or '"'
	depth := 0     // $( ... ) and backtick nesting
	flush := func() {
		if t := strings.TrimSpace(cur.String()); t != "" {
			out = append(out, t)
		}
		cur.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(c)
			i++
			c = s[i]
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			depth++
		case c == ')' && depth > 0:
			depth--
		case c == '`':
			if depth > 0 {
				depth--
			} else {
				depth++
			}
		case depth == 0 && (c == ';' || c == '&' || c == '|' || c == '\n'):
			flush()
			continue
		}
		cur.WriteByte(c)
	}
	flush()
	return out
}

// commandWrappers run their argument as the program.
var commandWrappers = map[string]bool{
	"sudo": true, "nohup": true, "time": true, "env": true, "exec": true, "nice": true, "stdbuf": true, "timeout": true,
	"command": false, // `command -v x` is a lookup, not a run
}

// commandProgram returns the bare program name a simple command runs, or "" when
// it is not a plain name (a path, a variable, a keyword, a lookup).
func commandProgram(seg string) string {
	fields := strings.Fields(strings.TrimLeft(seg, "({! \t"))
	for i := 0; i < len(fields); i++ {
		f := fields[i]
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "=") && !strings.HasPrefix(f, "-") {
			continue // FOO=bar prefix
		}
		if wrap, ok := commandWrappers[f]; ok {
			if !wrap {
				return ""
			}
			// Skip the wrapper's own flags and, for timeout, its duration.
			for i+1 < len(fields) && strings.HasPrefix(fields[i+1], "-") {
				i++
			}
			if f == "timeout" && i+1 < len(fields) {
				i++
			}
			continue
		}
		if strings.ContainsAny(f, "/$`\"'") || filepath.Base(f) != f {
			return ""
		}
		return f
	}
	return ""
}

// missingToolMessage explains a refusal and offers installed tools for the job.
func missingToolMessage(tool string) string {
	job := knownToolJob[tool]
	var alts []string
	for _, t := range knownTools {
		if t.job == job && t.name != tool {
			if _, err := lookPath(t.name); err == nil {
				alts = append(alts, t.name)
			}
		}
	}
	sort.Strings(alts)
	msg := fmt.Sprintf("%s is not installed on this host (not found on PATH), so this command would fail with exit code 127 and was not run.", tool)
	if len(alts) > 0 {
		msg += fmt.Sprintf(" Installed tools for %s: %s. Use one of them instead.", job, strings.Join(alts, ", "))
	} else {
		msg += fmt.Sprintf(" No other tool for %s is installed: use curl or a short script for the same check, or record the gap and move on. Do not retry %s.", job, tool)
	}
	return msg
}

// missingToolHooks refuses Bash commands that run a known tool that is missing.
type missingToolHooks struct {
	inner harness.HookRunner
}

// MissingToolHooks wraps hooks (which may be nil) with the missing-tool check.
func MissingToolHooks(hooks harness.HookRunner) harness.HookRunner {
	return missingToolHooks{inner: hooks}
}

func (h missingToolHooks) PreToolUse(ctx context.Context, name string, input []byte) (bool, string, []byte) {
	if name == "Bash" {
		var in struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input, &in) == nil {
			if tool := missingToolIn(in.Command); tool != "" {
				return true, missingToolMessage(tool), nil
			}
		}
	}
	if h.inner != nil {
		return h.inner.PreToolUse(ctx, name, input)
	}
	return false, "", nil
}

func (h missingToolHooks) PostToolUse(ctx context.Context, name string, input, result []byte, isErr bool) {
	if h.inner != nil {
		h.inner.PostToolUse(ctx, name, input, result, isErr)
	}
}

func (h missingToolHooks) Stop(ctx context.Context, messages []llm.Message) (bool, []string, string) {
	if h.inner != nil {
		return h.inner.Stop(ctx, messages)
	}
	return false, nil, ""
}
