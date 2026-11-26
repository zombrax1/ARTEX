//go:build windows

package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	actool "github.com/Autumn-27/norma/tool"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/traffic"
)

// The allowlist is case-insensitive like Windows variable names, and the shim's own
// variables are on it (the shim needs them) but never reach the agent process.
func TestWindowsExecutorEnvAllowlist(t *testing.T) {
	for _, name := range []string{"PATH", "Path", "https_proxy", "HTTPS_PROXY", "ssl_cert_file", envExecCred} {
		if !executorEnvAllowed(name) {
			t.Errorf("%s should cross to the agent shim", name)
		}
	}
	for _, name := range []string{"ARTEX_PG_DSN", "ARTEX_SECRET_KEY", "OPENAI_API_KEY", "USERPROFILE", "APPDATA", "LC_SECRET"} {
		if executorEnvAllowed(name) {
			t.Errorf("%s must not cross to an agent process", name)
		}
	}
	env := []string{"PATH=a", "ARTEX_PG_DSN=postgres://u:pw@h/db", "=C:=C:\\x", "broken", "TOOL_X=1"}
	got := executorEnv(env, map[string]bool{"TOOL_X": true})
	if strings.Join(got, "|") != "PATH=a|TOOL_X=1" {
		t.Fatalf("executorEnv = %q", got)
	}
}

func TestWindowsPathWithout(t *testing.T) {
	got := pathWithout(`C:\shim;C:\Windows\system32;c:\SHIM\;;C:\tools`, `C:\shim`)
	if got != `C:\Windows\system32;C:\tools` {
		t.Fatalf("pathWithout = %q", got)
	}
}

// A custom tool's session and parameter variables are not on the allowlist: the
// drop shim keeps them because execToolCommand names them in ARTEX_EXEC_KEEP.
func TestWindowsExecToolCommandKeepsToolVariables(t *testing.T) {
	p := ExecPrivilege{Enabled: true, Account: "artex-agent", SID: "S-1-5-21-1-2-3-1001"}
	name, args, env, err := execToolCommand(p, "python", []string{`C:\s\t.py`}, []string{"PATH=x", "TOOL_TARGET=example", "HTTP_PROXY=http://127.0.0.1:8788"})
	if err != nil {
		t.Fatal(err)
	}
	self, _ := os.Executable()
	if name != self || len(args) < 5 || args[0] != execDropArg || args[3] != "--" || args[4] != "python" {
		t.Fatalf("command %s %q, want the drop shim around python", name, args)
	}
	keep := keepFromEnv(env)
	if !keep["TOOL_TARGET"] || keep["PATH"] || keep["HTTP_PROXY"] {
		t.Fatalf("keep = %v, want TOOL_TARGET only", keep)
	}
	if n, a, e, _ := execToolCommand(ExecPrivilege{}, "python", []string{"t.py"}, []string{"A=1"}); n != "python" || len(a) != 1 || len(e) != 1 {
		t.Fatalf("disabled: %s %q %q, want the tool unchanged", n, a, e)
	}
}

func TestWindowsEnvBlockRoundTrip(t *testing.T) {
	in := []string{"A=1", "PATH=C:\\x;C:\\y", "Ü=ö"}
	block, err := envListToBlock(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := envBlockToList(block); strings.Join(got, "|") != strings.Join(in, "|") {
		t.Fatalf("round trip %q, want %q", got, in)
	}
}

// A Windows server with an agent account does not start when the self-test fails;
// without one it starts degraded (TestEnforceIsolation covers the rest).
func TestWindowsIsolationRequiredWithAccount(t *testing.T) {
	acct := ExecPrivilege{Enabled: true, Account: "artex-agent", SID: "S-1-5-21-1-2-3-1001"}
	if _, err := EnforceIsolation("windows", acct, errors.New("the agent shell can read jwt.key"), false); err == nil {
		t.Fatal("a Windows server with an agent account must not start when the self-test fails")
	}
	st, err := EnforceIsolation("windows", ExecPrivilege{}, errors.New("no agent account is set up"), false)
	if err != nil || st.Mode != IsolationDegraded {
		t.Fatalf("no account: %+v %v, want a degraded start", st, err)
	}
}

// windowsAccountFixture sets up an ARTEX layout under base with an agent account,
// the way cmd/artex does at start.
type windowsAccountFixture struct {
	priv                               ExecPrivilege
	root, data, keyDir, skills, config string
}

func newWindowsAccountFixture(t *testing.T, base string) *windowsAccountFixture {
	t.Helper()
	// Process-wide state that PrepareExecPrivilege and InstallBashShim set.
	for _, k := range []string{"PATH", envExecShell, envExecAccount, envExecSID, envExecCred, envExecBin} {
		t.Setenv(k, os.Getenv(k))
	}
	t.Cleanup(func() {
		agent.SetFileToolIdentity(nil)
		traffic.RestrictCAKey = nil
	})
	var nonce [4]byte
	rand.Read(nonce[:])
	root := filepath.Join(base, "artex-"+hex.EncodeToString(nonce[:]))
	f := &windowsAccountFixture{root: root, data: filepath.Join(root, "data"), keyDir: root,
		skills: filepath.Join(root, "skills"), config: filepath.Join(root, "config.json")}
	if err := os.MkdirAll(filepath.Join(f.skills, "recon"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	for name, body := range map[string]string{
		"jwt.key": "key-jwt", "secret.key": "key-secret", "config.json": `{"database":{"dsn":"postgres://u:pw@h/db"}}`,
		filepath.Join("skills", "recon", "SKILL.md"): "# recon",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := execAccountSetup(windowsTestAccount, f.keyDir, true, false); err != nil {
		t.Fatalf("exec-account setup: %v", err)
	}
	priv, err := ResolveExecAccount("", f.keyDir, false)
	if err != nil || !priv.Enabled {
		t.Fatalf("ResolveExecAccount: %+v %v", priv, err)
	}
	priv.SkillDir = f.skills
	if err := PrepareExecPrivilege(&priv, f.data, f.keyDir, f.config); err != nil {
		t.Fatalf("PrepareExecPrivilege: %v", err)
	}
	if err := InstallBashShim(priv); err != nil {
		t.Fatalf("InstallBashShim: %v", err)
	}
	f.priv = priv
	return f
}

const windowsTestAccount = "artex-ci-agent"

func (f *windowsAccountFixture) targets() IsolationTargets {
	return IsolationTargets{DataDir: f.data, KeyDir: f.keyDir, ConfigPath: f.config, SkillDir: f.skills}
}

// The deployment the Windows self-test is for, end to end, on a disposable elevated
// host (the CI runner): setup creates the account, the server prepares the layout,
// the self-test passes through the real PowerShell shim, and the agent's shell, an
// MCP-style drop command and the file tools all run as the account and cannot read
// the keys. It runs twice: under the user's profile, which other users cannot read
// at all, and under a drive-root folder, which inherits read and write rights for
// every user, so the ACLs ARTEX sets are what keeps the account out.
func TestWindowsAgentAccountIsolation(t *testing.T) {
	if os.Getenv("ARTEX_WINDOWS_ACCOUNT_TEST") != "1" {
		t.Skip("set ARTEX_WINDOWS_ACCOUNT_TEST=1 on a disposable, elevated Windows host: this creates a local account")
	}
	drive := filepath.VolumeName(os.Getenv("SystemRoot")) + `\`
	for _, base := range []struct{ name, dir string }{{"profile", t.TempDir()}, {"drive-root", drive}} {
		t.Run(base.name, func(t *testing.T) {
			f := newWindowsAccountFixture(t, base.dir)
			if err := IsolationSelfTest(f.priv, f.targets()); err != nil {
				t.Fatalf("self-test: %v", err)
			}

			sid, err := f.priv.accountSID()
			if err != nil {
				t.Fatal(err)
			}
			run := filepath.Join(f.data, "tasks", "t1", "main")
			if err := makeLeafDirWin(f.data, run, sid, runDirACEs); err != nil {
				t.Fatal(err)
			}

			// The agent's shell: Norma starts "powershell" from PATH.
			t.Setenv("ARTEX_TEST_SECRET", "s3cret-value")
			c := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command",
				`[Security.Principal.WindowsIdentity]::GetCurrent().Name; "secret=[$env:ARTEX_TEST_SECRET]"; "loc=[$((Get-Location).Path)] cwd=[$([Environment]::CurrentDirectory)]"; try { Set-Location -LiteralPath ([Environment]::CurrentDirectory); "loc2=[$((Get-Location).Path)]" } catch { "setloc=[$_]" }; Set-Content -Path out.txt -Value hi; exit 7`)
			c.Dir = run
			out, err := c.CombinedOutput()
			var ee *exec.ExitError
			if !errors.As(err, &ee) || ee.ExitCode() != 7 {
				t.Fatalf("shell: err %v, want exit code 7\n%s", err, out)
			}
			if !strings.Contains(strings.ToLower(string(out)), `\`+windowsTestAccount) {
				t.Errorf("shell ran as\n%s\nwant %s", out, windowsTestAccount)
			}
			if !strings.Contains(string(out), "secret=[]") {
				t.Errorf("a server variable reached the shell:\n%s", out)
			}
			if _, err := os.Stat(filepath.Join(run, "out.txt")); err != nil {
				t.Errorf("the shell could not write its run directory: %v\n%s", err, out)
			}
			c = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Content -LiteralPath "+psQuote(filepath.Join(f.keyDir, "jwt.key")))
			c.Dir = run
			if out, err := c.CombinedOutput(); err == nil || strings.Contains(string(out), "key-jwt") {
				t.Errorf("the shell read jwt.key: %v\n%s", err, out)
			}

			// A key created after the start (a fresh install creates them after the
			// self-test) is denied by inheritance.
			late := filepath.Join(f.keyDir, "late.key")
			if err := os.WriteFile(late, []byte("late-secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			c = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", "Get-Content -LiteralPath "+psQuote(late))
			c.Dir = run
			if out, err := c.CombinedOutput(); err == nil || strings.Contains(string(out), "late-secret") {
				t.Errorf("the shell read a key created after the start: %v\n%s", err, out)
			}

			// An agent command far longer than CreateProcessWithLogonW's 1,024 characters.
			long := "$x = '" + strings.Repeat("a", 5000) + "'; 'len=' + $x.Length"
			c = exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", long)
			c.Dir = run
			if out, err := c.CombinedOutput(); err != nil || !strings.Contains(string(out), "len=5000") {
				t.Errorf("long command: %v\n%s", err, out)
			}

			// An MCP stdio server or a custom tool: the drop shim.
			name, args, err := execDropCommand(f.priv, "cmd.exe", []string{"/d", "/c", "whoami"})
			if err != nil {
				t.Fatal(err)
			}
			c = exec.Command(name, args...)
			c.Dir = run
			if out, err := c.CombinedOutput(); err != nil || !strings.Contains(strings.ToLower(string(out)), windowsTestAccount) {
				t.Errorf("drop shim: %v\n%s", err, out)
			}

			// The file tools.
			var openErr error
			if err := agent.RunAsFileToolIdentity(func() {
				var fh *os.File
				if fh, openErr = os.Open(filepath.Join(f.keyDir, "jwt.key")); openErr == nil {
					fh.Close()
				}
			}); err != nil {
				t.Fatal(err)
			}
			if openErr == nil {
				t.Error("the file tools read jwt.key")
			}
			if err := agent.RunAsFileToolIdentity(func() {
				openErr = os.WriteFile(filepath.Join(run, "tool.txt"), []byte("x"), 0o644)
			}); err != nil || openErr != nil {
				t.Errorf("the file tools could not write the run directory: %v %v", err, openErr)
			}

			// The agents' confined file tools, through the whole path from the data
			// directory down, as the account.
			tc := &actool.ToolContext{WorkingDir: run}
			write := agent.ConfinedFileTool(f.data, "Write")
			read := agent.ConfinedFileTool(f.data, "Read")
			if write == nil || read == nil {
				t.Fatal("no confined Write or Read tool")
			}
			if res, err := write.Call(context.Background(), json.RawMessage(`{"file_path":"ft.txt","content":"from-the-file-tool"}`), tc); err != nil || res.IsError {
				t.Errorf("confined Write: %v %s", err, res.Flatten())
			}
			if res, err := read.Call(context.Background(), json.RawMessage(`{"file_path":"ft.txt"}`), tc); err != nil || res.IsError || !strings.Contains(res.Flatten(), "from-the-file-tool") {
				t.Errorf("confined Read: %v %s", err, res.Flatten())
			}

			// The probe reports what the account can reach: a file in its run directory.
			spec, err := winIsolationSpec(f.priv, f.targets())
			if err != nil {
				t.Fatal(err)
			}
			spec.Unreadable = append(spec.Unreadable, filepath.Join(run, "out.txt"))
			spec.Unwritable = append(spec.Unwritable, run)
			rep, err := runWinIsolationProbe(spec, f.priv.BinDir)
			if err != nil {
				t.Fatal(err)
			}
			joined := strings.Join(rep.Failures, "; ")
			if !strings.Contains(joined, "can read "+filepath.Join(run, "out.txt")) || !strings.Contains(joined, run) {
				t.Errorf("the probe missed what the account can reach: %s", joined)
			}
		})
	}
}
