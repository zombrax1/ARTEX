//go:build windows

package server

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jackc/pgx/v5"
	"golang.org/x/sys/windows"
)

// The Windows isolation self-test (see isolation.go). The probe starts the way the
// agent's shell starts, as "powershell" looked up on PATH, where InstallBashShim put
// the shim that switches to the agent account; PowerShell then runs the probe copy
// of this binary, which checks from inside that it runs as the agent account, cannot
// read the server's secrets or its process memory, cannot write or replace the
// server's directories, binary, shims or skills, sees no variable of the server's
// environment outside the allowlist, and cannot open a database session without the
// server's password. The file tools are checked in the server, through their
// impersonation.

// winProbeSpec is what the probe checks from inside an agent process.
type winProbeSpec struct {
	SID       string `json:"sid"`
	ServerSID string `json:"server_sid"`
	ServerPID int    `json:"server_pid"`
	// Unreadable are files no agent process may open for reading.
	Unreadable []string `json:"unreadable,omitempty"`
	// Unwritable are directories no agent process may create, remove or rename an
	// entry in, or replace, or change the permissions of.
	Unwritable []string `json:"unwritable,omitempty"`
	// Unreplaceable are files no agent process may write, delete, rename or change the
	// permissions of: the server binary and the shims it runs.
	Unreplaceable []string `json:"unreplaceable,omitempty"`
	// SkillDir is walked: no skill file or directory may be writable.
	SkillDir string             `json:"skill_dir,omitempty"`
	DB       []isolationProbeDB `json:"db,omitempty"`
}

// IsolationSelfTest checks that agent processes and file tools are isolated from
// the server. It returns nil when every check passes, otherwise an error that names
// each failure.
func IsolationSelfTest(p ExecPrivilege, t IsolationTargets) error {
	if !p.Enabled {
		return errors.New("agent processes run with the server's identity: no agent account is set up (run \"artex exec-account setup\" from an elevated prompt, see docs/windows-agent-isolation.md)")
	}
	spec, err := winIsolationSpec(p, t)
	if err != nil {
		return err
	}
	failures := fileToolIsolationFailures(spec.Unreadable)
	if t.DSN != "" && len(spec.DB) == 0 {
		failures = append(failures, "the database DSN names no host the self-test can check")
	}
	rep, err := runWinIsolationProbe(spec, p.BinDir)
	if err != nil {
		failures = append(failures, fmt.Sprintf("the probe did not run through the PowerShell shim: %v", err))
	} else {
		failures = append(failures, rep.Failures...)
	}
	if len(failures) > 0 {
		return errors.New(strings.Join(failures, "; "))
	}
	return nil
}

func winIsolationSpec(p ExecPrivilege, t IsolationTargets) (winProbeSpec, error) {
	self, err := currentUserSID()
	if err != nil {
		return winProbeSpec{}, err
	}
	spec := winProbeSpec{SID: p.SID, ServerSID: self, ServerPID: os.Getpid(), SkillDir: t.SkillDir}
	if t.KeyDir != "" {
		spec.Unreadable = append(spec.Unreadable, filepath.Join(t.KeyDir, "jwt.key"), filepath.Join(t.KeyDir, "secret.key"))
	}
	if t.ConfigPath != "" {
		spec.Unreadable = append(spec.Unreadable, t.ConfigPath)
	}
	if t.DataDir != "" {
		spec.Unreadable = append(spec.Unreadable, filepath.Join(t.DataDir, "traffic", "_ca", "mitmproxy-ca.pem"))
	}
	if p.cred != "" {
		spec.Unreadable = append(spec.Unreadable, p.cred)
	}
	exeDir, err := execExeDir()
	if err != nil {
		return winProbeSpec{}, err
	}
	for _, dir := range []string{t.DataDir, t.KeyDir, configDir(t.ConfigPath), t.SkillDir, exeDir, p.BinDir, p.ScriptDir} {
		if dir == "" {
			continue
		}
		if abs, err := filepath.Abs(dir); err == nil {
			dir = abs
		}
		dup := false
		for _, d := range spec.Unwritable {
			if strings.EqualFold(d, dir) {
				dup = true
			}
		}
		if !dup {
			spec.Unwritable = append(spec.Unwritable, dir)
		}
	}
	if self, err := os.Executable(); err == nil {
		spec.Unreplaceable = append(spec.Unreplaceable, self)
	}
	if p.BinDir != "" {
		spec.Unreplaceable = append(spec.Unreplaceable, filepath.Join(p.BinDir, execProbeExe), filepath.Join(p.BinDir, execShellShimExe))
	}
	if t.DSN != "" {
		if cfg, err := pgx.ParseConfig(t.DSN); err == nil {
			spec.DB = dsnProbeHosts(cfg)
		}
	}
	return spec, nil
}

// psQuote quotes s as a PowerShell single-quoted string.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// runWinIsolationProbe runs the probe through the PowerShell shim. The spec travels
// as a base64 argument and the report as one base64 line on stdout, so that
// PowerShell's re-encoding of native output cannot change either.
func runWinIsolationProbe(spec winProbeSpec, binDir string) (isolationProbeReport, error) {
	var rep isolationProbeReport
	if binDir == "" {
		return rep, errors.New("the agent shim directory is not prepared")
	}
	in, err := json.Marshal(spec)
	if err != nil {
		return rep, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), isolationProbeTimeout)
	defer cancel()
	script := "& " + psQuote(filepath.Join(binDir, execProbeExe)) + " " + isolationProbeArg + " " + psQuote(base64.StdEncoding.EncodeToString(in))
	c := exec.CommandContext(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	c.Dir = binDir
	var stderr bytes.Buffer
	c.Stderr = &stderr
	out, err := c.Output()
	if err != nil {
		return rep, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
	}
	lines := strings.Fields(string(out))
	if len(lines) == 0 {
		return rep, fmt.Errorf("empty probe report: %s", strings.TrimSpace(stderr.String()))
	}
	raw, err := base64.StdEncoding.DecodeString(lines[len(lines)-1])
	if err != nil {
		return rep, fmt.Errorf("unreadable probe report %q: %v", out, err)
	}
	if err := json.Unmarshal(raw, &rep); err != nil {
		return rep, fmt.Errorf("unreadable probe report %q: %v", raw, err)
	}
	return rep, nil
}

// runIsolationProbeMain is the probe process: it decodes the spec from its argument,
// checks, writes the report and exits.
func runIsolationProbeMain(args []string) {
	var spec winProbeSpec
	rep := isolationProbeReport{Failures: []string{}}
	raw, err := []byte(nil), errors.New("no spec argument")
	if len(args) > 0 {
		raw, err = base64.StdEncoding.DecodeString(args[0])
	}
	if err == nil {
		err = json.Unmarshal(raw, &spec)
	}
	if err != nil {
		rep.Failures = append(rep.Failures, fmt.Sprintf("probe: bad spec: %v", err))
	} else {
		rep.Failures = append(rep.Failures, checkIsolationAsAgent(spec)...)
	}
	b, _ := json.Marshal(rep)
	fmt.Println(base64.StdEncoding.EncodeToString(b))
	os.Exit(0)
}

// canOpen reports whether the calling process gets the access to path. A sharing
// violation counts as access: Windows checks the access before the sharing mode, and
// a running binary refuses writers by its sharing mode alone.
func canOpen(path string, access uint32) bool {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(p, access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil,
		windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err == nil {
		windows.CloseHandle(h)
		return true
	}
	return errors.Is(err, windows.ERROR_SHARING_VIOLATION)
}

type namedAccess struct {
	mask uint32
	what string
}

var dirWriteAccess = []namedAccess{
	{fileWriteData, "create files in"},
	{fileAppendData, "create directories in"},
	{fileDeleteChild, "delete entries of"},
	{accessDelete, "delete or rename"},
	{accessWriteDAC, "change the permissions of"},
	{accessWriteOwner, "take ownership of"},
}

var fileWriteAccess = []namedAccess{
	{fileWriteData, "write"},
	{fileAppendData, "append to"},
	{accessDelete, "delete or rename"},
	{accessWriteDAC, "change the permissions of"},
	{accessWriteOwner, "take ownership of"},
}

// firstAccess returns what the first access of list that path grants lets the agent
// do, or "".
func firstAccess(path string, list []namedAccess) string {
	for _, a := range list {
		if canOpen(path, a.mask) {
			return a.what
		}
	}
	return ""
}

// skillProbeMaxEntries bounds the walk of the skill tree.
const skillProbeMaxEntries = 20000

// checkIsolationAsAgent runs the checks of spec in the calling process and returns
// what failed.
func checkIsolationAsAgent(spec winProbeSpec) []string {
	var failures []string
	fail := func(format string, args ...any) { failures = append(failures, fmt.Sprintf(format, args...)) }

	tok := windows.GetCurrentProcessToken()
	sid, err := tokenUserSID(tok)
	switch {
	case err != nil:
		fail("the agent shell cannot read its own identity: %v", err)
	case sid != spec.SID:
		fail("the agent shell runs as %s, not the agent account %s", sid, spec.SID)
	case sid == spec.ServerSID:
		fail("the agent shell runs as the server's Windows user")
	}
	if admin, err := tokenHasAdmins(tok); err != nil || admin {
		fail("the agent shell holds the Administrators group (or its groups cannot be read: %v)", err)
	}
	if tok.IsElevated() {
		fail("the agent shell is elevated")
	}
	for _, path := range spec.Unreadable {
		if f, err := os.Open(path); err == nil {
			f.Close()
			fail("the agent shell can read %s", path)
		}
	}
	if spec.ServerPID > 0 {
		for _, a := range []struct {
			mask uint32
			what string
		}{
			{windows.PROCESS_VM_READ, "read the memory of"},
			{windows.PROCESS_VM_WRITE, "write the memory of"},
			{windows.PROCESS_DUP_HANDLE, "duplicate the handles of"},
			{windows.PROCESS_CREATE_THREAD, "start a thread in"},
			{windows.PROCESS_TERMINATE, "terminate"},
		} {
			if h, err := windows.OpenProcess(a.mask, false, uint32(spec.ServerPID)); err == nil {
				windows.CloseHandle(h)
				fail("the agent shell can %s the server process", a.what)
			}
		}
	}
	for _, dir := range spec.Unwritable {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if what := firstAccess(dir, dirWriteAccess); what != "" {
			fail("the agent shell can %s %s", what, dir)
			continue
		}
		parent := filepath.Dir(dir)
		if parent != dir && canOpen(parent, fileAppendData) && canOpen(parent, fileDeleteChild) {
			fail("the agent shell can replace %s: it can delete entries of and create directories in its parent %s", dir, parent)
		}
	}
	for _, f := range spec.Unreplaceable {
		if _, err := os.Stat(f); err != nil {
			continue
		}
		if what := firstAccess(f, fileWriteAccess); what != "" {
			fail("the agent shell can %s %s", what, f)
		}
	}
	if spec.SkillDir != "" {
		n, reported := 0, 0
		_ = filepath.WalkDir(spec.SkillDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			n++
			if n > skillProbeMaxEntries || reported >= skillTreeMaxFailures {
				return fs.SkipAll
			}
			if d.Type()&fs.ModeSymlink != 0 || d.Type()&fs.ModeIrregular != 0 {
				return nil // a link is judged by the server's own skill loader, not descended
			}
			list := fileWriteAccess
			if d.IsDir() {
				list = dirWriteAccess
			}
			if what := firstAccess(path, list); what != "" {
				reported++
				fail("the agent shell can %s the skill entry %s, bypassing the skill approval", what, path)
			}
			return nil
		})
	}
	failures = append(failures, envFailures(tok)...)
	for i := range spec.DB {
		db := &spec.DB[i]
		if err := connectWithoutPassword(db); err == nil {
			fail("the agent shell opened a database session as %q on %s:%d without the server's password", db.User, db.Host, db.Port)
		}
	}
	return failures
}

// shellOwnEnv are the variables PowerShell itself sets for the programs it starts.
var shellOwnEnv = upperSet("PSModulePath")

// envFailures reports each variable of the probe's environment that neither comes
// from the agent account's own environment nor is on the allowlist: it came from
// the server.
func envFailures(tok windows.Token) []string {
	var real windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY|windows.TOKEN_DUPLICATE|windows.TOKEN_IMPERSONATE, &real); err != nil {
		return []string{fmt.Sprintf("the agent shell cannot open its token: %v", err)}
	}
	defer real.Close()
	own, err := ownEnvironment(real)
	if err != nil {
		return []string{fmt.Sprintf("the agent shell cannot build its own environment: %v", err)}
	}
	ownSet := map[string]bool{}
	for _, kv := range own {
		name, v, _ := strings.Cut(kv, "=")
		ownSet[strings.ToUpper(name)+"="+v] = true
	}
	var failures []string
	for _, kv := range os.Environ() {
		name, v, _ := strings.Cut(kv, "=")
		if name == "" {
			continue
		}
		up := strings.ToUpper(name)
		if executorEnvAllowed(name) || shellOwnEnv[up] || ownSet[up+"="+v] {
			continue
		}
		failures = append(failures, fmt.Sprintf("the variable %s reached the agent shell: it is neither on the agent environment allowlist nor the agent account's own", name))
	}
	return failures
}
