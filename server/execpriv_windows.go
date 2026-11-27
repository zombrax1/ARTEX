//go:build windows

package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/traffic"
)

// Agent process isolation on Windows. The server runs as the operator's Windows
// user; every process the agent can start (Bash's PowerShell, the interactive shell,
// background tasks, custom tools, stdio MCP servers) runs as a separate, non-admin
// local account instead (execaccount_windows.go), and the file tools impersonate it
// (agent/filetools_identity_windows.go). The account cannot read the operator's
// profile, the server's process, or the files ACLs deny it: the keys, the config,
// the credential and the MITM CA key, and cannot write the server's directories.
//
// Windows has no exec and no setuid. A shim, a copy of this binary, stands in for
// the program: Norma starts "powershell" from PATH, and a copy named powershell.exe
// in BinDir is first there; MCP servers and custom tools start as
// "artex __artex-exec-drop ... -- <command>". The shim, still the server's user,
// logs the account on with CreateProcessWithLogonW (which needs no privilege), on a
// window station and desktop of its own, inside a Job Object that ends the whole
// process tree when the shim ends (Norma kills the shim on a timeout or cancel) and
// denies it the clipboard and other processes' windows. It passes its standard
// handles through, waits, and exits with the child's exit code.

// Environment names the shim reads. They carry no secret: the real shell, the
// account name and SID, the path of the credential (which only the server's user
// can decrypt) and the shim directory.
const (
	envExecShell   = "ARTEX_EXEC_SHELL"
	envExecAccount = "ARTEX_EXEC_ACCOUNT"
	envExecSID     = "ARTEX_EXEC_SID"
	envExecCred    = "ARTEX_EXEC_CRED"
	envExecBin     = "ARTEX_EXEC_BIN"
)

const (
	execBinDirName    = "exec-bin"
	execScriptDirName = "exec-scripts"
	execProbeExe      = "artex.exe"
	execShellShimExe  = "powershell.exe"
)

func execPrivilegeSupported() bool { return false } // the uid drop; see ResolveExecAccount

func serverIsRoot() bool { return false }

// applyExecCredential does nothing: custom tools start through the drop shim
// (execToolCommand), which applies the account.
func applyExecCredential(c *exec.Cmd, p ExecPrivilege) {}

// prepareExecScript does nothing: a script written to the script directory takes
// its ACL, readable by the agent account, from the directory.
func prepareExecScript(p ExecPrivilege, path string) error { return nil }

// accountSID parses p.SID.
func (p ExecPrivilege) accountSID() (*windows.SID, error) {
	if p.SID == "" {
		return nil, errors.New("the agent account has no SID")
	}
	return windows.StringToSid(p.SID)
}

// Run directories: the agent account can change what is inside, and the directory's
// own entry minus DELETE, so it cannot remove the run directory and put a junction
// in its place (it cannot create entries in the parent either: the data directory
// denies it writes).
var runDirACEs = []fileACE{
	{windows.GRANT_ACCESS, aclModify &^ accessDelete, windows.NO_INHERITANCE},
	{windows.GRANT_ACCESS, aclModify, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT | windows.INHERIT_ONLY},
}

// Directories the agent account reads and runs from and never writes.
var readOnlyDirACEs = []fileACE{
	{windows.GRANT_ACCESS, aclReadExec, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT},
}

// Directories the server owns: no entry may be created, removed or renamed in them
// by the agent account, nor their permissions changed.
var denyWriteACEs = []fileACE{
	{windows.DENY_ACCESS, aclDenyWrite, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT},
}

// Directories whose new files are secret: every file below denies the account.
var denyFilesACEs = []fileACE{
	{windows.DENY_ACCESS, aclDenyAll, windows.OBJECT_INHERIT_ACE | windows.INHERIT_ONLY},
}

// Secret files: no access at all.
var denyAllACEs = []fileACE{
	{windows.DENY_ACCESS, aclDenyAll, windows.NO_INHERITANCE},
}

// makeLeafDirWin creates leaf below base, every directory between them taking the
// permissions of its parent, and gives the leaf aces.
func makeLeafDirWin(base, leaf string, sid *windows.SID, aces []fileACE) error {
	rel, err := filepath.Rel(base, leaf)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return fmt.Errorf("%s is not below %s", leaf, base)
	}
	if err := os.MkdirAll(leaf, 0o755); err != nil {
		return err
	}
	return addACEs(leaf, sid, aces)
}

// traverseACEs let the agent account pass through a directory and read its
// attributes, not list it.
var traverseACEs = []fileACE{{windows.GRANT_ACCESS, aclTraverse, windows.NO_INHERITANCE}}

// shareAncestorsWin gives the agent account traverseACEs on dataDir, on every
// directory created below it (by inheritance, directories only) and on each of its
// ancestors short of the volume root.
func shareAncestorsWin(dataDir string, sid *windows.SID) error {
	if err := addACEs(dataDir, sid, []fileACE{
		{windows.GRANT_ACCESS, aclTraverse, windows.SUB_CONTAINERS_ONLY_INHERIT},
	}); err != nil {
		return fmt.Errorf("let the agent account traverse %s: %w", dataDir, err)
	}
	for dir := filepath.Dir(dataDir); ; dir = filepath.Dir(dir) {
		if filepath.Dir(dir) == dir {
			return nil // the volume root: readable by local users by default
		}
		// A directory the server may not change (C:\Users, say) already lets
		// local users through: skip it quietly.
		if err := addACEs(dir, sid, traverseACEs); err != nil && !errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			log.Printf("[exec] %v", err)
		}
	}
}

// shareTaskDirWin gives the agent account the run directories of a task directory,
// and the entries that date from before the run-directory layout (see shareTaskDir
// in execpriv_unix.go). Links and junctions are left alone.
func shareTaskDirWin(taskDir string, sid *windows.SID) error {
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		path := filepath.Join(taskDir, e.Name())
		fi, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			continue
		}
		if agent.IsRunDirName(e.Name()) {
			if fi.IsDir() {
				err = addACEs(path, sid, runDirACEs)
			}
		} else {
			err = addACEs(path, sid, []fileACE{{windows.GRANT_ACCESS, aclModify, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT}})
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// shareRunDirsWin applies the run-directory permissions to what is on disk.
func shareRunDirsWin(dataDir string, sid *windows.SID) error {
	for _, sub := range []string{"tasks", "sessions"} {
		root := filepath.Join(dataDir, sub)
		if err := os.MkdirAll(root, 0o755); err != nil {
			return err
		}
		entries, err := os.ReadDir(root)
		if err != nil {
			return err
		}
		for _, e := range entries {
			path := filepath.Join(root, e.Name())
			fi, err := os.Lstat(path)
			if err != nil {
				return err
			}
			if !fi.IsDir() || fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
				continue
			}
			if sub == "tasks" {
				err = shareTaskDirWin(path, sid)
			} else {
				err = addACEs(path, sid, runDirACEs)
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func shareRestoredTaskDir(p ExecPrivilege, taskDir string) error {
	if !p.Enabled {
		return nil
	}
	sid, err := p.accountSID()
	if err != nil {
		return err
	}
	return shareTaskDirWin(taskDir, sid)
}

func shareRestoredSpillDir(p ExecPrivilege, dir string) error {
	if !p.Enabled {
		return nil
	}
	sid, err := p.accountSID()
	if err != nil {
		return err
	}
	return addACEs(dir, sid, readOnlyDirACEs)
}

// execExeDir is the directory of the server binary.
func execExeDir() (string, error) {
	self, err := os.Executable()
	if err != nil {
		return "", err
	}
	if self, err = filepath.EvalSymlinks(self); err != nil {
		return "", err
	}
	return filepath.Dir(self), nil
}

// copyFileAtomic copies src to dst through a temporary file in dst's directory.
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dst); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// tryACEs applies aces to path and logs a failure instead of returning it: the
// self-test then reports what the agent account can still reach.
func tryACEs(path string, sid *windows.SID, aces []fileACE) {
	if path == "" {
		return
	}
	if _, err := os.Lstat(path); err != nil {
		return
	}
	if err := addACEs(path, sid, aces); err != nil {
		log.Printf("[exec] %v", err)
	}
}

// PrepareExecPrivilege sets up what the agent account needs before the server opens
// its stores: the account signs in and is no administrator; the keys, the config,
// the credential and the MITM CA key deny it all access; the data, key, config,
// skill and binary directories deny it writes; run directories, the spill
// directories, the script directory and the shim directory are shared with it as
// the Linux layout shares them with the executor group; and the file tools get its
// impersonation token.
func PrepareExecPrivilege(p *ExecPrivilege, dataDir, keyDir, configPath string) error {
	if !p.Enabled {
		return nil
	}
	cred, err := loadExecCred(p.cred)
	if err != nil {
		return err
	}
	tok, err := logonExecAccount(cred)
	if err != nil {
		return err
	}
	if got, err := tokenUserSID(tok); err != nil || got != p.SID {
		tok.Close()
		return fmt.Errorf("the agent account %s signed in as %s, want %s (%v)", p.Account, got, p.SID, err)
	}
	if admin, err := tokenHasAdmins(tok); err != nil || admin {
		tok.Close()
		if err != nil {
			return err
		}
		return fmt.Errorf("the agent account %s is a member of Administrators: it must be a standard user", p.Account)
	}
	var imp windows.Token
	err = windows.DuplicateTokenEx(tok, windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE,
		nil, windows.SecurityImpersonation, windows.TokenImpersonation, &imp)
	tok.Close()
	if err != nil {
		return fmt.Errorf("agent account impersonation token: %w", err)
	}
	sid, err := p.accountSID()
	if err != nil {
		return err
	}
	if dataDir, err = filepath.Abs(dataDir); err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}

	// The agent's shells resolve their working directory component by component
	// (PowerShell falls back to the drive root otherwise), so the account may
	// traverse and read the attributes of the data directory's ancestors and of
	// every directory below it, without listing them or reading files there.
	if err := shareAncestorsWin(dataDir, sid); err != nil {
		return err
	}

	// Writes denied first: everything created below takes the deny from here on.
	exeDir, err := execExeDir()
	if err != nil {
		return err
	}
	for _, dir := range []string{dataDir, keyDir, configDir(configPath), p.SkillDir, exeDir} {
		tryACEs(dir, sid, denyWriteACEs)
	}
	// Agents run skill scripts: the skill tree stays readable.
	tryACEs(p.SkillDir, sid, readOnlyDirACEs)
	// Agents start the MCP servers ARTEX installs (server/mcptools.go): the tools
	// folder is readable and runnable, not writable.
	toolsDir := MCPToolsDir(dataDir)
	if err := os.MkdirAll(toolsDir, 0o755); err != nil {
		return err
	}
	tryACEs(toolsDir, sid, readOnlyDirACEs)
	for _, f := range []string{filepath.Join(keyDir, "jwt.key"), filepath.Join(keyDir, "secret.key"), configPath, p.cred} {
		tryACEs(f, sid, denyAllACEs)
	}
	// The keys may not exist yet: NewManager and server.New create them after this,
	// and Windows ignores their 0600 mode. Every file created below the key and
	// config directories denies the account by inheritance; what it must read there
	// (run, spill, script and shim directories, the skills, the CA certificate) is
	// granted closer to the file, which takes precedence. The self-test checks a
	// freshly created file (secretCanaries).
	for _, dir := range []string{keyDir, configDir(configPath)} {
		tryACEs(dir, sid, denyFilesACEs)
	}
	// The MITM CA: the certificate is read by the agents' tools, the key is not.
	caDir := filepath.Join(dataDir, "traffic", "_ca")
	if err := os.MkdirAll(caDir, 0o755); err != nil {
		return err
	}
	if err := addACEs(caDir, sid, []fileACE{{windows.GRANT_ACCESS, aclRead, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT}}); err != nil {
		return err
	}
	tryACEs(filepath.Join(caDir, "mitmproxy-ca.pem"), sid, denyAllACEs)
	traffic.RestrictCAKey = func(path string) error { return addACEs(path, sid, denyAllACEs) }

	if err := shareRunDirsWin(dataDir, sid); err != nil {
		return fmt.Errorf("share the run directories with the agent account: %w", err)
	}
	agent.SetRunDirMaker(func(base, leaf string) error { return makeLeafDirWin(base, leaf, sid, runDirACEs) })
	agent.SetSpillDirMaker(
		func(base, dir string) error { return makeLeafDirWin(base, dir, sid, readOnlyDirACEs) },
		func(string) error { return nil }, // spill files take the directory's ACL
	)

	scriptDir := filepath.Join(dataDir, execScriptDirName)
	if err := makeLeafDirWin(dataDir, scriptDir, sid, readOnlyDirACEs); err != nil {
		return fmt.Errorf("prepare the agent script directory: %w", err)
	}
	p.ScriptDir = scriptDir

	binDir := filepath.Join(dataDir, execBinDirName)
	if err := makeLeafDirWin(dataDir, binDir, sid, readOnlyDirACEs); err != nil {
		return fmt.Errorf("prepare the agent shim directory: %w", err)
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	for _, name := range []string{execProbeExe, execShellShimExe} {
		if err := copyFileAtomic(self, filepath.Join(binDir, name)); err != nil {
			return fmt.Errorf("install the agent shim %s: %w", name, err)
		}
	}
	p.BinDir = binDir

	agent.SetFileToolIdentity(&agent.FileToolIdentity{Token: uintptr(imp)})
	log.Printf("[exec] agent processes and file tools run as the local account %s (%s)", p.Account, p.SID)
	return nil
}

// InstallBashShim puts the PowerShell shim first on PATH: Norma starts the agent
// shell as "powershell" looked up there. The real PowerShell is resolved first.
func InstallBashShim(p ExecPrivilege) error {
	if !p.Enabled {
		return nil
	}
	if p.BinDir == "" {
		return errors.New("the agent shim directory is not prepared")
	}
	real, err := exec.LookPath("powershell")
	if err != nil {
		return fmt.Errorf("PowerShell is needed for the agent shell: %w", err)
	}
	if real, err = filepath.Abs(real); err != nil {
		return err
	}
	for k, v := range map[string]string{
		envExecShell: real, envExecAccount: p.Account, envExecSID: p.SID, envExecCred: p.cred, envExecBin: p.BinDir,
	} {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
	}
	return os.Setenv("PATH", p.BinDir+string(os.PathListSeparator)+pathWithout(os.Getenv("PATH"), p.BinDir))
}

// RunExecShimIfRequested makes the process a shim when it was started as one: as
// powershell through the PATH shim, or as artex __artex-exec-drop for an MCP stdio
// command or a custom tool; or the isolation self-test probe (isolation_windows.go).
// It exits; it returns only for an ordinary start.
func RunExecShimIfRequested(argv []string) {
	if len(argv) == 0 {
		return
	}
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(argv[0])), ".exe")
	if base == "powershell" && os.Getenv(envExecShell) != "" {
		os.Exit(shimRun(os.Getenv(envExecShell), argv[1:], false))
	}
	if len(argv) >= 2 && argv[1] == execDropArg {
		runDropShim(argv[2:])
	}
	if len(argv) >= 2 && argv[1] == execChildArg {
		runExecChild()
	}
	if len(argv) >= 2 && argv[1] == isolationProbeArg {
		runIsolationProbeMain(argv[2:])
	}
}

// execChildArg is the argv marker of the launcher: the process the shim starts as
// the agent account, which starts the real command from envExecLaunch.
const execChildArg = "__artex-exec-child"

// envExecLaunch carries the real command from the shim to the launcher.
const envExecLaunch = "ARTEX_EXEC_LAUNCH"

// createProcessWithLogonMaxCmdLine is the documented command-line limit of
// CreateProcessWithLogonW.
const createProcessWithLogonMaxCmdLine = 1024

type execLaunch struct {
	App  string   `json:"app"`
	Args []string `json:"args"`
}

// runExecChild is the launcher, already the agent account and in the job: it takes
// the command out of its environment, so the command does not see it, and runs it
// with the standard handles, exiting with its exit code.
func runExecChild() {
	var l execLaunch
	if err := json.Unmarshal([]byte(os.Getenv(envExecLaunch)), &l); err != nil || l.App == "" {
		shimFail(fmt.Errorf("launcher: no command in %s: %v", envExecLaunch, err))
	}
	if err := os.Unsetenv(envExecLaunch); err != nil {
		shimFail(err)
	}
	os.Exit(runDirect(l.App, l.Args))
}

// runDropShim runs "<uid> <gid> -- <command> <args...>" as the agent account. The
// ids are those of the Linux drop and are not used here.
func runDropShim(args []string) {
	i := 0
	for i < len(args) && args[i] != "--" {
		i++
	}
	if i+1 >= len(args) {
		shimFail(errors.New("drop shim: no command after --"))
	}
	os.Exit(shimRun(args[i+1], args[i+2:], true))
}

func shimFail(err error) {
	fmt.Fprintf(os.Stderr, "artex agent shim: %v\n", err)
	os.Exit(126)
}

// shimRun starts app with args as the agent account and returns its exit code.
// lookup resolves app on the agent's PATH first (a command name of an MCP server or
// an interpreter); the shell shim passes an absolute path.
func shimRun(app string, args []string, lookup bool) int {
	account, sidStr, credPath, binDir := os.Getenv(envExecAccount), os.Getenv(envExecSID), os.Getenv(envExecCred), os.Getenv(envExecBin)
	if account == "" || sidStr == "" || credPath == "" {
		shimFail(errors.New("the agent account is not configured in the environment"))
	}
	self, err := currentUserSID()
	if err != nil {
		shimFail(err)
	}
	if self == sidStr {
		// Already the agent account (it ran the shim itself): nothing to cross.
		return runDirect(app, args)
	}
	cred, err := loadExecCred(credPath)
	if err != nil {
		shimFail(err)
	}
	if !strings.EqualFold(cred.Account, account) {
		shimFail(fmt.Errorf("the credential is for %s, not %s", cred.Account, account))
	}
	tok, err := logonExecAccount(cred)
	if err != nil {
		shimFail(err)
	}
	env, err := agentChildEnv(tok, os.Environ(), binDir)
	tok.Close()
	if err != nil {
		shimFail(fmt.Errorf("build the agent environment: %w", err))
	}
	if lookup {
		if app, err = lookPathIn(app, env); err != nil {
			shimFail(err)
		}
	}
	// CreateProcessWithLogonW takes at most 1,024 characters of command line, far
	// less than an agent command. The account starts the launcher copy in binDir with
	// a short command line instead, and the launcher reads the real command from its
	// environment (no length limit short of the 32K of a Windows command line).
	launch, err := json.Marshal(execLaunch{App: app, Args: args})
	if err != nil {
		shimFail(err)
	}
	env = append(env, envExecLaunch+"="+string(launch))
	block, err := envListToBlock(env)
	if err != nil {
		shimFail(err)
	}
	code, err := startAsAccount(cred, self, sidStr, filepath.Join(binDir, execProbeExe), []string{execChildArg}, block)
	if err != nil {
		shimFail(err)
	}
	return code
}

// runDirect runs app with args in this process's identity, passing the standard
// handles through.
func runDirect(app string, args []string) int {
	c := exec.Command(app, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}
		shimFail(err)
	}
	return 0
}

// lookPathIn resolves file on the PATH and PATHEXT of env.
func lookPathIn(file string, env []string) (string, error) {
	for _, kv := range env {
		name := envName(kv)
		if strings.EqualFold(name, "PATH") || strings.EqualFold(name, "PATHEXT") {
			_, v, _ := strings.Cut(kv, "=")
			if err := os.Setenv(name, v); err != nil {
				return "", err
			}
		}
	}
	p, err := exec.LookPath(file)
	if err != nil {
		return "", err
	}
	return filepath.Abs(p)
}

// startAsAccount starts app as the agent account on a window station of its own and
// in a kill-on-close Job Object, waits for it and returns its exit code.
func startAsAccount(cred execCred, serverSID, agentSID, app string, args []string, env *uint16) (int, error) {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, err
	}
	desktop, closeStation, err := newAgentWindowStation("artex-agent-"+strconv.Itoa(os.Getpid())+"-"+hex.EncodeToString(nonce[:]), serverSID, agentSID)
	if err != nil {
		return 0, fmt.Errorf("agent window station: %w", err)
	}
	defer closeStation()
	job, err := newAgentJob()
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(job) // kills what is left of the tree

	deskPtr, err := windows.UTF16PtrFromString(desktop)
	if err != nil {
		return 0, err
	}
	si := windows.StartupInfo{
		Cb:         uint32(unsafe.Sizeof(windows.StartupInfo{})),
		Desktop:    deskPtr,
		Flags:      windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW,
		ShowWindow: windows.SW_HIDE,
	}
	for _, h := range []struct {
		std uint32
		dst *windows.Handle
	}{{windows.STD_INPUT_HANDLE, &si.StdInput}, {windows.STD_OUTPUT_HANDLE, &si.StdOutput}, {windows.STD_ERROR_HANDLE, &si.StdErr}} {
		handle, err := windows.GetStdHandle(h.std)
		if err != nil || handle == windows.InvalidHandle {
			continue
		}
		_ = windows.SetHandleInformation(handle, windows.HANDLE_FLAG_INHERIT, windows.HANDLE_FLAG_INHERIT)
		*h.dst = handle
	}
	cwd, err := os.Getwd()
	if err != nil {
		return 0, err
	}
	cmdLine := windows.ComposeCommandLine(append([]string{app}, args...))
	if n := len(windows.StringToUTF16(cmdLine)) - 1; n > createProcessWithLogonMaxCmdLine {
		return 0, fmt.Errorf("the launcher command line is %d characters, more than the %d CreateProcessWithLogonW takes: move ARTEX's data directory to a shorter path", n, createProcessWithLogonMaxCmdLine)
	}
	var pi windows.ProcessInformation
	if err := createProcessWithLogon(cred.Account, cred.Password, app, cmdLine,
		windows.CREATE_SUSPENDED|windows.CREATE_UNICODE_ENVIRONMENT, env, cwd, &si, &pi); err != nil {
		return 0, fmt.Errorf("start %s as %s: %w", app, cred.Account, err)
	}
	defer windows.CloseHandle(pi.Process)
	defer windows.CloseHandle(pi.Thread)
	if err := windows.AssignProcessToJobObject(job, pi.Process); err != nil {
		_ = windows.TerminateProcess(pi.Process, 126)
		return 0, fmt.Errorf("put the agent process in its job: %w", err)
	}
	if _, err := windows.ResumeThread(pi.Thread); err != nil {
		_ = windows.TerminateProcess(pi.Process, 126)
		return 0, fmt.Errorf("resume the agent process: %w", err)
	}
	if _, err := windows.WaitForSingleObject(pi.Process, windows.INFINITE); err != nil {
		return 0, err
	}
	var code uint32
	if err := windows.GetExitCodeProcess(pi.Process, &code); err != nil {
		return 0, err
	}
	return int(code), nil
}

// newAgentJob creates the Job Object of one agent process tree: the tree ends when
// the job's last handle closes (the shim exits or is killed), and it may not use the
// clipboard, other processes' windows, global atoms or system settings.
func newAgentJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, fmt.Errorf("create the agent job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION,
		},
	}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("limit the agent job: %w", err)
	}
	ui := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: jobUILimitAll}
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
		windows.CloseHandle(job)
		return 0, fmt.Errorf("restrict the agent job's UI access: %w", err)
	}
	return job, nil
}
