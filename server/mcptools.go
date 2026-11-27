package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
)

// ARTEX installs the free, keyless MCP servers of the preset catalog by itself
// (mcpPreset.Auto) into a tools folder under the data directory, adds a row for
// each one it can run, and starts them with the other enabled servers. Nothing
// that needs an API key, a path or another program running is installed or
// added. A server the user already has on PATH is used as is. Set
// ARTEX_MCP_AUTOINSTALL=off to turn all of this off.
//
// Layout of <data>/mcp-tools:
//
//	bin/            pinned release binaries (osv-scanner, trivy-mcp), checksum-verified
//	py/             a Python virtual environment for the pip packages (semgrep, mcp-server-nmap);
//	                their commands are linked into bin/
//	node/           an npm prefix for the npm packages (@playwright/mcp)
//	ms-playwright/  the Chromium build Playwright downloads, when ARTEX installed Playwright
const mcpToolsDirName = "mcp-tools"

// envMCPAutoInstall turns the automatic install and add off when set to off, 0,
// false or no.
const envMCPAutoInstall = "ARTEX_MCP_AUTOINSTALL"

// MCPToolsDir is the folder ARTEX installs MCP servers into, as an absolute
// path: it goes on PATH, which a relative folder would break for processes
// started in another directory.
func MCPToolsDir(dataDir string) string {
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}
	return filepath.Join(dataDir, mcpToolsDirName)
}

// MCPAutoInstallEnabled reports whether ARTEX may install and add the free MCP
// servers on its own.
func MCPAutoInstallEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envMCPAutoInstall))) {
	case "off", "0", "false", "no":
		return false
	}
	return true
}

func venvBinDir(goos string) string {
	if goos == "windows" {
		return "Scripts"
	}
	return "bin"
}

// mcpToolPathDirs are the folders of the tools dir that hold commands.
func mcpToolPathDirs(tools, goos string) []string {
	return []string{
		filepath.Join(tools, "bin"),
		filepath.Join(tools, "node", "node_modules", ".bin"),
	}
}

// appendPathDirs adds dirs to the end of a PATH value, skipping ones it already
// has, so a command the user installed always wins over ARTEX's copy.
func appendPathDirs(path string, dirs []string) string {
	have := map[string]bool{}
	for _, d := range filepath.SplitList(path) {
		have[pathKey(d)] = true
	}
	parts := []string{}
	if path != "" {
		parts = append(parts, path)
	}
	for _, d := range dirs {
		if !have[pathKey(d)] {
			parts = append(parts, d)
			have[pathKey(d)] = true
		}
	}
	return strings.Join(parts, string(os.PathListSeparator))
}

func pathKey(p string) string {
	p = filepath.Clean(p)
	if runtime.GOOS == "windows" {
		return strings.ToLower(p)
	}
	return p
}

// AddMCPToolsToPath makes the commands of the tools dir visible to ARTEX and to
// every process it starts (agent processes get PATH through executorEnvNames).
// It runs before anything resolves a command, and again after an install adds a
// folder. The folders go at the end of PATH.
func AddMCPToolsToPath(dataDir string) {
	tools := MCPToolsDir(dataDir)
	_ = os.Setenv("PATH", appendPathDirs(os.Getenv("PATH"), mcpToolPathDirs(tools, runtime.GOOS)))
	usePlaywrightBrowsers(tools)
}

// usePlaywrightBrowsers points Playwright at the Chromium ARTEX downloaded, but
// only when it did download one and nothing else picked a location: a browser
// the user installed in Playwright's default cache keeps working.
func usePlaywrightBrowsers(tools string) {
	if os.Getenv("PLAYWRIGHT_BROWSERS_PATH") != "" {
		return
	}
	dir := filepath.Join(tools, "ms-playwright")
	if _, err := os.Stat(filepath.Join(dir, playwrightDoneMarker)); err == nil {
		_ = os.Setenv("PLAYWRIGHT_BROWSERS_PATH", dir)
	}
}

// mcpReleaseAsset is one pinned download. Archive is "" for a bare binary or
// "tar.gz"; Member is the file to take out of an archive.
type mcpReleaseAsset struct {
	URL     string
	SHA256  string
	Archive string
	Member  string
}

// mcpReleaseBinary is a preset installed from a pinned release binary.
type mcpReleaseBinary struct {
	PresetID string
	Command  string
	Version  string
	Assets   map[string]mcpReleaseAsset // key: GOOS/GOARCH
}

func osvAsset(goos, goarch, sum string) mcpReleaseAsset {
	name := "osv-scanner_" + goos + "_" + goarch
	if goos == "windows" {
		name += ".exe"
	}
	return mcpReleaseAsset{URL: "https://github.com/google/osv-scanner/releases/download/v2.7.1/" + name, SHA256: sum}
}

func trivyMCPAsset(goos, goarch, sum string) mcpReleaseAsset {
	member := "trivy-mcp"
	if goos == "windows" {
		member += ".exe"
	}
	return mcpReleaseAsset{
		URL:     "https://github.com/aquasecurity/trivy-mcp/releases/download/v0.0.20/trivy-mcp-" + goos + "-" + goarch + ".tar.gz",
		SHA256:  sum,
		Archive: "tar.gz",
		Member:  member,
	}
}

// mcpReleaseBinaries pins the release binaries ARTEX downloads. The checksums
// were taken from each project's release (osv-scanner's SHA256SUMS; trivy-mcp
// publishes none, so they are the sha256 of the downloaded assets). Bump the
// version and every checksum together.
var mcpReleaseBinaries = []mcpReleaseBinary{
	{
		PresetID: "osv-scanner",
		Command:  "osv-scanner",
		Version:  "2.7.1",
		Assets: map[string]mcpReleaseAsset{
			"darwin/amd64":  osvAsset("darwin", "amd64", "b8420d5485ba792626315f1bf9a5a2046e971d38eea75bf9090c38852dbc3b1b"),
			"darwin/arm64":  osvAsset("darwin", "arm64", "b22c02877a811c8f78956e8643efa554932b7378f590d13f8e97d4e9448a29f3"),
			"linux/amd64":   osvAsset("linux", "amd64", "fb7dab19a8bd9bbe5c3189f09d4b7ee1820c9553a23bac202648a56efd2f6ee8"),
			"linux/arm64":   osvAsset("linux", "arm64", "983d22fbad9724514e3fcc6acc83b5fa64c5ffa6b0d9f510028f22c1b223ff81"),
			"windows/amd64": osvAsset("windows", "amd64", "7121dcf420aefbbf89a7f0050c4d3094e079ff93afd334dfc96f16b02ec85800"),
			"windows/arm64": osvAsset("windows", "arm64", "5f3998b55c9268f8468502bbcb60645038fd5b145ee5e685e6ae2a32e923afc7"),
		},
	},
	{
		PresetID: "trivy",
		Command:  "trivy-mcp",
		Version:  "0.0.20",
		Assets: map[string]mcpReleaseAsset{
			"darwin/amd64":  trivyMCPAsset("darwin", "amd64", "1e97b1f9607771b820899e09dc5fc5b4df9851032e88083163b3c24a8e7e70fe"),
			"darwin/arm64":  trivyMCPAsset("darwin", "arm64", "51be0ef16466cdcc3cf8f45561b6fab3e57c30fc9d5265d4bce4094f01aec1d9"),
			"linux/amd64":   trivyMCPAsset("linux", "amd64", "5168a3da88af9f39b12096e2686416f09f306b7320559b757fe5fca0d5d8e468"),
			"linux/arm64":   trivyMCPAsset("linux", "arm64", "9a1e548f071eebad6404fbf9bec867bd2be3f378234cd9fbbaac563b99d31a58"),
			"windows/amd64": trivyMCPAsset("windows", "amd64", "d741ab246e007219decc77408d58f27fb87ad8488cb8ae50c2da0f1fe8423b86"),
		},
	},
}

// mcpPipPackage is a preset installed with pip into the tools venv.
type mcpPipPackage struct {
	PresetID string
	Command  string
	Spec     string
}

var mcpPipPackages = []mcpPipPackage{
	{PresetID: "semgrep", Command: "semgrep", Spec: "semgrep==1.187.0"},
	{PresetID: "nmap", Command: "mcp-server-nmap", Spec: "mcp-server-nmap==0.1.1"},
}

// mcpNpmPackage is a preset installed with npm into the tools prefix.
type mcpNpmPackage struct {
	PresetID string
	Command  string
	Spec     string
	// Entry is the package's bin script under node_modules, which node runs on
	// Windows in place of the .cmd wrapper npm puts on PATH.
	Entry string
}

var mcpNpmPackages = []mcpNpmPackage{
	{PresetID: "playwright", Command: browserMCPCommandName, Spec: "@playwright/mcp@0.0.86", Entry: "@playwright/mcp/cli.js"},
}

// mcpInstallState is what the installer did for one preset, shown on its card.
type mcpInstallState struct {
	// State: "installing", "installed" (by ARTEX, or found on PATH), "failed",
	// or "unavailable" (nothing to install it with on this machine).
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// mcpInstaller holds the tools dir and the per-preset install state.
type mcpInstaller struct {
	dir    string
	client *http.Client
	mu     sync.Mutex
	states map[string]mcpInstallState
}

func newMCPInstaller(dataDir string) *mcpInstaller {
	return &mcpInstaller{
		dir:    MCPToolsDir(dataDir),
		client: &http.Client{Timeout: 15 * time.Minute},
		states: map[string]mcpInstallState{},
	}
}

func (in *mcpInstaller) set(id, state, msg string) {
	in.mu.Lock()
	in.states[id] = mcpInstallState{State: state, Message: msg}
	in.mu.Unlock()
}

func (in *mcpInstaller) state(id string) (mcpInstallState, bool) {
	if in == nil {
		return mcpInstallState{}, false
	}
	in.mu.Lock()
	defer in.mu.Unlock()
	st, ok := in.states[id]
	return st, ok
}

// WithMCPAutoInstall makes the server install and add the free MCP servers into
// dataDir's tools folder when it starts. Only the binary passes it, so tests
// never download anything.
func WithMCPAutoInstall(dataDir string) Option {
	return func(s *Server) {
		if MCPAutoInstallEnabled() {
			s.toolInstaller = newMCPInstaller(dataDir)
		}
	}
}

// commandWithExe returns the file name of a command on goos.
func commandWithExe(command, goos string) string {
	if goos == "windows" {
		return command + ".exe"
	}
	return command
}

// installReleaseBinary downloads, checks and installs one pinned binary into
// <tools>/bin. It returns errMCPNoBuild when the release has no build for this
// platform.
func (in *mcpInstaller) installReleaseBinary(ctx context.Context, b mcpReleaseBinary) error {
	asset, ok := b.Assets[runtime.GOOS+"/"+runtime.GOARCH]
	if !ok {
		return errMCPNoBuild
	}
	binDir := filepath.Join(in.dir, "bin")
	if err := mkdirShared(binDir); err != nil {
		return err
	}
	data, err := in.download(ctx, asset.URL)
	if err != nil {
		return err
	}
	if err := checkSHA256(data, asset.SHA256); err != nil {
		return fmt.Errorf("%s: %w", asset.URL, err)
	}
	if asset.Archive == "tar.gz" {
		if data, err = tarGzMember(data, asset.Member); err != nil {
			return fmt.Errorf("%s: %w", asset.URL, err)
		}
	}
	return writeExecutable(filepath.Join(binDir, commandWithExe(b.Command, runtime.GOOS)), data)
}

var errMCPNoBuild = errors.New("no release build for this platform")

// mcpMaxDownload caps a release download (the largest pinned asset is ~50 MB).
const mcpMaxDownload = 256 << 20

func (in *mcpInstaller) download(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := in.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, mcpMaxDownload+1))
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", url, err)
	}
	if len(data) > mcpMaxDownload {
		return nil, fmt.Errorf("download %s: larger than %d bytes", url, mcpMaxDownload)
	}
	return data, nil
}

func checkSHA256(data []byte, want string) error {
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, want)
	}
	return nil
}

// tarGzMember returns the regular file named member at the top of a .tar.gz.
func tarGzMember(data []byte, member string) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("%s not found in the archive", member)
		}
		if err != nil {
			return nil, err
		}
		if strings.TrimPrefix(h.Name, "./") != member || h.Typeflag != tar.TypeReg {
			continue
		}
		return io.ReadAll(io.LimitReader(tr, mcpMaxDownload))
	}
}

// writeExecutable writes data to path through a temporary file in the same
// folder, so a half-written binary never takes the command's name.
func writeExecutable(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, 0o755); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		_ = os.Remove(path) // Rename does not replace an existing file there
	}
	return os.Rename(name, path)
}

// mkdirShared creates a tools folder that every local account can read and
// nobody but ARTEX's own can change (on Windows the data directory's ACL, set
// by PrepareExecPrivilege, decides that instead).
func mkdirShared(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		return os.Chmod(dir, 0o755)
	}
	return nil
}

// installCommand runs an installer (pip, npm, playwright) with output captured.
// On Unix it runs under umask 022: once the privilege drop is set up ARTEX's
// own umask lets the executor group write new files, and the agent identity
// must not be able to change what ARTEX later runs.
func (in *mcpInstaller) installCommand(ctx context.Context, env []string, name string, args ...string) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, name, args...)
	} else {
		cmd = exec.CommandContext(ctx, "/bin/sh", append([]string{"-c", `umask 022 && exec "$@"`, "artex-mcp-install", name}, args...)...)
	}
	cmd.Dir = in.dir
	cmd.Env = append(os.Environ(), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", filepath.Base(name), strings.Join(args, " "), err, lastLines(out.String(), 6))
	}
	return nil
}

// lastLines keeps the end of an installer's output for an error message.
func lastLines(s string, n int) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.TrimSpace(strings.Join(lines, " | "))
	if len(out) > 600 {
		out = "…" + out[len(out)-600:]
	}
	return out
}

// pythonCandidates are the commands tried for a Python 3.10+ interpreter.
func pythonCandidates(goos string) [][]string {
	if goos == "windows" {
		return [][]string{{"py", "-3"}, {"python"}, {"python3"}}
	}
	return [][]string{{"python3"}, {"python"}}
}

// findPython returns a working Python 3.10+ command, or nil. On Windows the
// "python" app alias that only opens the Store fails the version check.
func findPython(ctx context.Context) []string {
	for _, c := range pythonCandidates(runtime.GOOS) {
		if _, err := exec.LookPath(c[0]); err != nil {
			continue
		}
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		out, err := exec.CommandContext(cctx, c[0], append(c[1:], "-c", "import sys; print(sys.version_info >= (3, 10))")...).Output()
		cancel()
		if err == nil && strings.TrimSpace(string(out)) == "True" {
			return c
		}
	}
	return nil
}

func (in *mcpInstaller) venvPython() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(in.dir, "py", "Scripts", "python.exe")
	}
	return filepath.Join(in.dir, "py", "bin", "python")
}

// ensureVenv creates <tools>/py with the Python found on PATH.
func (in *mcpInstaller) ensureVenv(ctx context.Context) error {
	if _, err := os.Stat(in.venvPython()); err == nil {
		return nil
	}
	py := findPython(ctx)
	if py == nil {
		return errMCPNoPython
	}
	if err := mkdirShared(in.dir); err != nil {
		return err
	}
	args := append(py[1:], "-m", "venv", filepath.Join(in.dir, "py"))
	if err := in.installCommand(ctx, nil, py[0], args...); err != nil {
		_ = os.RemoveAll(filepath.Join(in.dir, "py"))
		return fmt.Errorf("create a Python virtual environment (on Debian or Ubuntu install python3-venv): %w", err)
	}
	return nil
}

var (
	errMCPNoPython = errors.New("Python 3.10 or newer was not found on PATH; install it from https://www.python.org and restart ARTEX")
	errMCPNoNode   = errors.New("Node.js (npm) was not found on PATH; install Node.js 20 or newer from https://nodejs.org and restart ARTEX")
)

func (in *mcpInstaller) installPip(ctx context.Context, p mcpPipPackage) error {
	if err := in.ensureVenv(ctx); err != nil {
		return err
	}
	if err := in.installCommand(ctx, []string{"PIP_DISABLE_PIP_VERSION_CHECK=1"}, in.venvPython(), "-m", "pip", "install", "--no-input", p.Spec); err != nil {
		return err
	}
	return in.linkVenvCommand(p.Command)
}

// linkVenvCommand puts one console script of the venv into <tools>/bin. The
// venv's own bin folder stays off PATH: it also holds python, pip and the
// scripts of every dependency, which must not stand in for missing commands.
// A script finds its interpreter by absolute path, so a symlink (or on Windows
// a copy of the launcher .exe) runs the same as the original.
func (in *mcpInstaller) linkVenvCommand(command string) error {
	binDir := filepath.Join(in.dir, "bin")
	if err := mkdirShared(binDir); err != nil {
		return err
	}
	name := commandWithExe(command, runtime.GOOS)
	src := filepath.Join(in.dir, "py", venvBinDir(runtime.GOOS), name)
	dst := filepath.Join(binDir, name)
	if runtime.GOOS == "windows" {
		data, err := os.ReadFile(src)
		if err != nil {
			return err
		}
		return writeExecutable(dst, data)
	}
	if _, err := os.Stat(src); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return os.Symlink(filepath.Join("..", "py", venvBinDir(runtime.GOOS), name), dst)
}

// npmCommand returns how to run npm. On Windows npm is a .cmd wrapper, which
// os/exec cannot start without a command interpreter (and quoting through
// cmd.exe is fragile), so npm's own JavaScript entry point is run with node
// instead, the way the wrapper does.
func npmCommand() ([]string, error) {
	if runtime.GOOS == "windows" {
		node, err := exec.LookPath("node")
		if err != nil {
			return nil, errMCPNoNode
		}
		cli := filepath.Join(filepath.Dir(node), "node_modules", "npm", "bin", "npm-cli.js")
		if _, err := os.Stat(cli); err != nil {
			return nil, fmt.Errorf("npm was not found next to %s: %w", node, errMCPNoNode)
		}
		return []string{node, cli}, nil
	}
	npm, err := exec.LookPath("npm")
	if err != nil {
		return nil, errMCPNoNode
	}
	return []string{npm}, nil
}

func (in *mcpInstaller) installNpm(ctx context.Context, p mcpNpmPackage) error {
	npm, err := npmCommand()
	if err != nil {
		return err
	}
	prefix := filepath.Join(in.dir, "node")
	if err := mkdirShared(prefix); err != nil {
		return err
	}
	args := append(npm[1:], "install", "--prefix", prefix, "--no-audit", "--no-fund", p.Spec)
	if err := in.installCommand(ctx, nil, npm[0], args...); err != nil {
		return err
	}
	if p.PresetID == "playwright" {
		return in.installPlaywrightBrowser(ctx, prefix)
	}
	return nil
}

// installPlaywrightBrowser downloads the Chromium build the installed
// Playwright expects into <tools>/ms-playwright, unless Playwright is already
// pointed at browsers somewhere else.
func (in *mcpInstaller) installPlaywrightBrowser(ctx context.Context, prefix string) error {
	if os.Getenv("PLAYWRIGHT_BROWSERS_PATH") != "" {
		return nil
	}
	node, err := exec.LookPath("node")
	if err != nil {
		return errMCPNoNode
	}
	browsers := filepath.Join(in.dir, "ms-playwright")
	cli := filepath.Join(prefix, "node_modules", "playwright-core", "cli.js")
	_ = os.Remove(filepath.Join(browsers, playwrightDoneMarker))
	if err := in.installCommand(ctx, []string{"PLAYWRIGHT_BROWSERS_PATH=" + browsers}, node, cli, "install", "chromium"); err != nil {
		return fmt.Errorf("download Chromium for Playwright: %w", err)
	}
	if err := os.WriteFile(filepath.Join(browsers, playwrightDoneMarker), []byte("chromium\n"), 0o644); err != nil {
		return err
	}
	usePlaywrightBrowsers(in.dir)
	return nil
}

// playwrightDoneMarker is written into <tools>/ms-playwright once the browser
// download finished, so a download cut short is retried at the next start and
// never used.
const playwrightDoneMarker = ".artex-complete"

// playwrightComplete reports whether the Playwright ARTEX manages still needs
// its browser: true when playwright-mcp is not ARTEX's copy, when Playwright
// is pointed at browsers elsewhere, or when the download finished.
func (in *mcpInstaller) playwrightComplete() bool {
	own := filepath.Join(in.dir, "node", "node_modules", ".bin", browserMCPCommandName)
	if runtime.GOOS == "windows" {
		own += ".cmd"
	}
	if _, err := os.Stat(own); err != nil {
		return true
	}
	if os.Getenv("PLAYWRIGHT_BROWSERS_PATH") != "" && !in.usesOwnBrowsers() {
		return true
	}
	_, err := os.Stat(filepath.Join(in.dir, "ms-playwright", playwrightDoneMarker))
	return err == nil
}

func (in *mcpInstaller) usesOwnBrowsers() bool {
	return pathKey(os.Getenv("PLAYWRIGHT_BROWSERS_PATH")) == pathKey(filepath.Join(in.dir, "ms-playwright"))
}

// mcpAutoAddAgents are the built-in agents an automatically added security
// server is made visible to. The user can change this per agent at any time;
// ARTEX does it only once per server.
var mcpAutoAddAgents = []string{"pentest", "worker"}

func mcpAutoAddKey(id string) string { return "mcp_autoadd_v1_" + id }

// autoInstallMCPTools installs every Auto preset that is not on PATH yet, then
// adds the ones that can run. It runs in the startup goroutine, before the
// startup discovery, and never blocks the server.
func (s *Server) autoInstallMCPTools() {
	in := s.toolInstaller
	if in == nil || s.m.pg == nil {
		return
	}
	ctx := s.ctx
	presets := map[string]mcpPreset{}
	for _, p := range mcpPresets(runtime.GOOS) {
		presets[p.ID] = p
	}
	// complete, when set, says whether a command that is on PATH still needs
	// part of its install finished (Playwright's browser download).
	run := func(id, command string, install func() error, complete func() bool) {
		p, ok := presets[id]
		if !ok || !p.Auto || ctx.Err() != nil {
			return
		}
		if lookupMCPCommand(command, nil) && (complete == nil || complete()) {
			in.set(id, "installed", "")
		} else {
			in.set(id, "installing", "")
			log.Printf("[mcp] installing %s into %s", p.Title, in.dir)
			err := install()
			AddMCPToolsToPath(filepath.Dir(in.dir))
			switch {
			case err == nil && lookupMCPCommand(command, nil):
				in.set(id, "installed", "")
				log.Printf("[mcp] installed %s", p.Title)
			case err == nil:
				in.set(id, "failed", fmt.Sprintf("the install finished but %s is still not on PATH", command))
				return
			case errors.Is(err, errMCPNoBuild), errors.Is(err, errMCPNoPython), errors.Is(err, errMCPNoNode):
				in.set(id, "unavailable", err.Error())
				log.Printf("[mcp] %s not installed: %v", p.Title, err)
				return
			default:
				in.set(id, "failed", err.Error())
				log.Printf("[mcp] installing %s failed: %v", p.Title, err)
				return
			}
		}
		s.autoAddMCPPreset(p)
	}
	for _, b := range mcpReleaseBinaries {
		run(b.PresetID, b.Command, func() error { return in.installReleaseBinary(ctx, b) }, nil)
	}
	for _, p := range mcpPipPackages {
		run(p.PresetID, p.Command, func() error { return in.installPip(ctx, p) }, nil)
	}
	for _, p := range mcpNpmPackages {
		complete := func() bool { return true }
		if p.PresetID == "playwright" {
			complete = in.playwrightComplete
		}
		run(p.PresetID, p.Command, func() error { return in.installNpm(ctx, p) }, complete)
	}
}

// mcpMissingRequires returns the programs a preset needs that are not on PATH.
func mcpMissingRequires(p mcpPreset) []string {
	var miss []string
	for _, r := range p.Requires {
		if !lookupMCPCommand(r, nil) {
			miss = append(miss, r)
		}
	}
	return miss
}

// autoAddMCPPreset adds an installed Auto preset as an enabled row once. A row
// the user removed or changed later is left alone: the settings flag records
// that ARTEX already did it. The seeded browser row is enabled instead of
// added, if it is still the stock disabled row.
func (s *Server) autoAddMCPPreset(p mcpPreset) {
	pg := s.m.pg
	key := mcpAutoAddKey(p.ID)
	if v, ok, err := pg.GetSetting(key); err != nil || (ok && v != "") {
		return
	}
	if miss := mcpMissingRequires(p); len(miss) > 0 {
		s.toolInstaller.set(p.ID, "installed", fmt.Sprintf("needs %s on PATH before ARTEX adds it", strings.Join(miss, ", ")))
		return
	}
	rows, err := pg.ListMCP()
	if err != nil {
		log.Printf("[mcp] auto-add %s: %v", p.Name, err)
		return
	}
	for _, r := range rows {
		if r.Name != p.Name {
			continue
		}
		if p.ID == "playwright" && isStockBrowserRow(r) {
			r.Enabled = true
			var rowArgs []string
			_ = json.Unmarshal(r.Args, &rowArgs)
			if cmd, args, ok := s.toolInstaller.windowsNodeLaunch(mcpPreset{ID: p.ID, Args: rowArgs}); ok {
				r.Command = cmd
				r.Args, _ = json.Marshal(args) // keeps the proxy flags ARTEX manages
			}
			if _, err := pg.SaveMCP(r); err != nil {
				log.Printf("[mcp] enable %s: %v", r.Name, err)
				return
			}
			log.Printf("[mcp] enabled %s now that it is installed", r.Name)
		}
		_ = pg.SetSetting(key, "done")
		return
	}
	if cmd, a, ok := s.toolInstaller.windowsNodeLaunch(p); ok {
		p.Command, p.Args = cmd, a
	}
	args, _ := json.Marshal(p.Args)
	env, _ := json.Marshal(p.Env)
	m := &db.MCPServer{Name: p.Name, Transport: p.Transport, Command: p.Command, Args: args, Env: env, Enabled: true}
	id, err := pg.SaveMCP(m)
	if err != nil {
		log.Printf("[mcp] auto-add %s: %v", p.Name, err)
		return
	}
	if err := pg.GrantMCPToAgentKeys(id, mcpAutoAddAgents); err != nil {
		log.Printf("[mcp] auto-add %s: agent visibility: %v", p.Name, err)
	}
	_ = pg.SetSetting(key, "done")
	log.Printf("[mcp] added %s (installed by ARTEX or found on PATH); agents %s can use it", p.Name, strings.Join(mcpAutoAddAgents, ", "))
}

// isStockBrowserRow reports whether the browser row is still exactly what the
// database seeded (db/db.go): disabled, stdio, playwright-mcp with the seeded
// arguments and no environment. The proxy flags and CA variable ARTEX itself
// keeps in sync with traffic capture (Manager.syncBrowserMCPProxy) do not
// count as changes. An operator's own configuration is left alone.
func isStockBrowserRow(r *db.MCPServer) bool {
	if r.Enabled || r.Transport != "stdio" || r.Command != browserMCPCommandName || r.URL != "" {
		return false
	}
	var args []string
	if json.Unmarshal(r.Args, &args) != nil || strings.Join(stripProxyArgs(args), "\x00") != strings.Join([]string{"--headless", "--browser", "chromium"}, "\x00") {
		return false
	}
	env := jsonStrMap(r.Env)
	delete(env, "NODE_EXTRA_CA_CERTS")
	return len(env) == 0
}

// windowsNodeLaunch returns how to start an npm-installed server on Windows
// without its .cmd wrapper: node with the package's JavaScript entry point.
// npm puts only a batch wrapper on PATH there, and ARTEX starts stdio servers
// directly (and through the agent account's launcher), not through cmd.exe.
// ok is false on other systems and for a copy ARTEX did not install.
func (in *mcpInstaller) windowsNodeLaunch(p mcpPreset) (string, []string, bool) {
	return in.nodeLaunch(p, runtime.GOOS)
}

func (in *mcpInstaller) nodeLaunch(p mcpPreset, goos string) (string, []string, bool) {
	if goos != "windows" || in == nil {
		return "", nil, false
	}
	for _, n := range mcpNpmPackages {
		if n.PresetID != p.ID || n.Entry == "" {
			continue
		}
		entry := filepath.Join(in.dir, "node", "node_modules", filepath.FromSlash(n.Entry))
		if _, err := os.Stat(entry); err != nil {
			return "", nil, false
		}
		return "node", append([]string{entry}, p.Args...), true
	}
	return "", nil, false
}
