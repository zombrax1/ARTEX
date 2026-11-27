package server

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Autumn-27/artex/db"
)

// mcpPreset is a ready-made MCP server entry the UI can add in one step. The
// catalog only holds free servers with a verified package, transport and
// license. Nothing is added or enabled on its own: the user picks a preset,
// fills in what it needs (an API key, a path) and saves it as a normal row.
type mcpPreset struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"` // row name when added
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Category    string            `json:"category"`
	License     string            `json:"license"`
	Homepage    string            `json:"homepage"`
	Transport   string            `json:"transport"`
	Command     string            `json:"command,omitempty"`
	Args        []string          `json:"args"`
	Env         map[string]string `json:"env"`
	URL         string            `json:"url,omitempty"`
	// RequiredEnv must be filled in before the row can be saved (API keys).
	RequiredEnv []string `json:"required_env,omitempty"`
	// Placeholders are args the user must replace (for example a path).
	Placeholders []string `json:"placeholders,omitempty"`
	// Setup is a short note on what has to run first (Burp, a backend server).
	Setup   string `json:"setup,omitempty"`
	Install string `json:"install,omitempty"`
	// Cost: "free" (no account, no key), "free_key" (a free account's API key
	// is enough) or "paid" (needs a paid product or plan for real use).
	Cost string `json:"cost"`
	// CostNote says what a free key or plan covers, when Cost is not "free".
	CostNote string `json:"cost_note,omitempty"`
}

// mcpPresetStatus is a preset plus what this machine has for it.
type mcpPresetStatus struct {
	mcpPreset
	// Installed: the stdio command is on PATH. nil for http presets.
	Installed *bool `json:"installed,omitempty"`
	// AddedID is the id of an existing row with the preset's name, or 0.
	AddedID int64 `json:"added_id,omitempty"`
}

func pythonCommand(goos string) string {
	if goos == "windows" {
		return "python"
	}
	return "python3"
}

// mcpPresets returns the catalog for one OS. goos only changes command names
// that differ between systems (python vs python3) and the install hints.
func mcpPresets(goos string) []mcpPreset {
	py := pythonCommand(goos)
	return []mcpPreset{
		{
			ID:          "playwright",
			Cost:        "free",
			Name:        "browser",
			Title:       "Playwright (browser)",
			Description: "Drives a real Chromium browser: open pages, click, fill forms, read the page and take screenshots.",
			Category:    "Web",
			License:     "Apache-2.0",
			Homepage:    "https://github.com/microsoft/playwright-mcp",
			Transport:   "stdio",
			Command:     browserMCPCommandName,
			Args:        []string{"--headless", "--browser", "chromium"},
			Env:         map[string]string{},
			Install:     mcpInstallHint(browserMCPCommandName, goos),
		},
		{
			ID:          "semgrep",
			Cost:        "free",
			Name:        "semgrep",
			Title:       "Semgrep",
			Description: "Static analysis: scans source code for vulnerabilities and insecure patterns with Semgrep's open rules. No account needed for local scans.",
			Category:    "Code",
			License:     "LGPL-2.1",
			Homepage:    "https://github.com/semgrep/semgrep",
			Transport:   "stdio",
			Command:     "semgrep",
			Args:        []string{"mcp"},
			Env:         map[string]string{},
			Install:     mcpInstallHint("semgrep", goos),
		},
		{
			ID:          "osv-scanner",
			Cost:        "free",
			Name:        "osv-scanner",
			Title:       "OSV-Scanner",
			Description: "Google's dependency scanner: finds known vulnerabilities in a project's lockfiles and manifests using the free OSV.dev database, and explains each one. No account or key.",
			Category:    "Code",
			License:     "Apache-2.0",
			Homepage:    "https://github.com/google/osv-scanner",
			Transport:   "stdio",
			Command:     "osv-scanner",
			Args:        []string{"experimental-mcp"},
			Env:         map[string]string{},
			Install:     mcpInstallHint("osv-scanner", goos),
		},
		{
			ID:          "trivy",
			Cost:        "free",
			Name:        "trivy",
			Title:       "Trivy",
			Description: "Aqua Security's open-source scanner: vulnerabilities, misconfigurations and secrets in folders, container images and remote repositories. No account or key.",
			Category:    "Code",
			License:     "MIT",
			Homepage:    "https://github.com/aquasecurity/trivy-mcp",
			Transport:   "stdio",
			Command:     "trivy",
			Args:        []string{"mcp"},
			Env:         map[string]string{},
			Setup:       "The MCP server is a Trivy plugin: after installing Trivy, run `trivy plugin install mcp` once.",
			Install:     mcpInstallHint("trivy", goos),
		},
		{
			ID:          "nmap",
			Cost:        "free",
			Name:        "nmap",
			Title:       "Nmap",
			Description: "Port and service scanning through python-nmap: host discovery, port scans, version detection and XML parsing. Needs nmap itself installed. Scan only networks you are allowed to test.",
			Category:    "Recon",
			License:     "MIT",
			Homepage:    "https://github.com/daedalus/mcp-server-nmap",
			Transport:   "stdio",
			Command:     "mcp-server-nmap",
			Args:        []string{},
			Env:         map[string]string{},
			Install:     mcpInstallHint("mcp-server-nmap", goos),
		},
		{
			ID:          "virustotal",
			Cost:        "free_key",
			CostNote:    "The free public API key allows 4 lookups a minute and 500 a day.",
			Name:        "virustotal",
			Title:       "VirusTotal",
			Description: "Looks up file hashes, URLs, domains and IPs in VirusTotal. Needs a free VirusTotal API key.",
			Category:    "Threat intel",
			License:     "MIT",
			Homepage:    "https://github.com/BurtTheCoder/mcp-virustotal",
			Transport:   "stdio",
			Command:     "npx",
			Args:        []string{"-y", "@burtthecoder/mcp-virustotal"},
			Env:         map[string]string{"VIRUSTOTAL_API_KEY": ""},
			RequiredEnv: []string{"VIRUSTOTAL_API_KEY"},
			Install:     mcpInstallHint("npx", goos),
		},
		{
			ID:          "shodan",
			Cost:        "free_key",
			CostNote:    "A free account key covers host lookups; search filters and higher limits need a paid membership.",
			Name:        "shodan",
			Title:       "Shodan",
			Description: "Queries Shodan for exposed hosts, open ports, banners, DNS and CVEs. Needs a Shodan API key.",
			Category:    "Threat intel",
			License:     "MIT",
			Homepage:    "https://github.com/BurtTheCoder/mcp-shodan",
			Transport:   "stdio",
			Command:     "npx",
			Args:        []string{"-y", "@burtthecoder/mcp-shodan"},
			Env:         map[string]string{"SHODAN_API_KEY": ""},
			RequiredEnv: []string{"SHODAN_API_KEY"},
			Install:     mcpInstallHint("npx", goos),
		},
		{
			ID:           "hexstrike",
			Cost:         "free",
			Name:         "hexstrike",
			Title:        "HexStrike AI",
			Description:  "Wraps many scanners (nmap, nuclei, ffuf, sqlmap and more) as MCP tools. Each wrapped tool must be installed on this machine; most target Linux.",
			Category:     "Recon",
			License:      "MIT",
			Homepage:     "https://github.com/0x4m4/hexstrike-ai",
			Transport:    "stdio",
			Command:      py,
			Args:         []string{"/path/to/hexstrike-ai/hexstrike_mcp.py", "--server", "http://127.0.0.1:8888"},
			Env:          map[string]string{},
			Placeholders: []string{"/path/to/hexstrike-ai/hexstrike_mcp.py"},
			Setup:        "Clone the repository, install its requirements, and start its backend with `" + py + " hexstrike_server.py` before ARTEX connects. Replace the path in the arguments with your copy of hexstrike_mcp.py.",
			Install:      "git clone https://github.com/0x4m4/hexstrike-ai && cd hexstrike-ai && " + py + " -m pip install -r requirements.txt",
		},
		{
			ID:          "burp",
			Cost:        "free",
			CostNote:    "Works with the free Community Edition; scanner tools need Burp Suite Professional.",
			Name:        "burp",
			Title:       "Burp Suite",
			Description: "Connects to a running Burp Suite through PortSwigger's MCP Server extension (proxy history, Repeater, scanner where available).",
			Category:    "Web",
			License:     "GPL-3.0",
			Homepage:    "https://github.com/PortSwigger/mcp-server",
			Transport:   "http",
			URL:         "http://127.0.0.1:9876/mcp",
			Args:        []string{},
			Env:         map[string]string{},
			Setup:       "Install the MCP Server extension in Burp Suite (BApp Store or a build of the repository) and keep Burp running with it enabled. The default address is http://127.0.0.1:9876.",
		},
	}
}

// browserMCPCommandName is the seeded browser row's binary (db/browser_mcp.go).
const browserMCPCommandName = "playwright-mcp"

// mcpInstallHint returns how to install a known stdio command, or "".
func mcpInstallHint(command, goos string) string {
	// Take the last path element for either separator, so a Windows path
	// stored in the row still matches when checked anywhere.
	base := strings.ToLower(command[strings.LastIndexAny(command, `/\`)+1:])
	if i := strings.LastIndexByte(base, '.'); i > 0 {
		base = base[:i]
	}
	switch base {
	case "playwright-mcp":
		return "npm install -g @playwright/mcp (needs Node.js 20+). If Chromium is missing, run: npx playwright install chromium"
	case "semgrep":
		switch goos {
		case "darwin":
			return "brew install semgrep (or: python3 -m pip install semgrep)"
		case "windows":
			return "python -m pip install semgrep (or: pipx install semgrep)"
		}
		return "python3 -m pip install semgrep (or: pipx install semgrep)"
	case "osv-scanner":
		switch goos {
		case "darwin":
			return "brew install osv-scanner (or: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)"
		case "windows":
			return "download osv-scanner_windows_amd64.exe from https://github.com/google/osv-scanner/releases, rename it to osv-scanner.exe and put it on PATH (or: go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest)"
		}
		return "go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest (or a release binary from https://github.com/google/osv-scanner/releases)"
	case "trivy":
		switch goos {
		case "darwin":
			return "brew install trivy, then: trivy plugin install mcp"
		case "windows":
			return "download Trivy from https://github.com/aquasecurity/trivy/releases and put trivy.exe on PATH, then: trivy plugin install mcp"
		}
		return "install Trivy (https://trivy.dev/latest/getting-started/installation/), then: trivy plugin install mcp"
	case "mcp-server-nmap":
		nmap := "install nmap from https://nmap.org/download"
		if goos == "darwin" {
			nmap = "brew install nmap"
		}
		return "pipx install mcp-server-nmap (or: " + pythonCommand(goos) + " -m pip install mcp-server-nmap), and " + nmap
	case "npx", "npm", "node":
		return "install Node.js 20 or newer from https://nodejs.org, then restart ARTEX so it sees the new PATH"
	case "uvx", "uv":
		return "install uv from https://docs.astral.sh/uv/"
	case "python", "python3", "py":
		return "install Python 3 from https://www.python.org and make sure it is on PATH"
	case "java":
		return "install a Java runtime (Burp ships one) and make sure java is on PATH"
	}
	return ""
}

// errMCPCommandMissing marks a stdio server whose command is not installed.
var errMCPCommandMissing = errors.New("command not found")

// checkMCPCommand reports a clear, actionable error when a stdio command is not
// installed, so a missing binary fails at once with an install hint instead of
// a process start that errors (or hangs) on every agent run. env is the row's
// configured environment: the server starts the command with it (directly, or
// through the privilege-drop shim, which resolves the command on the same
// environment), so a PATH (and on Windows PATHEXT) set there is searched as
// well as ARTEX's own.
func checkMCPCommand(command string, env map[string]string) error {
	if command == "" {
		return nil
	}
	if lookupMCPCommand(command, env) {
		return nil
	}
	msg := fmt.Sprintf("%q is not installed or not on PATH", command)
	if hint := mcpInstallHint(command, runtime.GOOS); hint != "" {
		msg += "; install: " + hint
	}
	return fmt.Errorf("%w: %s", errMCPCommandMissing, msg)
}

// envLookup returns a variable of env, matching the name without regard to
// case on Windows as the OS does.
func envLookup(env map[string]string, name string) (string, bool) {
	if v, ok := env[name]; ok {
		return v, true
	}
	if runtime.GOOS == "windows" {
		for k, v := range env {
			if strings.EqualFold(k, name) {
				return v, true
			}
		}
	}
	return "", false
}

func lookupMCPCommand(command string, env map[string]string) bool {
	if filepath.IsAbs(command) || strings.ContainsAny(command, `/\`) {
		// exec.LookPath checks a path as given (adding PATHEXT on Windows).
		if _, err := exec.LookPath(command); err == nil {
			return true
		}
		_, err := os.Stat(command)
		return err == nil
	}
	// Without the privilege drop the command is resolved on ARTEX's own PATH;
	// with it, the shim resolves it on the row's PATH when one is set. Accept
	// either, so the check never rejects a command that would start.
	if _, err := exec.LookPath(command); err == nil {
		return true
	}
	path, ok := envLookup(env, "PATH")
	if !ok {
		return false
	}
	var exts []string
	if runtime.GOOS == "windows" {
		pathext, ok := envLookup(env, "PATHEXT")
		if !ok {
			pathext = os.Getenv("PATHEXT")
		}
		if pathext == "" {
			pathext = ".com;.exe;.bat;.cmd"
		}
		exts = append([]string{""}, strings.Split(pathext, ";")...)
	} else {
		exts = []string{""}
	}
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			dir = "."
		}
		for _, ext := range exts {
			if mcpIsExecutable(filepath.Join(dir, command+ext)) {
				return true
			}
		}
	}
	return false
}

func mcpIsExecutable(p string) bool {
	fi, err := os.Stat(p)
	if err != nil || fi.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return fi.Mode().Perm()&0o111 != 0
}

func (s *Server) presetStatuses() ([]mcpPresetStatus, error) {
	var rows []*db.MCPServer
	if pg := s.m.pg; pg != nil {
		var err error
		if rows, err = pg.ListMCP(); err != nil {
			return nil, err
		}
	}
	byName := map[string]int64{}
	for _, r := range rows {
		byName[r.Name] = r.ID
	}
	presets := mcpPresets(runtime.GOOS)
	out := make([]mcpPresetStatus, 0, len(presets))
	for _, p := range presets {
		st := mcpPresetStatus{mcpPreset: p, AddedID: byName[p.Name]}
		if p.Transport == "stdio" {
			ok := checkMCPCommand(p.Command, nil) == nil
			st.Installed = &ok
		}
		out = append(out, st)
	}
	return out, nil
}

// pgListMCPPresets serves the preset catalog with install and added status.
func (s *Server) pgListMCPPresets(w http.ResponseWriter, r *http.Request) {
	if s.pg(w) == nil {
		return
	}
	out, err := s.presetStatuses()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"presets": out})
}

// checkEnabledMCPCommandsOnStartup marks every enabled stdio server whose
// command is missing as down, with the install hint, so the MCP page shows why
// right after ARTEX starts instead of after the first failed agent run.
func (s *Server) checkEnabledMCPCommandsOnStartup(servers []*db.MCPServer) {
	for _, m := range servers {
		if !m.Enabled || m.Transport != "stdio" {
			continue
		}
		if err := checkMCPCommand(m.Command, jsonStrMap(m.Env)); err != nil {
			_ = s.m.pg.UpdateMCPHealth(m.ID, false, err.Error())
		}
	}
}
