package server

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestMCPAutoInstallCatalog(t *testing.T) {
	presets := map[string]mcpPreset{}
	for _, p := range mcpPresets(runtime.GOOS) {
		presets[p.ID] = p
	}
	installers := map[string]string{} // preset id -> command
	sha := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for _, b := range mcpReleaseBinaries {
		installers[b.PresetID] = b.Command
		if len(b.Assets) == 0 {
			t.Fatalf("%s has no release assets", b.PresetID)
		}
		for plat, a := range b.Assets {
			if !sha.MatchString(a.SHA256) {
				t.Fatalf("%s %s: bad sha256 %q", b.PresetID, plat, a.SHA256)
			}
			if !strings.HasPrefix(a.URL, "https://github.com/") || !strings.Contains(a.URL, "/v"+b.Version+"/") {
				t.Fatalf("%s %s: url %q is not a pinned GitHub release of v%s", b.PresetID, plat, a.URL, b.Version)
			}
			goos, goarch, _ := strings.Cut(plat, "/")
			if !strings.Contains(a.URL, goos) || !strings.Contains(a.URL, goarch) {
				t.Fatalf("%s %s: url %q is for another platform", b.PresetID, plat, a.URL)
			}
			if a.Archive != "" && a.Member == "" {
				t.Fatalf("%s %s: archive without a member", b.PresetID, plat)
			}
		}
	}
	for _, p := range mcpPipPackages {
		installers[p.PresetID] = p.Command
		if !strings.Contains(p.Spec, "==") {
			t.Fatalf("pip package %s is not pinned: %q", p.PresetID, p.Spec)
		}
	}
	for _, p := range mcpNpmPackages {
		installers[p.PresetID] = p.Command
		if strings.LastIndex(p.Spec, "@") <= 0 {
			t.Fatalf("npm package %s is not pinned: %q", p.PresetID, p.Spec)
		}
	}
	for id, cmd := range installers {
		p, ok := presets[id]
		if !ok {
			t.Fatalf("installer for unknown preset %s", id)
		}
		if !p.Auto || p.Command != cmd {
			t.Fatalf("preset %s: auto=%v command=%q, installer installs %q", id, p.Auto, p.Command, cmd)
		}
	}
	for _, p := range presets {
		if !p.Auto {
			continue
		}
		if _, ok := installers[p.ID]; !ok {
			t.Fatalf("auto preset %s has no installer", p.ID)
		}
		if p.Cost != "free" || p.Transport != "stdio" || len(p.RequiredEnv) > 0 || len(p.Placeholders) > 0 || p.Setup != "" {
			t.Fatalf("auto preset %s needs a key, a path or setup; ARTEX must not add it on its own", p.ID)
		}
	}
}

func TestMCPAutoInstallOptOut(t *testing.T) {
	for v, want := range map[string]bool{"": true, "on": true, "off": false, "0": false, "False": false, " no ": false} {
		t.Setenv(envMCPAutoInstall, v)
		if got := MCPAutoInstallEnabled(); got != want {
			t.Fatalf("%s=%q: enabled=%v, want %v", envMCPAutoInstall, v, got, want)
		}
		s := &Server{}
		WithMCPAutoInstall(t.TempDir())(s)
		if (s.toolInstaller != nil) != want {
			t.Fatalf("%s=%q: installer set=%v", envMCPAutoInstall, v, s.toolInstaller != nil)
		}
	}
}

func TestAppendPathDirs(t *testing.T) {
	sep := string(os.PathListSeparator)
	a, b, c := filepath.Join("x", "a"), filepath.Join("x", "b"), filepath.Join("x", "c")
	if got := appendPathDirs(a+sep+b, []string{b, c, c}); got != a+sep+b+sep+c {
		t.Fatalf("appendPathDirs = %q", got)
	}
	if got := appendPathDirs("", []string{c}); got != c {
		t.Fatalf("appendPathDirs on empty PATH = %q", got)
	}
}

func TestMCPToolsDirIsAbsolute(t *testing.T) {
	if d := MCPToolsDir("data"); !filepath.IsAbs(d) || filepath.Base(d) != mcpToolsDirName {
		t.Fatalf("MCPToolsDir = %q", d)
	}
}

func tarGz(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(zw)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sum(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func TestInstallReleaseBinary(t *testing.T) {
	bin := []byte("#!/bin/sh\necho fake\n")
	archive := tarGz(t, map[string][]byte{"LICENSE": []byte("MIT"), "./" + commandWithExe("fake-mcp", runtime.GOOS): bin})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/raw":
			w.Write(bin)
		case "/tgz":
			w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	plat := runtime.GOOS + "/" + runtime.GOARCH
	cases := []struct {
		name  string
		asset mcpReleaseAsset
		ok    bool
	}{
		{"raw", mcpReleaseAsset{URL: srv.URL + "/raw", SHA256: sum(bin)}, true},
		{"tar.gz", mcpReleaseAsset{URL: srv.URL + "/tgz", SHA256: sum(archive), Archive: "tar.gz", Member: commandWithExe("fake-mcp", runtime.GOOS)}, true},
		{"bad checksum", mcpReleaseAsset{URL: srv.URL + "/raw", SHA256: sum([]byte("other"))}, false},
		{"missing member", mcpReleaseAsset{URL: srv.URL + "/tgz", SHA256: sum(archive), Archive: "tar.gz", Member: "nope"}, false},
		{"http error", mcpReleaseAsset{URL: srv.URL + "/404", SHA256: sum(bin)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := newMCPInstaller(t.TempDir())
			err := in.installReleaseBinary(context.Background(), mcpReleaseBinary{PresetID: "fake", Command: "fake-mcp", Assets: map[string]mcpReleaseAsset{plat: tc.asset}})
			path := filepath.Join(in.dir, "bin", commandWithExe("fake-mcp", runtime.GOOS))
			got, rerr := os.ReadFile(path)
			if tc.ok {
				if err != nil || rerr != nil || !bytes.Equal(got, bin) {
					t.Fatalf("install: %v / %v / %q", err, rerr, got)
				}
				if runtime.GOOS != "windows" {
					if !mcpIsExecutable(path) {
						t.Fatal("installed binary is not executable")
					}
					if fi, _ := os.Stat(filepath.Dir(path)); fi.Mode().Perm()&0o022 != 0 {
						t.Fatalf("bin folder mode %v is writable by others", fi.Mode().Perm())
					}
				}
				if !lookupMCPCommand("fake-mcp", map[string]string{"PATH": filepath.Dir(path)}) {
					t.Fatal("installed command not found on the tools PATH")
				}
				return
			}
			if err == nil || rerr == nil {
				t.Fatalf("want a failed install and no file: %v / %v", err, rerr)
			}
			entries, _ := os.ReadDir(filepath.Dir(path))
			if len(entries) != 0 {
				t.Fatalf("a failed install left files: %v", entries)
			}
		})
	}
	in := newMCPInstaller(t.TempDir())
	if err := in.installReleaseBinary(context.Background(), mcpReleaseBinary{Command: "x", Assets: map[string]mcpReleaseAsset{"plan9/mips": {}}}); err != errMCPNoBuild {
		t.Fatalf("no build for this platform: %v", err)
	}
}

func TestUsePlaywrightBrowsersOnlyWhenDownloaded(t *testing.T) {
	tools := t.TempDir()
	t.Setenv("PLAYWRIGHT_BROWSERS_PATH", "")
	usePlaywrightBrowsers(tools)
	if v := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); v != "" {
		t.Fatalf("set to %q with no browser downloaded", v)
	}
	if err := os.Mkdir(filepath.Join(tools, "ms-playwright"), 0o755); err != nil {
		t.Fatal(err)
	}
	usePlaywrightBrowsers(tools)
	if v := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); v != "" {
		t.Fatalf("set to %q for a download that did not finish", v)
	}
	if err := os.WriteFile(filepath.Join(tools, "ms-playwright", playwrightDoneMarker), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	usePlaywrightBrowsers(tools)
	if v := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); v != filepath.Join(tools, "ms-playwright") {
		t.Fatalf("PLAYWRIGHT_BROWSERS_PATH = %q", v)
	}
	t.Setenv("PLAYWRIGHT_BROWSERS_PATH", "/elsewhere")
	usePlaywrightBrowsers(tools)
	if v := os.Getenv("PLAYWRIGHT_BROWSERS_PATH"); v != "/elsewhere" {
		t.Fatalf("an existing location was replaced: %q", v)
	}
}

func TestAutoAddMCPPreset(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	if m.pg == nil {
		db.SkipNoPG(t)
	}
	defer m.Close()
	s := &Server{m: m, toolInstaller: newMCPInstaller(t.TempDir())}
	pg := m.pg
	p := mcpPreset{ID: "t-autoadd", Name: "t-autoadd", Transport: "stdio", Command: "t-autoadd-cmd", Args: []string{"mcp"}, Env: map[string]string{}, Auto: true}
	cleanup := func() {
		pg.Exec(`DELETE FROM settings WHERE key=$1`, mcpAutoAddKey(p.ID))
		pg.Exec(`DELETE FROM agent_visibility WHERE resource_kind='mcp' AND resource_id IN (SELECT id FROM mcp_servers WHERE name=$1)`, p.Name)
		pg.Exec(`DELETE FROM mcp_servers WHERE name=$1`, p.Name)
	}
	cleanup()
	defer cleanup()
	find := func() *db.MCPServer {
		rows, err := pg.ListMCP()
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.Name == p.Name {
				return r
			}
		}
		return nil
	}

	// A program it needs is missing: nothing is added, and it is tried again later.
	p.Requires = []string{"t-autoadd-missing-prog"}
	s.autoAddMCPPreset(p)
	if find() != nil {
		t.Fatal("added although a required program is missing")
	}
	if st, _ := s.toolInstaller.state(p.ID); !strings.Contains(st.Message, "t-autoadd-missing-prog") {
		t.Fatalf("state does not name the missing program: %+v", st)
	}

	p.Requires = nil
	s.autoAddMCPPreset(p)
	r := find()
	if r == nil || !r.Enabled || r.Command != p.Command {
		t.Fatalf("auto-added row = %+v", r)
	}
	var n int
	if err := pg.QueryRow(`SELECT count(*) FROM agent_visibility v JOIN agents a ON a.id=v.agent_id WHERE v.resource_kind='mcp' AND v.resource_id=$1 AND v.enabled AND a.key = ANY($2)`, r.ID, mcpAutoAddAgents).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(mcpAutoAddAgents) {
		t.Fatalf("visible to %d of the %d default agents", n, len(mcpAutoAddAgents))
	}

	// The user removes it: ARTEX does not add it back.
	if err := pg.DeleteMCP(r.ID); err != nil {
		t.Fatal(err)
	}
	s.autoAddMCPPreset(p)
	if find() != nil {
		t.Fatal("a removed server was added again")
	}
}

func TestPlaywrightCompleteRetriesACutDownload(t *testing.T) {
	t.Setenv("PLAYWRIGHT_BROWSERS_PATH", "")
	in := newMCPInstaller(t.TempDir())
	if !in.playwrightComplete() {
		t.Fatal("a playwright-mcp that is not ARTEX's copy must count as complete")
	}
	shim := filepath.Join(in.dir, "node", "node_modules", ".bin", browserMCPCommandName)
	if runtime.GOOS == "windows" {
		shim += ".cmd"
	}
	if err := os.MkdirAll(filepath.Dir(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(shim, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if in.playwrightComplete() {
		t.Fatal("ARTEX's Playwright without a finished browser download counted as complete")
	}
	if err := os.MkdirAll(filepath.Join(in.dir, "ms-playwright"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in.dir, "ms-playwright", playwrightDoneMarker), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !in.playwrightComplete() {
		t.Fatal("a finished download counted as incomplete")
	}
}

func TestIsStockBrowserRow(t *testing.T) {
	stock := func() *db.MCPServer {
		return &db.MCPServer{Name: "browser", Transport: "stdio", Command: browserMCPCommandName,
			Args: []byte(`["--headless","--browser","chromium"]`), Env: []byte(`{}`)}
	}
	if !isStockBrowserRow(stock()) {
		t.Fatal("the seeded row is not recognised")
	}
	proxied := stock()
	proxied.Args = []byte(`["--headless","--browser","chromium","--proxy-server","http://127.0.0.1:8788"]`)
	proxied.Env = []byte(`{"NODE_EXTRA_CA_CERTS":"/data/traffic/_ca/mitmproxy-ca-cert.pem"}`)
	if !isStockBrowserRow(proxied) {
		t.Fatal("the capture proxy ARTEX attaches made the seeded row look customised")
	}
	for name, change := range map[string]func(*db.MCPServer){
		"enabled":   func(r *db.MCPServer) { r.Enabled = true },
		"args":      func(r *db.MCPServer) { r.Args = []byte(`["--headless","--browser","firefox"]`) },
		"env":       func(r *db.MCPServer) { r.Env = []byte(`{"DEBUG":"1"}`) },
		"command":   func(r *db.MCPServer) { r.Command = "npx" },
		"transport": func(r *db.MCPServer) { r.Transport = "http"; r.URL = "http://127.0.0.1:1/mcp" },
	} {
		r := stock()
		change(r)
		if isStockBrowserRow(r) {
			t.Fatalf("a row with changed %s counted as stock", name)
		}
	}
}

func TestNodeLaunchOnWindows(t *testing.T) {
	in := newMCPInstaller(t.TempDir())
	var p mcpPreset
	for _, q := range mcpPresets("windows") {
		if q.ID == "playwright" {
			p = q
		}
	}
	if _, _, ok := in.nodeLaunch(p, "windows"); ok {
		t.Fatal("node launch chosen for a Playwright ARTEX did not install")
	}
	entry := filepath.Join(in.dir, "node", "node_modules", "@playwright", "mcp", "cli.js")
	if err := os.MkdirAll(filepath.Dir(entry), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(entry, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd, args, ok := in.nodeLaunch(p, "windows")
	if !ok || cmd != "node" || len(args) != len(p.Args)+1 || args[0] != entry || args[1] != p.Args[0] {
		t.Fatalf("nodeLaunch = %q %q %v", cmd, args, ok)
	}
	if _, _, ok := in.nodeLaunch(p, "linux"); ok {
		t.Fatal("node launch chosen outside Windows")
	}
}
