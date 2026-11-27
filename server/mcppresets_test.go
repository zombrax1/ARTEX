package server

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestMCPPresetsCatalogIsConsistent(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		ids, names := map[string]bool{}, map[string]bool{}
		for _, p := range mcpPresets(goos) {
			if p.ID == "" || p.Name == "" || p.Title == "" || p.License == "" || p.Homepage == "" {
				t.Fatalf("%s: preset %+v is missing metadata", goos, p)
			}
			if ids[p.ID] || names[p.Name] {
				t.Fatalf("%s: duplicate preset id or name %q/%q", goos, p.ID, p.Name)
			}
			ids[p.ID], names[p.Name] = true, true
			switch p.Transport {
			case "stdio":
				if p.Command == "" || p.Install == "" {
					t.Fatalf("%s: stdio preset %s needs a command and an install hint", goos, p.ID)
				}
			case "http", "sse":
				if p.URL == "" {
					t.Fatalf("%s: remote preset %s needs a URL", goos, p.ID)
				}
			default:
				t.Fatalf("%s: preset %s has transport %q", goos, p.ID, p.Transport)
			}
			for _, k := range p.RequiredEnv {
				v, ok := p.Env[k]
				if !ok {
					t.Fatalf("%s: preset %s requires %s but does not list it in env", goos, p.ID, k)
				}
				if v != "" {
					t.Fatalf("%s: preset %s ships a value for %s; keys must be left for the user", goos, p.ID, k)
				}
			}
			for _, ph := range p.Placeholders {
				found := false
				for _, a := range p.Args {
					found = found || a == ph
				}
				if !found {
					t.Fatalf("%s: preset %s placeholder %q is not in its args", goos, p.ID, ph)
				}
			}
		}
		if !names["browser"] {
			t.Fatalf("%s: the Playwright preset must reuse the seeded browser row name", goos)
		}
	}
}

func TestMCPPresetPythonCommandPerOS(t *testing.T) {
	find := func(goos string) mcpPreset {
		for _, p := range mcpPresets(goos) {
			if p.ID == "hexstrike" {
				return p
			}
		}
		t.Fatal("hexstrike preset missing")
		return mcpPreset{}
	}
	if got := find("windows").Command; got != "python" {
		t.Fatalf("windows python command = %q", got)
	}
	if got := find("linux").Command; got != "python3" {
		t.Fatalf("linux python command = %q", got)
	}
}

func TestMCPInstallHintMatchesPathsAndExtensions(t *testing.T) {
	for _, cmd := range []string{"semgrep", "/usr/local/bin/semgrep", `C:\Tools\semgrep.exe`, "SEMGREP.EXE"} {
		if !strings.Contains(mcpInstallHint(cmd, "windows"), "pip install semgrep") {
			t.Fatalf("no semgrep hint for %q", cmd)
		}
	}
	if h := mcpInstallHint("npx.cmd", "windows"); !strings.Contains(h, "Node.js") {
		t.Fatalf("npx.cmd hint = %q", h)
	}
	if h := mcpInstallHint("some-unknown-tool", "linux"); h != "" {
		t.Fatalf("unknown command hint = %q", h)
	}
}

func TestCheckMCPCommand(t *testing.T) {
	if err := checkMCPCommand("", nil); err != nil {
		t.Fatalf("empty command: %v", err)
	}
	err := checkMCPCommand("semgrep-definitely-not-installed-artex", nil)
	if !errors.Is(err, errMCPCommandMissing) {
		t.Fatalf("missing command err = %v", err)
	}
	if err := checkMCPCommand("unknown-tool-not-here-artex", nil); err == nil || strings.Contains(err.Error(), "install:") {
		t.Fatalf("unknown missing command should fail without a hint: %v", err)
	}
	missingPath := filepath.Join(t.TempDir(), "nope", "semgrep")
	err = checkMCPCommand(missingPath, nil)
	if !errors.Is(err, errMCPCommandMissing) || !strings.Contains(err.Error(), "install:") {
		t.Fatalf("missing absolute path err = %v", err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkMCPCommand(self, nil); err != nil {
		t.Fatalf("existing absolute path: %v", err)
	}
	shell := "sh"
	if runtime.GOOS == "windows" {
		shell = "cmd"
	}
	if err := checkMCPCommand(shell, nil); err != nil {
		t.Fatalf("%s on PATH: %v", shell, err)
	}
}

func TestCheckMCPCommandUsesConfiguredPath(t *testing.T) {
	dir := t.TempDir()
	name := "artex-fake-mcp-server"
	file := name
	if runtime.GOOS == "windows" {
		file += ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, file), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := checkMCPCommand(name, nil); err == nil {
		t.Fatal("command outside ARTEX's PATH was found without the configured PATH")
	}
	if err := checkMCPCommand(name, map[string]string{"PATH": dir}); err != nil {
		t.Fatalf("command on the configured PATH: %v", err)
	}
	shell := "sh"
	if runtime.GOOS == "windows" {
		shell = "cmd"
	}
	if err := checkMCPCommand(shell, map[string]string{"PATH": dir}); err != nil {
		t.Fatalf("a command on ARTEX's PATH was rejected because the row sets another PATH: %v", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(filepath.Join(dir, file), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := checkMCPCommand(name, map[string]string{"PATH": dir}); err == nil {
			t.Fatal("a non-executable file counted as installed")
		}
	}
}
