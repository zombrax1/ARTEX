//go:build windows

package server

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/windows"
)

// Environment of the agent processes on Windows. A process that crosses from the
// server's identity to the agent account gets the agent account's own environment
// (CreateEnvironmentBlock: its profile, temp directory and the machine variables),
// and from the server's environment only the allowlist below plus the names the
// caller asks to keep (an MCP server's configured variables, a custom tool's
// parameters). Nothing else crosses, whatever its name. Windows variable names are
// case-insensitive, and so is the allowlist.

// executorEnvNames are the server variables an agent process keeps: the search
// path, the locale, the non-interactive defaults Norma sets, the proxy and CA trust
// variables the agents pass to their shells (agent.proxyEnv), the browser location,
// and the shim's own non-secret variables (ARTEX_EXEC_*), which the shim reads and
// does not pass on.
var executorEnvNames = upperSet(
	"PATH", "PATHEXT",
	"LANG", "LANGUAGE", "TERM", "TZ",
	"LC_ALL", "LC_CTYPE", "LC_NUMERIC", "LC_TIME", "LC_COLLATE", "LC_MONETARY",
	"LC_MESSAGES", "LC_PAPER", "LC_NAME", "LC_ADDRESS", "LC_TELEPHONE",
	"LC_MEASUREMENT", "LC_IDENTIFICATION",
	"PAGER", "GIT_PAGER", "SYSTEMD_PAGER", "DEBIAN_FRONTEND",
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "NODE_USE_ENV_PROXY",
	"SSL_CERT_FILE", "CURL_CA_BUNDLE", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO", "NODE_EXTRA_CA_CERTS",
	"PLAYWRIGHT_BROWSERS_PATH",
	envExecShell, envExecAccount, envExecSID, envExecCred, envExecBin,
)

// envExecKeep lists, comma-separated, names the shim keeps besides the allowlist.
// It is not kept itself.
const envExecKeep = "ARTEX_EXEC_KEEP"

// shimOnlyEnvPrefix marks the shim's own variables: they reach the shim, never the
// agent process it starts.
const shimOnlyEnvPrefix = "ARTEX_EXEC_"

func upperSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[strings.ToUpper(n)] = true
	}
	return m
}

// executorEnvAllowed reports whether the variable name crosses to an agent process.
func executorEnvAllowed(name string) bool {
	return executorEnvNames[strings.ToUpper(name)]
}

// envName returns the name of a NAME=value entry, or "" for a malformed one and for
// the per-drive "=C:=C:\..." entries.
func envName(kv string) string {
	name, _, ok := strings.Cut(kv, "=")
	if !ok || name == "" {
		return ""
	}
	return name
}

// executorEnv returns the entries of env an agent process keeps: the allowlisted
// names and the names in keep (upper case), in their order.
func executorEnv(env []string, keep map[string]bool) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		name := envName(kv)
		if name == "" {
			continue
		}
		if executorEnvAllowed(name) || keep[strings.ToUpper(name)] {
			out = append(out, kv)
		}
	}
	return out
}

// agentProcessEnv is the base environment of a custom tool: the allowlist when it
// runs as the agent account, the server's environment otherwise.
func agentProcessEnv(p ExecPrivilege) []string {
	if !p.Enabled {
		return os.Environ()
	}
	return executorEnv(os.Environ(), nil)
}

// withExecKeep adds envExecKeep to the configured environment of an MCP stdio
// server that runs as the agent account, so the shim keeps those variables.
func withExecKeep(p ExecPrivilege, env map[string]string) map[string]string {
	if !p.Enabled || len(env) == 0 {
		return env
	}
	names := make([]string, 0, len(env))
	out := make(map[string]string, len(env)+1)
	for k, v := range env {
		names = append(names, k)
		out[k] = v
	}
	sort.Strings(names)
	out[envExecKeep] = strings.Join(names, ",")
	return out
}

// execToolCommand returns the command line and environment of a custom tool. As
// the agent account the tool starts through the drop shim, which keeps the names
// of env that are not on the allowlist (the session's and the TOOL_ parameters).
func execToolCommand(p ExecPrivilege, name string, args, env []string) (string, []string, []string, error) {
	if !p.Enabled {
		return name, args, env, nil
	}
	cmd, cmdArgs, err := execDropCommand(p, name, args)
	if err != nil {
		return "", nil, nil, err
	}
	var keep []string
	for _, kv := range env {
		if n := envName(kv); n != "" && !executorEnvAllowed(n) {
			keep = append(keep, n)
		}
	}
	out := append([]string(nil), env...)
	if len(keep) > 0 {
		out = append(out, envExecKeep+"="+strings.Join(keep, ","))
	}
	return cmd, cmdArgs, out, nil
}

// keepFromEnv reads envExecKeep from env as a set of upper-case names.
func keepFromEnv(env []string) map[string]bool {
	keep := map[string]bool{}
	for _, kv := range env {
		if strings.EqualFold(envName(kv), envExecKeep) {
			_, v, _ := strings.Cut(kv, "=")
			for _, n := range strings.Split(v, ",") {
				if n = strings.TrimSpace(n); n != "" {
					keep[strings.ToUpper(n)] = true
				}
			}
		}
	}
	return keep
}

// agentChildEnv builds the environment of a process the shim starts as the agent
// account: the account's own environment (tok is its logon token), overridden by
// the allowlisted and kept entries of the shim's environment serverEnv. The shim's
// own variables and envExecKeep do not cross, and binDir, where the shim lives, is
// taken off PATH, so a nested "powershell" in the agent runs the real one.
func agentChildEnv(tok windows.Token, serverEnv []string, binDir string) ([]string, error) {
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, tok, false); err != nil {
		return nil, err
	}
	own := envBlockToList(block)
	_ = windows.DestroyEnvironmentBlock(block)

	keep := keepFromEnv(serverEnv)
	var order []string
	byName := map[string]string{}
	set := func(kv string) {
		up := strings.ToUpper(envName(kv))
		if _, ok := byName[up]; !ok {
			order = append(order, up)
		}
		byName[up] = kv
	}
	for _, kv := range own {
		if envName(kv) != "" {
			set(kv)
		}
	}
	for _, kv := range serverEnv {
		name := envName(kv)
		if name == "" {
			continue
		}
		up := strings.ToUpper(name)
		if strings.HasPrefix(up, shimOnlyEnvPrefix) {
			continue
		}
		if executorEnvAllowed(name) || keep[up] {
			if up == "PATH" {
				_, v, _ := strings.Cut(kv, "=")
				kv = name + "=" + pathWithout(v, binDir)
			}
			set(kv)
		}
	}
	out := make([]string, 0, len(order))
	for _, up := range order {
		out = append(out, byName[up])
	}
	return out, nil
}

// pathWithout removes dir from a PATH list.
func pathWithout(list, dir string) string {
	if dir == "" {
		return list
	}
	clean := filepath.Clean(dir)
	var keep []string
	for _, p := range filepath.SplitList(list) {
		if p == "" || strings.EqualFold(filepath.Clean(p), clean) {
			continue
		}
		keep = append(keep, p)
	}
	return strings.Join(keep, string(os.PathListSeparator))
}

// ownEnvironment returns the environment Windows builds for tok's account, for the
// probe's environment check.
func ownEnvironment(tok windows.Token) ([]string, error) {
	var block *uint16
	if err := windows.CreateEnvironmentBlock(&block, tok, false); err != nil {
		return nil, err
	}
	defer windows.DestroyEnvironmentBlock(block)
	return envBlockToList(block), nil
}
