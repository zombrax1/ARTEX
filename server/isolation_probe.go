//go:build unix || windows

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/Autumn-27/artex/agent"
)

// The parts of the isolation self-test that Linux (isolation_unix.go) and Windows
// (isolation_windows.go) share: the probe's database checks and the file tool check.

// isolationProbeArg is the argv marker of the self-test probe:
// artex __artex-isolation-probe, with an isolationProbeSpec on stdin.
const isolationProbeArg = "__artex-isolation-probe"

// isolationProbeTimeout bounds the probe, database attempt included.
const isolationProbeTimeout = 30 * time.Second

type isolationProbeDB struct {
	Host     string `json:"host"`
	Port     uint16 `json:"port"`
	User     string `json:"user"`
	Database string `json:"database"`
}

// isolationProbeReport is the probe's answer on stdout.
type isolationProbeReport struct {
	Failures []string `json:"failures"`
}

// dsnProbeHosts lists each distinct host and port of a parsed DSN, the first one
// and its fallbacks (pgx adds a fallback per TLS attempt, so hosts repeat).
func dsnProbeHosts(cfg *pgx.ConnConfig) []isolationProbeDB {
	var out []isolationProbeDB
	add := func(host string, port uint16) {
		if host == "" {
			return
		}
		for _, db := range out {
			if db.Host == host && db.Port == port {
				return
			}
		}
		out = append(out, isolationProbeDB{Host: host, Port: port, User: cfg.User, Database: cfg.Database})
	}
	add(cfg.Host, cfg.Port)
	for _, fb := range cfg.Fallbacks {
		add(fb.Host, fb.Port)
	}
	return out
}

func configDir(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Dir(configPath)
}

// fileToolIsolationFailures opens each existing secret through the file tool
// identity (agent/filetools_identity.go): the open must be refused.
func fileToolIsolationFailures(secrets []string) []string {
	if !agent.FileToolIdentitySupported() {
		return []string{"the agent's file tools run with the server's identity on this platform"}
	}
	var failures []string
	for _, path := range secrets {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		var openErr error
		if err := agent.RunAsFileToolIdentity(func() {
			f, err := os.Open(path)
			if err == nil {
				f.Close()
			}
			openErr = err
		}); err != nil {
			failures = append(failures, fmt.Sprintf("the file tool identity cannot be applied: %v", err))
			break
		}
		if openErr == nil {
			failures = append(failures, fmt.Sprintf("the file tools can read %s", path))
		}
	}
	return failures
}

// connectWithoutPassword tries a session on the server's database with its user
// and no password. nil means the database let the executor in.
// The default sslmode (prefer) is kept: TLS first, then plain, as a client in the
// agent's shell would try.
func connectWithoutPassword(db *isolationProbeDB) error {
	quote := strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace
	dsn := fmt.Sprintf("host='%s' port=%d user='%s' dbname='%s' connect_timeout=5",
		quote(db.Host), db.Port, quote(db.User), quote(db.Database))
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		return err
	}
	cfg.Password = "" // not even one from a password file in the executor's home
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		return err
	}
	conn.Close(context.Background())
	return nil
}

// skillTreeMaxFailures caps what the skill tree check reports for one tree.
const skillTreeMaxFailures = 20
