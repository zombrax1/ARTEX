package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

// Connecting the MCP servers an agent can see happens before the agent's first
// model request. A server that starts but never answers (a stdio command waiting
// for input it will not get, a URL that accepts the connection and then says
// nothing) used to hold that step, and so the whole run, until the run was
// stopped: no request ever reached the model. Each server now gets a bounded
// time to connect and list its tools, the servers connect in parallel, and a
// server that timed out is skipped for a while instead of delaying every run.

// envMCPConnectTimeout sets, in seconds, how long one MCP server may take to
// connect and list its tools when an agent run starts.
const envMCPConnectTimeout = "ARTEX_MCP_CONNECT_TIMEOUT"

const (
	defaultMCPConnectTimeout = 30 * time.Second
	// mcpConnectCooldown is how long a server that timed out is skipped by agent
	// runs. Editing the server (or restarting ARTEX) clears it.
	mcpConnectCooldown = 5 * time.Minute
	// mcpConnectParallel caps how many servers start at once for one run.
	mcpConnectParallel = 4
)

var errMCPConnectTimeout = errors.New("did not answer in time")

// mcpConnectTimeout returns the per-server connect budget.
func mcpConnectTimeout() time.Duration {
	if v := strings.TrimSpace(os.Getenv(envMCPConnectTimeout)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Second
		}
	}
	return defaultMCPConnectTimeout
}

// mcpConnectResult is one server's outcome for an agent run.
type mcpConnectResult struct {
	client mcpClient
	tools  []actool.CoreTool
	stage  string // "connect" or "tools/list" when err is set
	err    error
}

// mcpCooldowns remembers servers that timed out, keyed by row id, together with
// a fingerprint of their settings so an edit retries at once.
type mcpCooldowns struct {
	mu    sync.Mutex
	until map[int64]mcpCooldown
}

type mcpCooldown struct {
	fp    string
	until time.Time
}

var agentMCPCooldowns = &mcpCooldowns{until: map[int64]mcpCooldown{}}

// mcpFingerprint is what identifies a server's configuration.
func mcpFingerprint(m *db.MCPServer) string {
	b, _ := json.Marshal([]any{m.Transport, m.Command, m.Args, m.URL, m.Env, m.Insecure})
	return string(b)
}

// skip reports whether m is cooling down after a timeout, and until when.
func (c *mcpCooldowns) skip(m *db.MCPServer, now time.Time) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cd, ok := c.until[m.ID]
	if !ok {
		return time.Time{}, false
	}
	if cd.fp != mcpFingerprint(m) || !now.Before(cd.until) {
		delete(c.until, m.ID)
		return time.Time{}, false
	}
	return cd.until, true
}

func (c *mcpCooldowns) mark(m *db.MCPServer, until time.Time) {
	c.mu.Lock()
	c.until[m.ID] = mcpCooldown{fp: mcpFingerprint(m), until: until}
	c.mu.Unlock()
}

func (c *mcpCooldowns) clear(id int64) {
	c.mu.Lock()
	delete(c.until, id)
	c.mu.Unlock()
}

// connectMCPTools connects one server and lists its tools within timeout. The
// work runs in its own goroutine, so even a transport that does not watch its
// context (an SSE stream that never sends its endpoint) cannot hold the caller;
// a client that connects after the deadline is closed when it does.
func connectMCPTools(ctx context.Context, m *db.MCPServer, priv ExecPrivilege, timeout time.Duration,
	connect func(context.Context, *db.MCPServer, ExecPrivilege) (mcpClient, error)) mcpConnectResult {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	done := make(chan mcpConnectResult, 1)
	var abandoned sync.Once
	gone := make(chan struct{})
	go func() {
		defer cancel()
		cl, err := connect(cctx, m, priv)
		if err != nil {
			done <- mcpConnectResult{stage: "connect", err: err}
			return
		}
		ts, err := cl.Tools(cctx)
		if err != nil {
			_ = cl.Close()
			done <- mcpConnectResult{stage: "tools/list", err: err}
			return
		}
		select {
		case done <- mcpConnectResult{client: cl, tools: ts}:
		case <-gone:
			_ = cl.Close() // the caller stopped waiting
		}
	}()
	select {
	case r := <-done:
		if r.err != nil && errors.Is(r.err, context.DeadlineExceeded) && ctx.Err() == nil {
			r.err = fmt.Errorf("%w (%s): %v", errMCPConnectTimeout, timeout, r.err)
		}
		return r
	case <-cctx.Done():
		abandoned.Do(func() { close(gone) })
		// The worker may have finished at the same moment.
		select {
		case r := <-done:
			if r.err == nil {
				return r
			}
		default:
		}
		if ctx.Err() != nil {
			return mcpConnectResult{stage: "connect", err: ctx.Err()}
		}
		return mcpConnectResult{stage: "connect", err: fmt.Errorf("%w (%s)", errMCPConnectTimeout, timeout)}
	}
}

// connectAgentMCPs connects the given servers for one agent run, in parallel
// and each within the connect timeout, and returns their outcomes in the same
// order. A failure is logged and written to the server's health, except when
// the run itself was stopped: that says nothing about the server. A server that
// timed out is skipped by later runs for mcpConnectCooldown.
func connectAgentMCPs(ctx context.Context, pg *db.DB, servers []*db.MCPServer, priv ExecPrivilege,
	connect func(context.Context, *db.MCPServer, ExecPrivilege) (mcpClient, error)) []mcpConnectResult {
	timeout := mcpConnectTimeout()
	out := make([]mcpConnectResult, len(servers))
	sem := make(chan struct{}, mcpConnectParallel)
	var wg sync.WaitGroup
	for i, m := range servers {
		if until, ok := agentMCPCooldowns.skip(m, time.Now()); ok {
			out[i] = mcpConnectResult{stage: "connect", err: fmt.Errorf("skipped until %s after it did not answer in time", until.Format("15:04:05"))}
			continue
		}
		wg.Add(1)
		go func(i int, m *db.MCPServer) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				out[i] = mcpConnectResult{stage: "connect", err: ctx.Err()}
				return
			}
			defer func() { <-sem }()
			r := connectMCPTools(ctx, m, priv, timeout, connect)
			out[i] = r
			switch {
			case r.err == nil:
				agentMCPCooldowns.clear(m.ID)
				if pg != nil {
					_ = pg.UpdateMCPHealth(m.ID, true, "")
				}
			case ctx.Err() != nil:
				// The run was stopped; the server's health is unknown, not bad.
			default:
				log.Printf("[mcp] %s %s failed: %v", m.Name, r.stage, r.err)
				msg := r.stage + ": " + r.err.Error()
				if errors.Is(r.err, errMCPConnectTimeout) {
					until := time.Now().Add(mcpConnectCooldown)
					agentMCPCooldowns.mark(m, until)
					msg += fmt.Sprintf("; agent runs skip it until %s (set %s to wait longer)", until.Format("15:04:05"), envMCPConnectTimeout)
				}
				if pg != nil {
					_ = pg.UpdateMCPHealth(m.ID, false, msg)
				}
			}
		}(i, m)
	}
	wg.Wait()
	return out
}
