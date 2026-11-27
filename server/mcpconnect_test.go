package server

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	actool "github.com/Autumn-27/norma/tool"
)

type fakeMCPClient struct{ closed atomic.Bool }

func (f *fakeMCPClient) Tools(context.Context) ([]actool.CoreTool, error) { return nil, nil }
func (f *fakeMCPClient) Close() error                                     { f.closed.Store(true); return nil }

// A server whose connect never returns, and ignores its context, must not hold
// the caller past the timeout.
func TestConnectMCPToolsTimesOutOnServerThatNeverAnswers(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	hang := func(context.Context, *db.MCPServer, ExecPrivilege) (mcpClient, error) {
		<-block
		return nil, errors.New("unreachable")
	}
	start := time.Now()
	r := connectMCPTools(context.Background(), &db.MCPServer{ID: 1, Name: "hang"}, ExecPrivilege{}, 100*time.Millisecond, hang)
	if !errors.Is(r.err, errMCPConnectTimeout) {
		t.Fatalf("err = %v, want a timeout", r.err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %s", d)
	}
}

// A client that connects after the caller gave up is closed, not leaked.
func TestConnectMCPToolsClosesLateClient(t *testing.T) {
	late := &fakeMCPClient{}
	release := make(chan struct{})
	slow := func(context.Context, *db.MCPServer, ExecPrivilege) (mcpClient, error) {
		<-release
		return late, nil
	}
	r := connectMCPTools(context.Background(), &db.MCPServer{ID: 2}, ExecPrivilege{}, 50*time.Millisecond, slow)
	if r.err == nil {
		t.Fatal("want a timeout")
	}
	close(release)
	deadline := time.Now().Add(2 * time.Second)
	for !late.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("late client was not closed")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Servers connect in parallel, a hanging one does not stop the others, and a
// server that timed out is skipped by the next run until its settings change.
func TestConnectAgentMCPsParallelAndCooldown(t *testing.T) {
	t.Setenv(envMCPConnectTimeout, "1")
	agentMCPCooldowns = &mcpCooldowns{until: map[int64]mcpCooldown{}}
	block := make(chan struct{})
	defer close(block)
	var calls atomic.Int32
	connect := func(ctx context.Context, m *db.MCPServer, _ ExecPrivilege) (mcpClient, error) {
		calls.Add(1)
		if m.Name == "ok" {
			return &fakeMCPClient{}, nil
		}
		<-block
		return nil, errors.New("unreachable")
	}
	servers := []*db.MCPServer{
		{ID: 10, Name: "hang1", Transport: "stdio", Command: "a"},
		{ID: 11, Name: "hang2", Transport: "stdio", Command: "b"},
		{ID: 12, Name: "ok", Transport: "stdio", Command: "c"},
	}
	start := time.Now()
	res := connectAgentMCPs(context.Background(), nil, servers, ExecPrivilege{}, connect)
	if d := time.Since(start); d > 1900*time.Millisecond {
		t.Fatalf("connect took %s; the servers did not connect in parallel", d)
	}
	if res[0].err == nil || res[1].err == nil || res[2].err != nil || res[2].client == nil {
		t.Fatalf("results = %+v", res)
	}
	calls.Store(0)
	start = time.Now()
	res = connectAgentMCPs(context.Background(), nil, servers, ExecPrivilege{}, connect)
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("second run waited %s on servers that are cooling down", d)
	}
	if calls.Load() != 1 || res[0].err == nil || res[2].err != nil {
		t.Fatalf("calls = %d, results = %+v", calls.Load(), res)
	}
	// Editing the server retries it at once.
	edited := *servers[0]
	edited.Command = "a2"
	calls.Store(0)
	connectAgentMCPs(context.Background(), nil, []*db.MCPServer{&edited}, ExecPrivilege{}, connect)
	if calls.Load() != 1 {
		t.Fatalf("edited server was not retried")
	}
}

// Stopping the run does not mark a server as cooling down.
func TestConnectAgentMCPsRunStoppedIsNotAServerFailure(t *testing.T) {
	t.Setenv(envMCPConnectTimeout, "5")
	agentMCPCooldowns = &mcpCooldowns{until: map[int64]mcpCooldown{}}
	ctx, cancel := context.WithCancel(context.Background())
	connect := func(ctx context.Context, _ *db.MCPServer, _ ExecPrivilege) (mcpClient, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	m := &db.MCPServer{ID: 20, Name: "slow"}
	res := connectAgentMCPs(ctx, nil, []*db.MCPServer{m}, ExecPrivilege{}, connect)
	if !errors.Is(res[0].err, context.Canceled) {
		t.Fatalf("err = %v", res[0].err)
	}
	if _, ok := agentMCPCooldowns.skip(m, time.Now()); ok {
		t.Fatal("a stopped run put the server on cooldown")
	}
}
