package server

import (
	"context"
	"testing"
	"time"
)

func TestProfileGateLifecycle(t *testing.T) {
	s := &Server{}
	g := s.profileGate(7)
	if g == nil || g.Limit() != 0 {
		t.Fatalf("a profile with no cap should still get an unlimited gate, got %v", g)
	}
	// A cap saved later must bind the same gate that existing providers hold.
	setGateLimit(7, g, 2)
	if g2 := s.profileGate(7); g2 != g || g.Limit() != 2 {
		t.Fatalf("rebuild did not reuse/update the gate: same=%v limit=%d", g2 == g, g.Limit())
	}
	setGateLimit(7, g, -1)
	if g.Limit() != 0 {
		t.Fatal("a negative cap should mean unlimited")
	}
	if s.profileGate(8) == g {
		t.Fatal("profiles must not share a gate")
	}
}

func TestLLMQueueStats(t *testing.T) {
	s := &Server{}
	if got := s.llmQueueStats(); len(got) != 0 {
		t.Fatalf("no gates yet: got %v", got)
	}
	g := s.profileGate(3)
	setGateLimit(3, g, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := g.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	waiting := make(chan error, 1)
	go func() { waiting <- g.Acquire(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, q := g.Stats(); q == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("second request never queued")
		}
		time.Sleep(5 * time.Millisecond)
	}
	got := s.llmQueueStats()["3"]
	if got != (LLMQueueStat{InFlight: 1, Queued: 1, Limit: 1}) {
		t.Fatalf("stats = %+v, want 1 in flight, 1 queued, limit 1", got)
	}
	g.Release()
	if err := <-waiting; err != nil {
		t.Fatal(err)
	}
	g.Release()
	if got := s.llmQueueStats()["3"]; got.InFlight != 0 || got.Queued != 0 {
		t.Fatalf("after release: %+v", got)
	}
}
