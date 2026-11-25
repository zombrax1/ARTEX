package server

import "testing"

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
