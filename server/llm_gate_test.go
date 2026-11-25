package server

import "testing"

func TestProfileGateLifecycle(t *testing.T) {
	s := &Server{}
	if g := s.profileGate(7, 0); g != nil {
		t.Fatal("unlimited profile with no prior cap should get no gate")
	}
	g := s.profileGate(7, 2)
	if g == nil || g.Limit() != 2 {
		t.Fatalf("want a gate with limit 2, got %v", g)
	}
	// A rebuild after a profile edit must reuse the same gate (in-flight
	// requests on the old provider keep counting) with the new limit.
	if g2 := s.profileGate(7, 1); g2 != g || g.Limit() != 1 {
		t.Fatalf("rebuild did not reuse/update the gate: same=%v limit=%d", g2 == g, g.Limit())
	}
	if g3 := s.profileGate(7, 0); g3 != g || g.Limit() != 0 {
		t.Fatal("lifting the cap should keep the gate, now unlimited")
	}
	if s.profileGate(8, 3) == g {
		t.Fatal("profiles must not share a gate")
	}
}
