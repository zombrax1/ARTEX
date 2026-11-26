package agent

import (
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

// The domain tools read and write the platform's own records (the exploration
// graph, assets, findings, goals). The target gate must find no target in
// their input: an intent or a finding that mentions a URL is not a connection.
// The gate scans every tool it does not know, so a domain tool added here has
// to be added to the gate's list of tools without a target. The exceptions are
// the domain tools that connect to the target themselves (networkDomainTools):
// the gate must read their targets.
var networkDomainTools = map[string]bool{"compare_access": true}

func TestDomainToolsDeclareNoTarget(t *testing.T) {
	seeds := BuiltinToolSeeds()
	if len(seeds) < 20 {
		t.Fatalf("only %d domain tools found", len(seeds))
	}
	input := []byte(`{"summary":"probe https://app.example.com/login","items":[{"url":"https://app.example.com:8443/","ip":"203.0.113.7"}],` +
		`"poc":"curl -sk https://app.example.com/ -x http://127.0.0.1:8080","scope":"203.0.113.0/24"}`)
	if targets := intercept.ExtractTargets("a_tool_the_gate_does_not_know", input); len(targets) == 0 {
		t.Fatal("control: the input names targets, and an unknown tool is scanned")
	}
	for _, seed := range seeds {
		if networkDomainTools[seed.Key] {
			if targets := intercept.ExtractTargets(seed.Key, input); len(targets) == 0 {
				t.Errorf("%s connects to the target, but the gate reads no target from it", seed.Key)
			}
			continue
		}
		if targets := intercept.ExtractTargets(seed.Key, input); len(targets) != 0 {
			t.Errorf("%s: the gate reads targets %+v from a domain tool", seed.Key, targets)
		}
	}
}
