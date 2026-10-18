package policy_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/kanywst/omega/internal/server/policy"
)

func TestEvaluateEmitsDecisionContext(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"p.cedar": `@id("allow-web")
permit (principal == Spiffe::"spiffe://omega.local/example/web", action, resource);

@id("forbid-delete")
forbid (principal, action == Action::"DELETE", resource);

@id("needs-level")
forbid (principal, action == Action::"PUT", resource) when { principal.level > 3 };
`,
	})
	e := policy.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatalf("load: %v", err)
	}
	eval := func(subject, action string) policy.EvalResponse {
		t.Helper()
		resp, err := e.Evaluate(policy.EvalRequest{
			Subject:  policy.Entity{Type: "Spiffe", ID: subject},
			Action:   policy.Action{Name: action},
			Resource: policy.Entity{Type: "HttpPath", ID: "/x"},
		})
		if err != nil {
			t.Fatalf("evaluate %s %s: %v", subject, action, err)
		}
		return resp
	}
	const web = "spiffe://omega.local/example/web"

	allow := eval(web, "GET")
	if !allow.Decision || allow.Context == nil || !slices.Equal(allow.Context.Reasons, []string{"allow-web"}) || len(allow.Context.Errors) != 0 {
		t.Fatalf("allow: got %+v, want context.reasons [allow-web]", allow)
	}
	if !slices.Equal(allow.Reasons, allow.Context.Reasons) {
		t.Errorf("top-level reasons %v and context.reasons %v must agree", allow.Reasons, allow.Context.Reasons)
	}

	forbid := eval(web, "DELETE")
	if forbid.Decision || forbid.Context == nil || !slices.Equal(forbid.Context.Reasons, []string{"forbid-delete"}) {
		t.Fatalf("forbid: got %+v, want context.reasons [forbid-delete]", forbid)
	}

	// Evaluating `principal.level` fails. Cedar would skip the forbid
	// and let the permit stand; the forbid that errored denies instead,
	// and the PEP is told which one.
	skipped := eval(web, "PUT")
	if skipped.Decision || skipped.Context == nil || len(skipped.Context.Errors) != 1 || !slices.Equal(skipped.Context.Reasons, []string{"needs-level"}) {
		t.Fatalf("erroring forbid: got %+v, want a deny for needs-level with one context error", skipped)
	}
	if got := skipped.Context.Errors[0]; got.Policy != "needs-level" || got.Message == "" {
		t.Errorf("context error: got %+v, want policy needs-level with a message", got)
	}

	// A default deny has nothing to explain, so no context at all: a
	// minimal Decision as in §5.5.
	none := eval("spiffe://omega.local/example/other", "GET")
	if none.Decision || none.Context != nil {
		t.Fatalf("default deny: got %+v, want no context", none)
	}
	raw, err := json.Marshal(none)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"decision":false}` {
		t.Errorf("default deny on the wire: got %s", raw)
	}
}

func TestForCallerStripsMessagesOnly(t *testing.T) {
	full := policy.EvalResponse{
		Decision: true,
		Reasons:  []string{"a"},
		Context: &policy.DecisionContext{
			Reasons: []string{"a"},
			Errors:  []policy.PolicyError{{Policy: "b", Message: "entity does not have attribute clearance"}},
		},
	}
	out := full.ForCaller()
	raw, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"decision":true,"context":{"reasons":["a"],"errors":[{"policy":"b"}]},"reasons":["a"]}` {
		t.Errorf("for caller: %s", raw)
	}
	if full.Context.Errors[0].Message == "" {
		t.Error("ForCaller must not modify the response it was called on, which is still audited")
	}
	none := policy.EvalResponse{Decision: false}
	if got := none.ForCaller(); got.Context != nil {
		t.Errorf("no context: %+v", got)
	}
}

// A policy that fails to evaluate must not widen access: Cedar skips
// it, so an erroring forbid beside a matching permit would otherwise
// allow. It denies, with the forbid as the reason; an erroring permit
// only fails to grant.
func TestPolicyErrorsNeverWidenAccess(t *testing.T) {
	cases := []struct {
		name     string
		policies string
		allow    bool
		reasons  []string
	}{
		{"erroring forbid beside a matching permit denies", `@id("permit-all") permit (principal, action, resource);
@id("forbid-low") forbid (principal, action, resource) when { principal.clearance < 3 };
`, false, []string{"forbid-low"}},
		{"erroring permit beside another matching permit allows", `@id("permit-all") permit (principal, action, resource);
@id("permit-high") permit (principal, action, resource) when { principal.clearance > 3 };
`, true, []string{"permit-all"}},
		{"erroring permit alone denies", `@id("permit-high") permit (principal, action, resource) when { principal.clearance > 3 };
`, false, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := policy.New()
			if err := e.LoadDir(writePolicies(t, map[string]string{"p.cedar": tc.policies})); err != nil {
				t.Fatalf("load: %v", err)
			}
			resp, err := e.Evaluate(policy.EvalRequest{
				Subject:  policy.Entity{Type: "User", ID: "u", Attrs: map[string]any{"team": "x"}},
				Action:   policy.Action{Name: "read"},
				Resource: policy.Entity{Type: "Doc", ID: "d"},
			})
			if err != nil {
				t.Fatal(err)
			}
			if resp.Decision != tc.allow || !slices.Equal(resp.Reasons, tc.reasons) || resp.Context == nil || len(resp.Context.Errors) != 1 {
				t.Fatalf("got decision %v reasons %v context %+v", resp.Decision, resp.Reasons, resp.Context)
			}
		})
	}
}
