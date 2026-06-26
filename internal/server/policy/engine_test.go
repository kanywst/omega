package policy_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kanywst/omega/internal/server/policy"
)

const policyAllowWebGetAPI = `permit (
  principal == Spiffe::"spiffe://omega.local/example/web",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`

func writePolicies(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func TestEvaluateAllowAndDeny(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"allow.cedar": policyAllowWebGetAPI,
	})
	e := policy.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatalf("load: %v", err)
	}

	allow, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/example/web"},
		Action:   policy.Action{Name: "GET"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/api/foo"},
	})
	if err != nil {
		t.Fatalf("evaluate allow: %v", err)
	}
	if !allow.Decision {
		t.Errorf("expected allow, got %+v", allow)
	}
	if len(allow.Reasons) == 0 {
		t.Errorf("expected at least one matching policy id in reasons")
	}

	deny, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/example/web"},
		Action:   policy.Action{Name: "DELETE"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/api/foo"},
	})
	if err != nil {
		t.Fatalf("evaluate deny: %v", err)
	}
	if deny.Decision {
		t.Errorf("expected deny on DELETE, got allow")
	}
}

func TestEmptyEngineDeniesEverything(t *testing.T) {
	e := policy.New()
	resp, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/example/web"},
		Action:   policy.Action{Name: "GET"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/api/foo"},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision {
		t.Errorf("empty engine must deny by default")
	}
}

func TestValidateMissingFields(t *testing.T) {
	e := policy.New()
	if _, err := e.Evaluate(policy.EvalRequest{
		Action:   policy.Action{Name: "GET"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/x"},
	}); err == nil {
		t.Error("missing subject must error")
	}
	if _, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/x"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/x"},
	}); err == nil {
		t.Error("missing action must error")
	}
	if _, err := e.Evaluate(policy.EvalRequest{
		Subject: policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/x"},
		Action:  policy.Action{Name: "GET"},
	}); err == nil {
		t.Error("missing resource must error")
	}
}

func TestLoadDirMultipleFilesUseDistinctIDs(t *testing.T) {
	// Regression: cedar-go's NewPolicySetFromBytes always assigns
	// "policy0" to a single-policy file, so naively merging two files
	// would collide. The loader must derive a unique id per file.
	dir := writePolicies(t, map[string]string{
		"a.cedar": `permit (principal == User::"alice", action == Action::"GET", resource);`,
		"b.cedar": `permit (principal == User::"bob",   action == Action::"GET", resource);`,
	})
	e := policy.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatalf("load multi-file dir: %v", err)
	}
	for _, sub := range []string{"alice", "bob"} {
		resp, err := e.Evaluate(policy.EvalRequest{
			Subject:  policy.Entity{Type: "User", ID: sub},
			Action:   policy.Action{Name: "GET"},
			Resource: policy.Entity{Type: "HttpPath", ID: "/anything"},
		})
		if err != nil {
			t.Fatalf("evaluate %s: %v", sub, err)
		}
		if !resp.Decision {
			t.Errorf("%s must be allowed by its file's permit", sub)
		}
	}
}

func TestLoadDirHonorsIDAnnotation(t *testing.T) {
	// An explicit @id("...") annotation should flow into the reasons
	// list so operators can match audit entries to source policies.
	dir := writePolicies(t, map[string]string{
		"x.cedar": `@id("custom-named-rule")
permit (principal == User::"alice", action == Action::"GET", resource);`,
	})
	e := policy.New()
	if err := e.LoadDir(dir); err != nil {
		t.Fatalf("load: %v", err)
	}
	resp, err := e.Evaluate(policy.EvalRequest{
		Subject:  policy.Entity{Type: "User", ID: "alice"},
		Action:   policy.Action{Name: "GET"},
		Resource: policy.Entity{Type: "HttpPath", ID: "/x"},
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !resp.Decision || len(resp.Reasons) == 0 || resp.Reasons[0] != "custom-named-rule" {
		t.Errorf("expected reason custom-named-rule, got %+v", resp)
	}
}

func TestLoadDirRejectsBadPolicy(t *testing.T) {
	dir := writePolicies(t, map[string]string{
		"bad.cedar": "this is not cedar syntax",
	})
	e := policy.New()
	if err := e.LoadDir(dir); err == nil {
		t.Error("expected error loading invalid cedar")
	}
}
