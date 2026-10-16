package policy_test

import (
	"strings"
	"testing"

	"github.com/kanywst/omega/internal/server/policy"
)

const (
	readPermit = `permit (principal == User::"alice", action == Action::"read", resource);`
	readForbid = `forbid (principal == User::"alice", action == Action::"read", resource);`
)

func decide(t *testing.T, e *policy.Engine) policy.EvalResponse {
	t.Helper()
	r, err := e.Evaluate(policy.EvalRequest{
		Subject: policy.Entity{Type: "User", ID: "alice"}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestStoredPoliciesJoinFilePolicies(t *testing.T) {
	e := policy.New()
	if err := e.LoadSources(map[string]string{"base.cedar": readPermit}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.SetStoredPolicies(map[string]string{"deny": `@id("block") ` + readForbid}); err != nil {
		t.Fatal(err)
	}
	r := decide(t, e)
	if r.Decision || len(r.Reasons) != 1 || r.Reasons[0] != "api/deny::block" {
		t.Fatalf("a stored forbid must apply under its namespaced id: %+v", r)
	}
	// A file reload keeps the stored set.
	if err := e.LoadSources(map[string]string{"base.cedar": readPermit, "more.cedar": readPermit}, nil); err != nil {
		t.Fatal(err)
	}
	if decide(t, e).Decision {
		t.Fatal("the stored forbid must survive a file reload")
	}
	sources, _, _ := e.Snapshot()
	if len(sources) != 3 || sources["api/deny"] == "" {
		t.Fatalf("sources: %v", sources)
	}
	if len(e.FilePolicies()) != 2 {
		t.Fatalf("files: %v", e.FilePolicies())
	}
	// Dropping the stored set restores the file decision.
	if err := e.SetStoredPolicies(map[string]string{}); err != nil {
		t.Fatal(err)
	}
	if !decide(t, e).Decision {
		t.Fatal("without the stored forbid the file permit applies")
	}
}

func TestStoredPolicyFailuresKeepTheLastSet(t *testing.T) {
	e := policy.New()
	if err := e.LoadSources(map[string]string{"base.cedar": `@id("api/x::policy0") ` + readPermit}, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.SetStoredPolicies(map[string]string{"ok": readForbid}); err != nil {
		t.Fatal(err)
	}
	if err := e.SetStoredPolicies(map[string]string{"bad": "permit ("}); err == nil {
		t.Fatal("an unparsable set must be refused")
	}
	if err := e.SetStoredPolicies(map[string]string{"x": readPermit}); err == nil || !strings.Contains(err.Error(), "duplicate policy id") {
		t.Fatalf("a stored id that collides with a file id must be refused: %v", err)
	}
	if decide(t, e).Decision {
		t.Fatal("the last stored set that loaded must stay in force")
	}
	// A file reload that would collide with the stored set is refused too.
	if err := e.LoadSources(map[string]string{"base.cedar": `@id("api/ok::policy0") ` + readPermit}, nil); err == nil {
		t.Fatal("a file reload that collides with a stored id must be refused")
	}
	if err := e.LoadSources(map[string]string{"a/b": readPermit}, nil); err == nil {
		t.Fatal("a file name with '/' must be refused")
	}
	if decide(t, e).Decision {
		t.Fatal("refused reloads must leave the engine untouched")
	}
}

func TestCheckStored(t *testing.T) {
	e := policy.New()
	if err := e.LoadSources(map[string]string{"base.cedar": `@id("api/taken::policy0") ` + readPermit}, nil); err != nil {
		t.Fatal(err)
	}
	ids, err := e.CheckStored("p", readPermit+"\n"+readForbid)
	if err != nil || len(ids) != 2 || ids[0] != "api/p::policy0" || ids[1] != "api/p::policy1" {
		t.Fatalf("ids %v %v", ids, err)
	}
	if _, err := e.CheckStored("taken", readPermit); err == nil {
		t.Fatal("a collision with a file id must be reported")
	}
	if _, err := e.CheckStored("p", "   "); err == nil {
		t.Fatal("text with no policy must be refused")
	}
	if _, err := e.CheckStored("p", "permit"); err == nil {
		t.Fatal("unparsable text must be refused")
	}
	if !decide(t, e).Decision {
		t.Fatal("CheckStored must change nothing")
	}
}
