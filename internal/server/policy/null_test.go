package policy_test

import (
	"encoding/json"
	"testing"

	"github.com/kanywst/omega/internal/server/policy"
)

// decodeReq builds the request from JSON so the null values arrive exactly
// as the HTTP handler sees them.
func decodeReq(t *testing.T, body string) policy.EvalRequest {
	t.Helper()
	var req policy.EvalRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return req
}

func loadEngine(t *testing.T, src string) *policy.Engine {
	t.Helper()
	e := policy.New()
	if err := e.LoadDir(writePolicies(t, map[string]string{"p.cedar": src})); err != nil {
		t.Fatalf("load: %v", err)
	}
	return e
}

// Two null properties used to become "" on both sides and satisfy an
// equality check, granting access neither entity was given.
func TestNullPropertiesDoNotMatchEachOther(t *testing.T) {
	e := loadEngine(t, `permit (principal, action == Action::"GET", resource)
  when { principal has tenant && resource has tenant && principal.tenant == resource.tenant };
permit (principal, action == Action::"READ", resource)
  when { principal.tenant == resource.tenant };`)
	for _, action := range []string{"GET", "READ"} {
		resp, err := e.Evaluate(decodeReq(t, `{
		  "subject":  {"type": "User", "id": "alice", "properties": {"tenant": null}},
		  "action":   {"name": "`+action+`"},
		  "resource": {"type": "Doc", "id": "d1", "properties": {"tenant": null}}
		}`))
		if err != nil {
			t.Fatalf("%s: a null property must be accepted, got %v", action, err)
		}
		if resp.Decision {
			t.Errorf("%s: null tenant on both sides must not satisfy principal.tenant == resource.tenant", action)
		}
	}
}

func TestNullContextPropertyIsAbsent(t *testing.T) {
	e := loadEngine(t, `permit (principal, action, resource) unless { context has revoked };`)
	resp, err := e.Evaluate(decodeReq(t, `{
	  "subject":  {"type": "User", "id": "alice"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "Doc", "id": "d1"},
	  "context":  {"revoked": null}
	}`))
	if err != nil {
		t.Fatalf("a null context property must be accepted, got %v", err)
	}
	if !resp.Decision {
		t.Errorf("context.revoked = null must read as absent, so `context has revoked` is false")
	}
}

// A property that holds a null anywhere is absent as a whole. Dropping
// only the null would leave `[null]` and `[]`, or `{"tenant": null}` and
// `{}`, equal on both sides.
func TestPropertiesHoldingNullAreAbsent(t *testing.T) {
	e := loadEngine(t, `permit (principal, action == Action::"OVERLAP", resource) when { principal.groups.containsAny(resource.groups) };
permit (principal, action == Action::"SETEQ", resource) when { principal.groups == resource.groups };
permit (principal, action == Action::"OBJEQ", resource) when { principal.org == resource.org };`)
	cases := []struct{ action, sub, res string }{
		{"OVERLAP", `{"groups": [null]}`, `{"groups": [null, "ops"]}`},
		{"SETEQ", `{"groups": [null]}`, `{"groups": [null]}`},
		{"SETEQ", `{"groups": [null]}`, `{"groups": []}`},
		{"OBJEQ", `{"org": {"tenant": null}}`, `{"org": {"tenant": null}}`},
		{"OBJEQ", `{"org": {"tenant": null}}`, `{"org": {}}`},
		{"OBJEQ", `{"org": {"tenant": null}}`, `{"org": {"tenant": "acme"}}`},
		{"OBJEQ", `{"org": [{"tenant": null}]}`, `{"org": [{"tenant": null}]}`},
	}
	for _, c := range cases {
		resp, err := e.Evaluate(decodeReq(t, `{
		  "subject":  {"type": "User", "id": "alice", "properties": `+c.sub+`},
		  "action":   {"name": "`+c.action+`"},
		  "resource": {"type": "Doc", "id": "d1", "properties": `+c.res+`}
		}`))
		if err != nil {
			t.Fatalf("%s %s vs %s: a null must be accepted, got %v", c.action, c.sub, c.res, err)
		}
		if resp.Decision {
			t.Errorf("%s %s vs %s: a property holding a null must not match", c.action, c.sub, c.res)
		}
	}
}

// Properties without a null still convert as before.
func TestNullFreeNestedValuesStillMatch(t *testing.T) {
	e := loadEngine(t, `permit (principal, action, resource) when { principal.org == resource.org && principal.groups.contains("ops") };`)
	resp, err := e.Evaluate(decodeReq(t, `{
	  "subject":  {"type": "User", "id": "alice", "properties": {"org": {"tenant": "acme"}, "groups": ["ops"], "note": null}},
	  "action":   {"name": "GET"},
	  "resource": {"type": "Doc", "id": "d1", "properties": {"org": {"tenant": "acme"}}}
	}`))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !resp.Decision {
		t.Errorf("null-free properties must keep matching; a null sibling must not affect them")
	}
}

// An unguarded read of a null property is an evaluation error; for a
// forbid that means deny, which is the fail-closed direction.
func TestNullPropertyReadByForbidDenies(t *testing.T) {
	e := loadEngine(t, `permit (principal, action, resource);
forbid (principal, action, resource) when { context.revoked == true };`)
	resp, err := e.Evaluate(decodeReq(t, `{
	  "subject":  {"type": "User", "id": "alice"},
	  "action":   {"name": "GET"},
	  "resource": {"type": "Doc", "id": "d1"},
	  "context":  {"revoked": null}
	}`))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision {
		t.Errorf("a forbid that cannot read context.revoked must deny")
	}
}
