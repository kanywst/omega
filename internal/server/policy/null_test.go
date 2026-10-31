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

func TestNullSetElementsAreDropped(t *testing.T) {
	e := loadEngine(t, `permit (principal, action, resource) when { principal.groups.containsAny(resource.groups) };`)
	resp, err := e.Evaluate(decodeReq(t, `{
	  "subject":  {"type": "User", "id": "alice", "properties": {"groups": [null]}},
	  "action":   {"name": "GET"},
	  "resource": {"type": "Doc", "id": "d1", "properties": {"groups": [null, "ops"]}}
	}`))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision {
		t.Errorf("null elements must not become a shared \"\" member of both sets")
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

func TestNullsInNestedObjectsDoNotMatch(t *testing.T) {
	e := loadEngine(t, `permit (principal, action, resource) when { principal.org == resource.org };`)
	resp, err := e.Evaluate(decodeReq(t, `{
	  "subject":  {"type": "User", "id": "alice", "properties": {"org": {"tenant": null}}},
	  "action":   {"name": "GET"},
	  "resource": {"type": "Doc", "id": "d1", "properties": {"org": {"tenant": "acme"}}}
	}`))
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if resp.Decision {
		t.Errorf("a null nested member must not match a set one")
	}
}
