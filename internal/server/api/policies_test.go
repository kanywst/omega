package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

const (
	filePolicy   = `@id("file-deny") forbid (principal == Spiffe::"spiffe://omega.local/people/mallory", action, resource);`
	alicePermit  = `permit (principal == Spiffe::"spiffe://omega.local/people/alice", action == Action::"read", resource);`
	alicePermit2 = `permit (principal == Spiffe::"spiffe://omega.local/people/alice", action in [Action::"read", Action::"write"], resource);`
)

// callH is call with request headers, returning the response headers too.
func callH(t *testing.T, c *http.Client, method, u string, body any, h map[string]string) (int, http.Header, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		r = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, u, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, out
}

func evalAs(t *testing.T, env *domainEnv, c *http.Client, subject, action string) policy.EvalResponse {
	t.Helper()
	code, body := call(t, c, "POST", env.srv.URL+"/access/v1/evaluation", policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: subject},
		Action:   policy.Action{Name: action},
		Resource: policy.Entity{Type: "Doc", ID: "d"},
	})
	if code != http.StatusOK {
		t.Fatalf("evaluate: %d %s", code, body)
	}
	var r policy.EvalResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestPolicyAPILifecycle(t *testing.T) {
	env := newDomainEnv(t, filePolicy, "spiffe://omega.local/node/agent")
	root, b := env.as(t, rootAdmin), env.as(t, bob)
	base := env.srv.URL + "/v1/policies"

	if r := evalAs(t, env, root, alice, "read"); r.Decision {
		t.Fatal("nothing permits alice yet")
	}

	// An invalid policy is rejected and never stored.
	if code, body := call(t, root, "POST", base, api.PolicyRequest{ID: "alice-read", Text: "permit (principal,"}); code != http.StatusBadRequest {
		t.Fatalf("invalid text: %d %s", code, body)
	}
	if code, _ := call(t, root, "GET", base+"/alice-read", nil); code != http.StatusNotFound {
		t.Fatalf("the rejected policy must not be stored: %d", code)
	}
	if code, _ := call(t, root, "POST", base, api.PolicyRequest{ID: "Bad.ID", Text: alicePermit}); code != http.StatusBadRequest {
		t.Fatalf("invalid id: %d", code)
	}

	// Only a root admin may write.
	if code, _ := call(t, b, "POST", base, api.PolicyRequest{ID: "alice-read", Text: alicePermit}); code != http.StatusForbidden {
		t.Fatalf("bob create: %d", code)
	}

	code, h, body := callH(t, root, "POST", base, api.PolicyRequest{ID: "alice-read", Text: alicePermit}, nil)
	if code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	var created api.PolicyView
	if err := json.Unmarshal(body, &created); err != nil {
		t.Fatal(err)
	}
	if created.Version != 1 || created.CreatedBy != rootAdmin || created.Source != api.PolicySourceAPI || h.Get("ETag") != created.ETag || created.ETag == "" {
		t.Fatalf("created view: %+v etag=%q", created, h.Get("ETag"))
	}
	if code, _ := call(t, root, "POST", base, api.PolicyRequest{ID: "alice-read", Text: alicePermit}); code != http.StatusConflict {
		t.Fatalf("duplicate create: %d", code)
	}

	r := evalAs(t, env, root, alice, "read")
	if !r.Decision || len(r.Reasons) != 1 || r.Reasons[0] != "api/alice-read::policy0" {
		t.Fatalf("a stored permit must take effect at once: %+v", r)
	}

	// The bundle served to node agents carries the stored policy.
	code, body = call(t, env.as(t, "spiffe://omega.local/node/agent"), "GET", env.srv.URL+"/v1/policy/bundle", nil)
	if code != http.StatusOK {
		t.Fatalf("bundle: %d %s", code, body)
	}
	var bundle policy.Bundle
	if err := json.Unmarshal(body, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Policies["api/alice-read"] != alicePermit || bundle.Policies["p.cedar"] != filePolicy {
		t.Fatalf("bundle policies: %v", bundle.Policies)
	}
	local := policy.New()
	if err := local.LoadBundle(bundle); err != nil {
		t.Fatalf("a local PDP must load the bundle: %v", err)
	}
	if lr, _ := local.Evaluate(policy.EvalRequest{Subject: policy.Entity{Type: "Spiffe", ID: alice}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"}}); !lr.Decision {
		t.Fatal("the local PDP must decide with the stored policy")
	}

	// list shows the file read-only and the stored policy without text.
	code, body = call(t, root, "GET", base, nil)
	var list struct{ Items []api.PolicyView }
	if code != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 2 {
		t.Fatalf("list: %d %s", code, body)
	}
	if list.Items[0].ID != "p.cedar" || list.Items[0].Source != api.PolicySourceFile || list.Items[1].ID != "alice-read" || list.Items[1].Text != "" {
		t.Fatalf("list items: %+v", list.Items)
	}
	code, body = call(t, root, "GET", base+"/p.cedar", nil)
	if code != http.StatusOK || !strings.Contains(string(body), "file-deny") {
		t.Fatalf("get file: %d %s", code, body)
	}
	if code, _ := call(t, root, "DELETE", base+"/p.cedar", nil); code != http.StatusConflict {
		t.Fatalf("a file is read-only: %d", code)
	}
	if code, _ := call(t, root, "PUT", base+"/p.cedar", api.PolicyRequest{Text: alicePermit}); code != http.StatusConflict {
		t.Fatalf("a file is read-only: %d", code)
	}

	// Updates are conditional.
	if code, _ := call(t, root, "PUT", base+"/alice-read", api.PolicyRequest{Text: alicePermit2}); code != http.StatusPreconditionRequired {
		t.Fatalf("update without If-Match: %d", code)
	}
	if code, _, _ := callH(t, root, "PUT", base+"/alice-read", api.PolicyRequest{Text: alicePermit2}, map[string]string{"If-Match": `"9-x"`}); code != http.StatusPreconditionFailed {
		t.Fatalf("stale If-Match: %d", code)
	}
	if code, _, _ := callH(t, root, "PUT", base+"/alice-read", api.PolicyRequest{Text: "nope"}, map[string]string{"If-Match": created.ETag}); code != http.StatusBadRequest {
		t.Fatalf("invalid update: %d", code)
	}
	if code, _, _ := callH(t, root, "PUT", base+"/alice-read", api.PolicyRequest{ID: "other", Text: alicePermit2}, map[string]string{"If-Match": created.ETag}); code != http.StatusBadRequest {
		t.Fatalf("mismatched id: %d", code)
	}
	if code, _, _ := callH(t, b, "PUT", base+"/alice-read", api.PolicyRequest{Text: alicePermit2}, map[string]string{"If-Match": created.ETag}); code != http.StatusForbidden {
		t.Fatalf("bob update: %d", code)
	}
	if code, _, _ := callH(t, root, "PUT", base+"/ghost", api.PolicyRequest{Text: alicePermit2}, map[string]string{"If-Match": "*"}); code != http.StatusNotFound {
		t.Fatalf("update of a missing policy: %d", code)
	}
	code, h, body = callH(t, root, "PUT", base+"/alice-read", api.PolicyRequest{Text: alicePermit2}, map[string]string{"If-Match": created.ETag})
	var updated api.PolicyView
	if code != http.StatusOK || json.Unmarshal(body, &updated) != nil || updated.Version != 2 || h.Get("ETag") == created.ETag {
		t.Fatalf("update: %d %s", code, body)
	}
	if !evalAs(t, env, root, alice, "write").Decision {
		t.Fatal("the updated policy must take effect")
	}

	// Deletes honour If-Match when given.
	if code, _, _ := callH(t, root, "DELETE", base+"/alice-read", nil, map[string]string{"If-Match": created.ETag}); code != http.StatusPreconditionFailed {
		t.Fatalf("stale delete: %d", code)
	}
	if code, _, _ := callH(t, root, "DELETE", base+"/alice-read", nil, map[string]string{"If-Match": updated.ETag}); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if code, _ := call(t, root, "DELETE", base+"/alice-read", nil); code != http.StatusPreconditionRequired {
		t.Fatalf("delete without If-Match: %d", code)
	}
	if code, _, _ := callH(t, root, "DELETE", base+"/alice-read", nil, map[string]string{"If-Match": "*"}); code != http.StatusNotFound {
		t.Fatalf("second delete: %d", code)
	}
	if evalAs(t, env, root, alice, "read").Decision {
		t.Fatal("the deleted policy must stop applying")
	}

	// Every write is in the chain with its digests, and so is the refusal.
	events, err := env.store.ListAudit(t.Context(), 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]map[string]any{}
	var denied bool
	for _, ev := range events {
		if !strings.HasPrefix(ev.Kind, "policy.") {
			continue
		}
		if ev.Decision == "deny" && ev.Actor == bob {
			denied = true
			continue
		}
		var p map[string]any
		_ = json.Unmarshal(ev.Payload, &p)
		if ev.Actor != rootAdmin || ev.Subject != "alice-read" {
			t.Errorf("%s row: actor %q subject %q", ev.Kind, ev.Actor, ev.Subject)
		}
		got[ev.Kind] = p
	}
	if !denied {
		t.Error("a refused write must be audited")
	}
	d1, d2 := storage.PolicyDigest(alicePermit), storage.PolicyDigest(alicePermit2)
	if got["policy.create"]["old_digest"] != "" || got["policy.create"]["new_digest"] != d1 ||
		got["policy.update"]["old_digest"] != d1 || got["policy.update"]["new_digest"] != d2 ||
		got["policy.delete"]["old_digest"] != d2 || got["policy.delete"]["new_digest"] != "" {
		t.Fatalf("audit payloads: %v", got)
	}
	if v, err := env.store.VerifyAudit(t.Context(), nil); err != nil || !v.Valid {
		t.Fatalf("chain: %+v %v", v, err)
	}
}

func TestPolicyAPIValidate(t *testing.T) {
	env := newDomainEnv(t, filePolicy)
	root := env.as(t, rootAdmin)
	u := env.srv.URL + "/v1/policies/validate"

	code, body := call(t, root, "POST", u, api.PolicyRequest{ID: "two", Text: alicePermit + "\n@id(\"named\") " + alicePermit2})
	var v api.PolicyValidation
	if code != http.StatusOK || json.Unmarshal(body, &v) != nil || !v.Valid || len(v.PolicyIDs) != 2 || v.PolicyIDs[0] != "api/two::named" || v.PolicyIDs[1] != "api/two::policy0" {
		t.Fatalf("validate: %d %s", code, body)
	}
	if code, _ := call(t, root, "POST", u, api.PolicyRequest{Text: alicePermit}); code != http.StatusOK {
		t.Fatalf("validate without id: %d", code)
	}
	for name, text := range map[string]string{
		"syntax": "permit (",
		"empty":  "// only a comment",
		"huge":   strings.Repeat(" ", api.MaxPolicyBytes+1) + alicePermit,
	} {
		if code, body := call(t, root, "POST", u, api.PolicyRequest{ID: "x", Text: text}); code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, code, body)
		}
	}
	// Validation changes nothing.
	if ps, _ := env.store.ListPolicies(t.Context()); len(ps) != 0 {
		t.Fatalf("validate stored %v", ps)
	}
}

func TestPolicyAPIRefusesIDCollisionWithFile(t *testing.T) {
	env := newDomainEnv(t, `@id("api/x::policy0") `+alicePermit)
	root := env.as(t, rootAdmin)
	code, body := call(t, root, "POST", env.srv.URL+"/v1/policies", api.PolicyRequest{ID: "x", Text: alicePermit})
	if code != http.StatusBadRequest || !strings.Contains(string(body), "--policy-dir") {
		t.Fatalf("collision: %d %s", code, body)
	}
}

func TestPolicyAPINeedsRequireAuth(t *testing.T) {
	srv, store := newTestServerWithStore(t, policy.New())
	code, body := call(t, srv.Client(), "POST", srv.URL+"/v1/policies", api.PolicyRequest{ID: "x", Text: alicePermit})
	if code != http.StatusForbidden || !strings.Contains(string(body), "--require-auth") {
		t.Fatalf("open server: %d %s", code, body)
	}
	if ps, _ := store.ListPolicies(t.Context()); len(ps) != 0 {
		t.Fatal("nothing may be stored")
	}
	// Reads stay open, like the rest of the read API without it.
	if code, _ := call(t, srv.Client(), "GET", srv.URL+"/v1/policies", nil); code != http.StatusOK {
		t.Fatalf("list: %d", code)
	}
	if code, _ := call(t, srv.Client(), "GET", srv.URL+"/v1/policies/nope", nil); code != http.StatusNotFound {
		t.Fatalf("get: %d", code)
	}
	if code, _ := call(t, srv.Client(), "GET", srv.URL+"/v1/policies/Not.Valid", nil); code != http.StatusNotFound {
		t.Fatalf("get invalid: %d", code)
	}
}

func TestPolicyAPIAuditFailureStoresNothing(t *testing.T) {
	env := newDomainEnv(t, "")
	env.api.FailAuditForTest("policy.create")
	root := env.as(t, rootAdmin)
	if code, _ := call(t, root, "POST", env.srv.URL+"/v1/policies", api.PolicyRequest{ID: "x", Text: alicePermit}); code != http.StatusInternalServerError {
		t.Fatalf("create: %d", code)
	}
	if ps, _ := env.store.ListPolicies(t.Context()); len(ps) != 0 {
		t.Fatal("a change whose audit row failed must not commit")
	}
}

func TestStoredPolicySetThatDoesNotLoad(t *testing.T) {
	env := newDomainEnv(t, "")
	root := env.as(t, rootAdmin)
	if code, body := call(t, root, "POST", env.srv.URL+"/v1/policies", api.PolicyRequest{ID: "good", Text: alicePermit}); code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	// A row the API would refuse, written behind its back.
	if _, _, err := env.store.ChangePolicy(t.Context(), "bad", func(*storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
		return &storage.Policy{Text: "permit ("}, storage.AuditEvent{Kind: "test"}, nil
	}); err != nil {
		t.Fatal(err)
	}
	err := env.api.RefreshDirectory(context.Background())
	if !errors.Is(err, api.ErrStoredPolicySet) {
		t.Fatalf("refresh: %v", err)
	}
	if !evalAs(t, env, root, alice, "read").Decision {
		t.Fatal("the last set that loaded must stay in force")
	}
	env.api.MarkDirectoryStale()
	if code, _ := call(t, root, "POST", env.srv.URL+"/access/v1/evaluation", policy.EvalRequest{
		Subject: policy.Entity{Type: "Spiffe", ID: alice}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"},
	}); code != http.StatusServiceUnavailable {
		t.Fatalf("a stale set must fail closed: %d", code)
	}
	// The API that fixes the set stays up, and fixing it recovers.
	if code, _, body := callH(t, root, "DELETE", env.srv.URL+"/v1/policies/bad", nil, map[string]string{"If-Match": "*"}); code != http.StatusNoContent {
		t.Fatalf("delete bad: %d %s", code, body)
	}
	if !evalAs(t, env, root, alice, "read").Decision {
		t.Fatal("evaluation must recover once the set loads")
	}
}

func TestPolicyAPIOnAFollower(t *testing.T) {
	env := newDomainEnv(t, "")
	root := env.as(t, rootAdmin)
	if code, body := call(t, root, "POST", env.srv.URL+"/v1/policies", api.PolicyRequest{ID: "x", Text: alicePermit}); code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	env.store.SetLeaderForTest(true, false)
	if code, h, _ := callH(t, root, "DELETE", env.srv.URL+"/v1/policies/x", nil, nil); code != http.StatusServiceUnavailable || h.Get("Retry-After") == "" {
		t.Fatalf("follower write: %d", code)
	}
	// A follower serves reads and picks the stored set up on refresh.
	if code, _ := call(t, root, "GET", env.srv.URL+"/v1/policies/x", nil); code != http.StatusOK {
		t.Fatalf("follower read: %d", code)
	}
	if code, _ := call(t, root, "POST", env.srv.URL+"/v1/policies/validate", api.PolicyRequest{Text: alicePermit}); code != http.StatusOK {
		t.Fatalf("follower validate: %d", code)
	}
}

func TestStoredPoliciesReachAnotherReplica(t *testing.T) {
	env := newDomainEnv(t, "")
	root := env.as(t, rootAdmin)
	ca, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	pdp := policy.New()
	replica := api.NewServer(env.store, ca, pdp)
	req := policy.EvalRequest{Subject: policy.Entity{Type: "Spiffe", ID: alice}, Action: policy.Action{Name: "read"}, Resource: policy.Entity{Type: "Doc", ID: "d"}}
	decision := func() bool {
		t.Helper()
		if err := replica.RefreshDirectory(t.Context()); err != nil {
			t.Fatal(err)
		}
		r, err := pdp.Evaluate(req)
		if err != nil {
			t.Fatal(err)
		}
		return r.Decision
	}
	if decision() {
		t.Fatal("nothing stored yet")
	}
	if code, body := call(t, root, "POST", env.srv.URL+"/v1/policies", api.PolicyRequest{ID: "x", Text: alicePermit}); code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}
	if !decision() {
		t.Fatal("the replica must pick the stored policy up on its next sync")
	}
	if code, _, _ := callH(t, root, "DELETE", env.srv.URL+"/v1/policies/x", nil, map[string]string{"If-Match": "*"}); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}
	if decision() {
		t.Fatal("the replica must drop the deleted policy on its next sync")
	}
}

func TestStoredPoliciesMustMatchTheAuditChain(t *testing.T) {
	behind := func(t *testing.T, env *domainEnv, id, text string) {
		t.Helper()
		if _, _, err := env.store.ChangePolicy(t.Context(), id, func(*storage.Policy) (*storage.Policy, storage.AuditEvent, error) {
			if text == "" {
				return nil, storage.AuditEvent{Kind: "test"}, nil
			}
			return &storage.Policy{Text: text}, storage.AuditEvent{Kind: "test"}, nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	for name, tamper := range map[string]func(*testing.T, *domainEnv){
		"edited":  func(t *testing.T, env *domainEnv) { behind(t, env, "x", alicePermit2) },
		"removed": func(t *testing.T, env *domainEnv) { behind(t, env, "x", "") },
		"added":   func(t *testing.T, env *domainEnv) { behind(t, env, "y", alicePermit2) },
	} {
		t.Run(name, func(t *testing.T) {
			env := newDomainEnv(t, "")
			root := env.as(t, rootAdmin)
			if code, body := call(t, root, "POST", env.srv.URL+"/v1/policies", api.PolicyRequest{ID: "x", Text: alicePermit}); code != http.StatusCreated {
				t.Fatalf("create: %d %s", code, body)
			}
			if err := env.api.RefreshDirectory(t.Context()); err != nil {
				t.Fatalf("an untouched set must load: %v", err)
			}
			tamper(t, env)
			if err := env.api.RefreshDirectory(t.Context()); !errors.Is(err, api.ErrStoredPolicySet) {
				t.Fatalf("a set the audit chain does not account for must not load: %v", err)
			}
			if r := evalAs(t, env, root, alice, "read"); !r.Decision || evalAs(t, env, root, alice, "write").Decision {
				t.Fatal("the last set that loaded must stay in force")
			}
		})
	}
}
