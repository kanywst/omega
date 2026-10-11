package api_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

const scimToken = "0123456789abcdef0123456789abcdef"

type scimEnv struct {
	srv   *httptest.Server
	api   *api.Server
	store *storage.Store
	pdp   *policy.Engine
	base  string
}

func newSCIMEnv(t *testing.T) *scimEnv {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateDomain(t.Context(), storage.Domain{Name: "people"}); err != nil {
		t.Fatal(err)
	}
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	pdir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pdir, "p.cedar"), []byte(`permit (principal in Group::"people:engineering", action == Action::"deploy", resource);`), 0o644); err != nil {
		t.Fatal(err)
	}
	pdp := policy.New()
	if err := pdp.LoadDir(pdir); err != nil {
		t.Fatal(err)
	}
	s := api.NewServer(store, ca, pdp).WithSCIM([]api.SCIMConfig{{
		Name: "corp", Domain: "people", TokenHash: sha256.Sum256([]byte(scimToken)),
		Template: "spiffe://omega.local/humans/{idp}/{externalId}",
	}})
	if err := s.RefreshDirectory(t.Context()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &scimEnv{srv: srv, api: s, store: store, pdp: pdp, base: srv.URL + "/scim/v2/corp"}
}

func (e *scimEnv) do(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	return e.doToken(t, scimToken, method, path, body)
}

func (e *scimEnv) doToken(t *testing.T, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		r = strings.NewReader(b)
	default:
		raw, _ := json.Marshal(b)
		r = bytes.NewReader(raw)
	}
	u := path
	if !strings.HasPrefix(path, "http") {
		u = e.base + path
	}
	req, _ := http.NewRequest(method, u, r)
	req.Header.Set("Content-Type", "application/scim+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *scimEnv) mayDeploy(t *testing.T, principal string) bool {
	t.Helper()
	r, err := e.pdp.Evaluate(policy.EvalRequest{
		Subject: policy.Entity{Type: "Spiffe", ID: principal}, Action: policy.Action{Name: "deploy"}, Resource: policy.Entity{Type: "App", ID: "a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return r.Decision
}

func patchOp(ops ...map[string]any) map[string]any {
	return map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}, "Operations": ops}
}

func TestSCIMAuthentication(t *testing.T) {
	e := newSCIMEnv(t)
	for name, tok := range map[string]string{"no token": "", "wrong token": "nope"} {
		if code, _ := e.doToken(t, tok, "GET", "/Users", nil); code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := e.do(t, "GET", e.srv.URL+"/scim/v2/other/Users", nil); code != http.StatusNotFound {
		t.Errorf("unknown provider: %d", code)
	}
	for _, p := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/Schemas"} {
		if code, _ := e.do(t, "GET", p, nil); code != http.StatusOK {
			t.Errorf("%s: %d", p, code)
		}
	}
}

func TestSCIMProvisioningDrivesPolicy(t *testing.T) {
	e := newSCIMEnv(t)
	alicePrincipal := "spiffe://omega.local/humans/corp/00u1"

	code, alice := e.do(t, "POST", "/Users", map[string]any{"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:User"}, "userName": "alice@corp.example", "externalId": "00u1", "active": true})
	if code != http.StatusCreated {
		t.Fatalf("create alice: %d %v", code, alice)
	}
	aliceID := alice["id"].(string)
	if code, body := e.do(t, "POST", "/Users", map[string]any{"userName": "ALICE@corp.example", "externalId": "00u9"}); code != http.StatusConflict || body["scimType"] != "uniqueness" {
		t.Errorf("duplicate userName: %d %v", code, body)
	}
	if code, _ := e.do(t, "POST", "/Users", map[string]any{"userName": "noext"}); code != http.StatusBadRequest {
		t.Errorf("a user without externalId cannot be mapped: %d", code)
	}
	_, bob := e.do(t, "POST", "/Users", map[string]any{"userName": "bob", "externalId": "00u2"})
	bobID := bob["id"].(string)

	code, grp := e.do(t, "POST", "/Groups", map[string]any{"displayName": "Engineering", "members": []map[string]string{{"value": aliceID}}})
	if code != http.StatusCreated || grp["omegaGroup"] != "people:engineering" {
		t.Fatalf("create group: %d %v", code, grp)
	}
	gid := grp["id"].(string)
	if !e.mayDeploy(t, alicePrincipal) {
		t.Fatal("alice is in people:engineering")
	}

	// Okta-style deactivation (a string boolean, no path) takes her out.
	if code, body := e.do(t, "PATCH", "/Users/"+aliceID, patchOp(map[string]any{"op": "Replace", "value": map[string]any{"active": "False"}})); code != http.StatusOK || body["active"] != false {
		t.Fatalf("deactivate: %d %v", code, body)
	}
	if e.mayDeploy(t, alicePrincipal) {
		t.Fatal("a deactivated user is in no group")
	}
	if code, _ := e.do(t, "PATCH", "/Users/"+aliceID, patchOp(map[string]any{"op": "replace", "path": "active", "value": true})); code != http.StatusOK {
		t.Fatal("reactivate")
	}
	if !e.mayDeploy(t, alicePrincipal) {
		t.Fatal("reactivated")
	}

	// Entra-style member add, then removal by filter path.
	if code, body := e.do(t, "PATCH", "/Groups/"+gid, patchOp(map[string]any{"op": "Add", "path": "members", "value": []map[string]string{{"value": bobID}}})); code != http.StatusOK || len(body["members"].([]any)) != 2 {
		t.Fatalf("add bob: %d %v", code, body)
	}
	if !e.mayDeploy(t, "spiffe://omega.local/humans/corp/00u2") {
		t.Fatal("bob was added")
	}
	if code, _ := e.do(t, "PATCH", "/Groups/"+gid, patchOp(map[string]any{"op": "remove", "path": `members[value eq "` + bobID + `"]`})); code != http.StatusOK {
		t.Fatal("remove bob")
	}
	if e.mayDeploy(t, "spiffe://omega.local/humans/corp/00u2") {
		t.Fatal("bob was removed")
	}
	if code, _ := e.do(t, "PATCH", "/Groups/"+gid, patchOp(map[string]any{"op": "add", "path": "members", "value": []map[string]string{{"value": "missing"}}})); code != http.StatusBadRequest {
		t.Errorf("unknown member: %d", code)
	}

	// The Omega API cannot change a provisioned group.
	if code, _ := e.do(t, "PUT", e.srv.URL+"/v1/domains/people/groups/engineering/members", map[string]any{"principal": "spiffe://omega.local/x"}); code != http.StatusConflict {
		t.Errorf("omega API on a SCIM group: %d", code)
	}

	// Filters and paging.
	if code, list := e.do(t, "GET", "/Users?filter="+url.QueryEscape(`userName eq "Alice@Corp.example"`), nil); code != http.StatusOK || list["totalResults"].(float64) != 1 {
		t.Errorf("filter: %d %v", code, list)
	}
	if code, list := e.do(t, "GET", "/Users?startIndex=2&count=1", nil); code != http.StatusOK || list["totalResults"].(float64) != 2 || len(list["Resources"].([]any)) != 1 {
		t.Errorf("paging: %d %v", code, list)
	}
	if code, _ := e.do(t, "GET", "/Users?filter="+url.QueryEscape(`emails co "x"`), nil); code != http.StatusBadRequest {
		t.Errorf("unsupported filter: %d", code)
	}
	if code, list := e.do(t, "GET", "/Groups?excludedAttributes=members&filter="+url.QueryEscape(`displayName eq "Engineering"`), nil); code != http.StatusOK || list["totalResults"].(float64) != 1 {
		t.Errorf("group filter: %d %v", code, list)
	}

	// A rename through PUT renames the Omega group.
	if code, body := e.do(t, "PUT", "/Groups/"+gid, map[string]any{"displayName": "Platform Eng", "members": []map[string]string{{"value": aliceID}}}); code != http.StatusOK || body["omegaGroup"] != "people:platform-eng" {
		t.Fatalf("rename: %d %v", code, body)
	}
	if e.mayDeploy(t, alicePrincipal) {
		t.Fatal("the policy names people:engineering, which no longer exists")
	}

	// Deletes.
	if code, _ := e.do(t, "DELETE", "/Users/"+bobID, nil); code != http.StatusNoContent {
		t.Fatal("delete bob")
	}
	if code, _ := e.do(t, "DELETE", "/Groups/"+gid, nil); code != http.StatusNoContent {
		t.Fatal("delete group")
	}
	if code, _ := e.do(t, "GET", "/Groups/"+gid, nil); code != http.StatusNotFound {
		t.Fatal("deleted group")
	}

	events, _ := e.store.ListAudit(t.Context(), 0, 100)
	kinds := map[string]int{}
	for _, ev := range events {
		if ev.Actor == "scim:corp" {
			kinds[ev.Kind]++
		}
	}
	for _, k := range []string{"scim.user.create", "scim.user.patch", "scim.group.create", "scim.group.patch", "scim.group.replace", "scim.user.delete", "scim.group.delete"} {
		if kinds[k] == 0 {
			t.Errorf("no %s audit row: %v", k, kinds)
		}
	}
}

func TestSCIMChangeIsNotKeptWhenItCannotBeRecorded(t *testing.T) {
	e := newSCIMEnv(t)
	e.api.FailSCIMForTest()
	if code, _ := e.do(t, "POST", "/Users", map[string]any{"userName": "alice", "externalId": "00u1"}); code != http.StatusInternalServerError {
		t.Fatalf("create: %d", code)
	}
	if code, list := e.do(t, "GET", "/Users", nil); code != http.StatusOK || list["totalResults"].(float64) != 0 {
		t.Fatalf("the unrecorded user must not exist: %v", list)
	}
}

func TestSCIMRejectsMalformedRequests(t *testing.T) {
	e := newSCIMEnv(t)
	_, u := e.do(t, "POST", "/Users", map[string]any{"userName": "alice", "externalId": "00u1"})
	id := u["id"].(string)
	for name, tc := range map[string]struct {
		method, path string
		body         any
		want         int
	}{
		"bad json":            {"POST", "/Users", "{", http.StatusBadRequest},
		"patch without ops":   {"PATCH", "/Users/" + id, map[string]any{"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"}}, http.StatusBadRequest},
		"unknown op":          {"PATCH", "/Users/" + id, patchOp(map[string]any{"op": "move", "path": "active", "value": true}), http.StatusBadRequest},
		"bad active":          {"PATCH", "/Users/" + id, patchOp(map[string]any{"op": "replace", "path": "active", "value": "maybe"}), http.StatusBadRequest},
		"remove userName":     {"PATCH", "/Users/" + id, patchOp(map[string]any{"op": "remove", "path": "userName"}), http.StatusBadRequest},
		"invalid SPIFFE path": {"POST", "/Users", map[string]any{"userName": "x", "externalId": "has space"}, http.StatusBadRequest},
		"unusable group name": {"POST", "/Groups", map[string]any{"displayName": "!!!"}, http.StatusBadRequest},
		"missing user":        {"GET", "/Users/nope", nil, http.StatusNotFound},
		"bad startIndex":      {"GET", "/Users?startIndex=x", nil, http.StatusBadRequest},
	} {
		if code, body := e.do(t, tc.method, tc.path, tc.body); code != tc.want {
			t.Errorf("%s: %d %v, want %d", name, code, body, tc.want)
		}
	}
}

func TestGroupNameFromDisplay(t *testing.T) {
	for in, want := range map[string]string{"Engineering": "engineering", "Platform  Eng!": "platform-eng", "a_b": "a-b", strings.Repeat("x", 80): strings.Repeat("x", 63)} {
		if got, err := api.GroupNameFromDisplay(in); err != nil || got != want {
			t.Errorf("%q: %q %v", in, got, err)
		}
	}
}

func TestSCIMUserAndGroupOperations(t *testing.T) {
	e := newSCIMEnv(t)
	_, a := e.do(t, "POST", "/Users", map[string]any{"userName": "alice", "externalId": "00u1", "displayName": "Alice"})
	aID := a["id"].(string)
	_, b := e.do(t, "POST", "/Users", map[string]any{"userName": "bob", "externalId": "00u2"})
	bID := b["id"].(string)
	_, g := e.do(t, "POST", "/Groups", map[string]any{"displayName": "Engineering", "externalId": "g1", "members": []map[string]string{{"value": aID}}})
	gID := g["id"].(string)

	// PUT with a new externalId moves the memberships to the new SPIFFE ID.
	if code, body := e.do(t, "PUT", "/Users/"+aID, map[string]any{"userName": "alice", "externalId": "00u1-new"}); code != http.StatusOK || body["displayName"] != nil {
		t.Fatalf("replace user: %d %v", code, body)
	}
	if !e.mayDeploy(t, "spiffe://omega.local/humans/corp/00u1-new") || e.mayDeploy(t, "spiffe://omega.local/humans/corp/00u1") {
		t.Fatal("membership must follow the new SPIFFE ID")
	}
	userOps := []struct {
		op   map[string]any
		want int
	}{
		{map[string]any{"op": "replace", "path": "userName", "value": "alice2"}, http.StatusOK},
		{map[string]any{"op": "replace", "path": "displayName", "value": "A"}, http.StatusOK},
		{map[string]any{"op": "remove", "path": "displayName"}, http.StatusOK},
		{map[string]any{"op": "add", "path": "name.givenName", "value": "ignored"}, http.StatusOK},
		{map[string]any{"op": "replace", "path": "externalId", "value": "00u1"}, http.StatusOK},
		{map[string]any{"op": "remove", "path": "externalId"}, http.StatusBadRequest},
		{map[string]any{"op": "remove", "path": "active"}, http.StatusBadRequest},
		{map[string]any{"op": "replace", "path": "userName", "value": 7}, http.StatusBadRequest},
		{map[string]any{"op": "remove"}, http.StatusBadRequest},
		{map[string]any{"op": "replace", "value": map[string]any{"userName": "bob"}}, http.StatusConflict},
	}
	for _, tc := range userOps {
		if code, body := e.do(t, "PATCH", "/Users/"+aID, patchOp(tc.op)); code != tc.want {
			t.Errorf("%v: %d %v, want %d", tc.op, code, body, tc.want)
		}
	}
	if code, list := e.do(t, "GET", "/Users?filter="+url.QueryEscape(`externalId eq "00u1"`), nil); code != http.StatusOK || list["totalResults"].(float64) != 1 {
		t.Errorf("filter by externalId: %d %v", code, list)
	}

	groupOps := []struct {
		op      map[string]any
		want    int
		members int
	}{
		{map[string]any{"op": "replace", "path": "members", "value": []map[string]string{{"value": bID}}}, http.StatusOK, 1},
		{map[string]any{"op": "add", "value": map[string]any{"members": []map[string]string{{"value": aID}}}}, http.StatusOK, 2},
		{map[string]any{"op": "remove", "path": "members", "value": []map[string]string{{"value": aID}}}, http.StatusOK, 1},
		{map[string]any{"op": "remove", "path": "members"}, http.StatusOK, 0},
		{map[string]any{"op": "replace", "path": "displayName", "value": "Eng Ops"}, http.StatusOK, 0},
		{map[string]any{"op": "replace", "path": "externalId", "value": "g2"}, http.StatusOK, 0},
		{map[string]any{"op": "remove", "path": "externalId"}, http.StatusOK, 0},
		{map[string]any{"op": "replace", "value": map[string]any{"displayName": "Engineering"}}, http.StatusOK, 0},
		{map[string]any{"op": "replace", "path": "members", "value": "nope"}, http.StatusBadRequest, 0},
		{map[string]any{"op": "replace", "path": "displayName", "value": "!!"}, http.StatusBadRequest, 0},
		{map[string]any{"op": "replace", "path": "owner", "value": "x"}, http.StatusBadRequest, 0},
		{map[string]any{"op": "add", "value": "x"}, http.StatusBadRequest, 0},
	}
	for _, tc := range groupOps {
		code, body := e.do(t, "PATCH", "/Groups/"+gID, patchOp(tc.op))
		if code != tc.want {
			t.Errorf("%v: %d %v, want %d", tc.op, code, body, tc.want)
			continue
		}
		if code == http.StatusOK && len(body["members"].([]any)) != tc.members {
			t.Errorf("%v: members %v", tc.op, body["members"])
		}
	}
	if code, body := e.do(t, "GET", "/Groups/"+gID, nil); code != http.StatusOK || body["omegaGroup"] != "people:engineering" || body["externalId"] != nil {
		t.Errorf("after patches: %d %v", code, body)
	}
	if code, _ := e.do(t, "PATCH", "/Groups/"+gID+"?excludedAttributes=members", patchOp(map[string]any{"op": "add", "path": "members", "value": []map[string]string{{"value": aID}}})); code != http.StatusOK {
		t.Errorf("patch with excludedAttributes: %d", code)
	}
	if code, _ := e.do(t, "PUT", "/Groups/"+gID, map[string]any{"displayName": "??"}); code != http.StatusBadRequest {
		t.Errorf("put with an unusable name: %d", code)
	}
	if code, _ := e.do(t, "PUT", "/Groups/missing", map[string]any{"displayName": "x"}); code != http.StatusNotFound {
		t.Errorf("put a missing group: %d", code)
	}
	if code, _ := e.do(t, "POST", "/Groups", map[string]any{"displayName": "!"}); code != http.StatusBadRequest {
		t.Errorf("create with an unusable name: %d", code)
	}
	if code, _ := e.do(t, "POST", "/Groups", map[string]any{"displayName": "Engineering"}); code != http.StatusConflict {
		t.Errorf("duplicate group: %d", code)
	}
	if code, _ := e.do(t, "GET", "/Groups?filter="+url.QueryEscape(`members eq "x"`), nil); code != http.StatusBadRequest {
		t.Errorf("unsupported group filter: %d", code)
	}
	if code, _ := e.do(t, "DELETE", e.srv.URL+"/v1/domains/people/groups/engineering", nil); code != http.StatusConflict {
		t.Errorf("omega API delete of a SCIM group: %d", code)
	}
	for _, p := range []string{"/Users/missing", "/Groups/missing"} {
		if code, _ := e.do(t, "DELETE", p, nil); code != http.StatusNotFound {
			t.Errorf("delete %s: %d", p, code)
		}
	}
	if code, _ := e.do(t, "PUT", "/Users/"+aID, "{"); code != http.StatusBadRequest {
		t.Errorf("put bad json: %d", code)
	}
}

func TestSCIMGroupInAMissingDomain(t *testing.T) {
	e := newSCIMEnv(t)
	if err := e.store.DeleteDomain(t.Context(), "people"); err != nil {
		t.Fatal(err)
	}
	if code, body := e.do(t, "POST", "/Groups", map[string]any{"displayName": "Engineering"}); code != http.StatusInternalServerError || !strings.Contains(body["detail"].(string), "does not exist") {
		t.Fatalf("missing domain: %d %v", code, body)
	}
}
