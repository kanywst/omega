package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

func TestGroupsDelegationAndPolicy(t *testing.T) {
	env := newDomainEnv(t, `permit (principal in Group::"media:oncall", action == Action::"page", resource);`)
	base := env.srv.URL + "/v1/domains"
	root, a, b := env.as(t, rootAdmin), env.as(t, alice), env.as(t, bob)
	groups := base + "/media/groups"
	members := groups + "/oncall/members"

	steps := []struct {
		name   string
		client *http.Client
		method string
		url    string
		body   any
		want   int
	}{
		{"root creates media for alice", root, "POST", base, storage.Domain{Name: "media", Admins: []string{alice}}, http.StatusCreated},
		{"bob cannot create a group in media", b, "POST", groups, api.GroupRequest{Name: "oncall"}, http.StatusForbidden},
		{"alice creates a group in her domain", a, "POST", groups, api.GroupRequest{Name: "oncall"}, http.StatusCreated},
		{"a group needs a valid name", a, "POST", groups, api.GroupRequest{Name: "On Call"}, http.StatusBadRequest},
		{"bob cannot add himself", b, "PUT", members, api.GroupMemberRequest{Principal: bob}, http.StatusForbidden},
		{"alice adds bob", a, "PUT", members, api.GroupMemberRequest{Principal: bob}, http.StatusOK},
		{"expiry in the past is rejected", a, "PUT", members, api.GroupMemberRequest{Principal: bob, ExpiresAt: time.Now().Add(-time.Hour)}, http.StatusBadRequest},
		{"the domain cannot be deleted while it owns groups", root, "DELETE", base + "/media", nil, http.StatusConflict},
	}
	for _, st := range steps {
		if code, body := call(t, st.client, st.method, st.url, st.body); code != st.want {
			t.Fatalf("%s: got %d %s, want %d", st.name, code, body, st.want)
		}
	}

	page := func(id string) bool {
		code, body := call(t, root, "POST", env.srv.URL+"/access/v1/evaluation", policy.EvalRequest{
			Subject:  policy.Entity{Type: "Spiffe", ID: id},
			Action:   policy.Action{Name: "page"},
			Resource: policy.Entity{Type: "Pager", ID: "p"},
		})
		if code != http.StatusOK {
			t.Fatalf("evaluate: %d %s", code, body)
		}
		var r policy.EvalResponse
		_ = json.Unmarshal(body, &r)
		return r.Decision
	}
	if !page(bob) {
		t.Fatal("bob is in media:oncall")
	}
	if page(alice) {
		t.Fatal("alice administers the group but is not in it")
	}

	if code, body := call(t, a, "DELETE", members+"?principal="+url.QueryEscape(bob), nil); code != http.StatusOK {
		t.Fatalf("remove: %d %s", code, body)
	}
	if page(bob) {
		t.Fatal("bob was removed")
	}

	events, _ := env.store.ListAudit(t.Context(), 0, 50)
	kinds := map[string]int{}
	for _, ev := range events {
		kinds[ev.Kind+"/"+ev.Decision]++
	}
	for _, k := range []string{"group.create/ok", "group.create/deny", "group.member.add/ok", "group.member.add/deny", "group.member.remove/ok"} {
		if kinds[k] == 0 {
			t.Errorf("no %s audit row: %v", k, kinds)
		}
	}
}

func TestGroupMembershipExpires(t *testing.T) {
	env := newDomainEnv(t, `permit (principal in Group::"media:oncall", action == Action::"page", resource);`)
	root := env.as(t, rootAdmin)
	base := env.srv.URL + "/v1/domains"
	for _, req := range []struct {
		method, url string
		body        any
	}{
		{"POST", base, storage.Domain{Name: "media"}},
		{"POST", base + "/media/groups", api.GroupRequest{Name: "oncall"}},
		{"PUT", base + "/media/groups/oncall/members", api.GroupMemberRequest{Principal: bob, ExpiresAt: time.Now().Add(1500 * time.Millisecond)}},
	} {
		if code, body := call(t, root, req.method, req.url, req.body); code >= 300 {
			t.Fatalf("%s %s: %d %s", req.method, req.url, code, body)
		}
	}
	eval := func() bool {
		_, body := call(t, root, "POST", env.srv.URL+"/access/v1/evaluation", policy.EvalRequest{
			Subject:  policy.Entity{Type: "Spiffe", ID: bob},
			Action:   policy.Action{Name: "page"},
			Resource: policy.Entity{Type: "Pager", ID: "p"},
		})
		var r policy.EvalResponse
		_ = json.Unmarshal(body, &r)
		return r.Decision
	}
	if !eval() {
		t.Fatal("membership is active before it expires")
	}
	time.Sleep(2 * time.Second)
	if eval() {
		t.Fatal("membership must lapse at expires_at without any refresh")
	}
	_, body := call(t, root, "GET", base+"/media/groups/oncall", nil)
	if !bytes.Contains(body, []byte("expires_at")) {
		t.Errorf("the expiry is visible on the group: %s", body)
	}
}
