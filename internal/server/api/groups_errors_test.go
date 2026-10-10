package api_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/storage"
)

func TestDomainAndGroupErrorPaths(t *testing.T) {
	env := newDomainEnv(t, "")
	base := env.srv.URL + "/v1/domains"
	root := env.as(t, rootAdmin)
	if code, body := call(t, root, "POST", base, storage.Domain{Name: "media"}); code != http.StatusCreated {
		t.Fatalf("setup: %d %s", code, body)
	}
	g := base + "/media/groups"
	if code, body := call(t, root, "POST", g, api.GroupRequest{Name: "oncall"}); code != http.StatusCreated {
		t.Fatalf("setup group: %d %s", code, body)
	}

	cases := []struct {
		name   string
		method string
		url    string
		body   any
		want   int
	}{
		{"create with a bad admin id", "POST", base, storage.Domain{Name: "sports", Admins: []string{"not-spiffe"}}, http.StatusBadRequest},
		{"create twice", "POST", base, storage.Domain{Name: "media"}, http.StatusConflict},
		{"delete a missing domain", "DELETE", base + "/nope", nil, http.StatusNotFound},
		{"grant on a missing domain", "POST", base + "/nope/admins", api.DomainAdminRequest{Principal: alice}, http.StatusNotFound},
		{"grant a non-SPIFFE principal", "POST", base + "/media/admins", api.DomainAdminRequest{Principal: "alice"}, http.StatusBadRequest},
		{"revoke without a principal", "DELETE", base + "/media/admins", nil, http.StatusBadRequest},
		{"revoke a non-admin", "DELETE", base + "/media/admins?principal=spiffe://omega.local/x", nil, http.StatusNotFound},
		{"group in a missing domain", "POST", base + "/nope/groups", api.GroupRequest{Name: "x"}, http.StatusNotFound},
		{"duplicate group", "POST", g, api.GroupRequest{Name: "oncall"}, http.StatusConflict},
		{"get a missing group", "GET", g + "/nope", nil, http.StatusNotFound},
		{"bad group name in the path", "GET", g + "/Bad_", nil, http.StatusBadRequest},
		{"delete a missing group", "DELETE", g + "/nope", nil, http.StatusNotFound},
		{"member of a missing group", "PUT", g + "/nope/members", api.GroupMemberRequest{Principal: alice}, http.StatusNotFound},
		{"non-SPIFFE member", "PUT", g + "/oncall/members", api.GroupMemberRequest{Principal: "alice"}, http.StatusBadRequest},
		{"remove without a principal", "DELETE", g + "/oncall/members", nil, http.StatusBadRequest},
		{"remove a non-member", "DELETE", g + "/oncall/members?principal=spiffe://omega.local/x", nil, http.StatusNotFound},
		{"remove from a missing group", "DELETE", g + "/nope/members?principal=spiffe://omega.local/x", nil, http.StatusNotFound},
		{"expiry beyond the maximum lifetime", "PUT", g + "/oncall/members", api.GroupMemberRequest{Principal: alice, ExpiresAt: time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)}, http.StatusBadRequest},
		{"list groups", "GET", g, nil, http.StatusOK},
		{"update a member's expiry", "PUT", g + "/oncall/members", api.GroupMemberRequest{Principal: alice}, http.StatusOK},
		{"re-put the same member", "PUT", g + "/oncall/members", api.GroupMemberRequest{Principal: alice}, http.StatusOK},
		{"delete the group with its members", "DELETE", g + "/oncall", nil, http.StatusNoContent},
		{"the domain can now be deleted", "DELETE", base + "/media", nil, http.StatusNoContent},
	}
	for _, tc := range cases {
		if code, body := call(t, root, tc.method, tc.url, tc.body); code != tc.want {
			t.Errorf("%s: got %d %s, want %d", tc.name, code, body, tc.want)
		}
	}
}
