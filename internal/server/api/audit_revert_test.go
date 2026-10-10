package api_test

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// TestUnrecordedChangesAreReverted checks every domain and group write
// is undone, and answered 500, when its audit row cannot be written.
func TestUnrecordedChangesAreReverted(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	s := api.NewServer(store, ca, policy.New())
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	c := srv.Client()
	base := srv.URL + "/v1/domains"
	ctx := t.Context()

	must := func(method, u string, body any, want int) {
		t.Helper()
		if code, out := call(t, c, method, u, body); code != want {
			t.Fatalf("%s %s: %d %s, want %d", method, u, code, out, want)
		}
	}
	must("POST", base, storage.Domain{Name: "media", Admins: []string{alice}}, http.StatusCreated)
	must("POST", base+"/media/groups", api.GroupRequest{Name: "oncall"}, http.StatusCreated)
	must("PUT", base+"/media/groups/oncall/members", api.GroupMemberRequest{Principal: bob}, http.StatusOK)

	s.FailAuditForTest("domain.create")
	must("POST", base, storage.Domain{Name: "sports"}, http.StatusInternalServerError)
	if _, err := store.GetDomain(ctx, "sports"); err == nil {
		t.Error("an unrecorded create must be undone")
	}

	s.FailAuditForTest("domain.admin.add")
	must("POST", base+"/media/admins", api.DomainAdminRequest{Principal: bob}, http.StatusInternalServerError)
	must("POST", base+"/media/admins", api.DomainAdminRequest{Principal: alice}, http.StatusInternalServerError)
	if d, _ := store.GetDomain(ctx, "media"); len(d.Admins) != 1 || d.Admins[0] != alice {
		t.Errorf("a new grant is undone and an existing one kept: %v", d.Admins)
	}

	s.FailAuditForTest("domain.admin.remove")
	must("DELETE", base+"/media/admins?principal="+alice, nil, http.StatusInternalServerError)
	if d, _ := store.GetDomain(ctx, "media"); len(d.Admins) != 1 {
		t.Errorf("an unrecorded revoke must be undone: %v", d.Admins)
	}

	s.FailAuditForTest("group.member.add")
	must("PUT", base+"/media/groups/oncall/members", api.GroupMemberRequest{Principal: alice}, http.StatusInternalServerError)
	if g, _ := store.GetGroup(ctx, "media", "oncall"); len(g.Members) != 1 {
		t.Errorf("an unrecorded membership must be undone: %+v", g.Members)
	}

	s.FailAuditForTest("group.member.remove")
	must("DELETE", base+"/media/groups/oncall/members?principal="+bob, nil, http.StatusInternalServerError)
	if g, _ := store.GetGroup(ctx, "media", "oncall"); len(g.Members) != 1 {
		t.Errorf("an unrecorded removal must be undone: %+v", g.Members)
	}

	s.FailAuditForTest("group.delete")
	must("DELETE", base+"/media/groups/oncall", nil, http.StatusInternalServerError)
	if g, err := store.GetGroup(ctx, "media", "oncall"); err != nil || len(g.Members) != 1 {
		t.Errorf("an unrecorded group delete must restore it with its members: %+v %v", g, err)
	}

	s.FailAuditForTest("group.create")
	must("POST", base+"/media/groups", api.GroupRequest{Name: "pagers"}, http.StatusInternalServerError)
	if _, err := store.GetGroup(ctx, "media", "pagers"); err == nil {
		t.Error("an unrecorded group create must be undone")
	}

	must("DELETE", base+"/media/groups/oncall", nil, http.StatusNoContent)
	s.FailAuditForTest("domain.delete")
	must("DELETE", base+"/media", nil, http.StatusInternalServerError)
	if d, err := store.GetDomain(ctx, "media"); err != nil || len(d.Admins) != 1 {
		t.Errorf("an unrecorded delete must restore the domain with its admins: %+v %v", d, err)
	}
}
