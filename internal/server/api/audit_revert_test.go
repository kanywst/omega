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

// TestUnrecordedChangesAreReverted checks every domain write is undone,
// and answered 500, when its audit row cannot be written.
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

	s.FailAuditForTest("domain.delete")
	must("DELETE", base+"/media", nil, http.StatusInternalServerError)
	if d, err := store.GetDomain(ctx, "media"); err != nil || len(d.Admins) != 1 {
		t.Errorf("an unrecorded delete must restore the domain with its admins: %+v %v", d, err)
	}
}

func TestDomainErrorPaths(t *testing.T) {
	env := newDomainEnv(t, "")
	base := env.srv.URL + "/v1/domains"
	root := env.as(t, rootAdmin)
	if code, body := call(t, root, "POST", base, storage.Domain{Name: "media"}); code != http.StatusCreated {
		t.Fatalf("setup: %d %s", code, body)
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
		{"delete the domain", "DELETE", base + "/media", nil, http.StatusNoContent},
	}
	for _, tc := range cases {
		if code, body := call(t, root, tc.method, tc.url, tc.body); code != tc.want {
			t.Errorf("%s: got %d %s, want %d", tc.name, code, body, tc.want)
		}
	}
}
