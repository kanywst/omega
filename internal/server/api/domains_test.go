package api_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

const (
	rootAdmin = "spiffe://omega.local/platform/root"
	alice     = "spiffe://omega.local/people/alice"
	bob       = "spiffe://omega.local/people/bob"
)

type domainEnv struct {
	srv   *httptest.Server
	tca   *testCA
	store *storage.Store
}

func newDomainEnv(t *testing.T, cedarSrc string, recorders ...string) *domainEnv {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	pdp := policy.New()
	if cedarSrc != "" {
		pdir := t.TempDir()
		if err := os.WriteFile(filepath.Join(pdir, "p.cedar"), []byte(cedarSrc), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := pdp.LoadDir(pdir); err != nil {
			t.Fatal(err)
		}
	}
	tca := newTestCA(t)
	srv := httptest.NewUnstartedServer(api.NewServer(store, ca, pdp).
		WithRequireAuth(true).
		WithDomainRootAdmins([]string{rootAdmin}).
		WithDecisionRecorders(recorders).
		Handler())
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tca.issue(t, "omega-server", "", []net.IP{net.ParseIP("127.0.0.1")})},
		ClientCAs:    tca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return &domainEnv{srv: srv, tca: tca, store: store}
}

func (e *domainEnv) as(t *testing.T, id string) *http.Client {
	t.Helper()
	cert := e.tca.issue(t, "client", id, nil)
	return clientWith(e.tca, &cert)
}

func call(t *testing.T, c *http.Client, method, u string, body any) (int, []byte) {
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
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, u, err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func TestDomainDelegation(t *testing.T) {
	env := newDomainEnv(t, "")
	base := env.srv.URL + "/v1/domains"
	root, a, b := env.as(t, rootAdmin), env.as(t, alice), env.as(t, bob)

	steps := []struct {
		name   string
		client *http.Client
		method string
		url    string
		body   any
		want   int
	}{
		{"non-root cannot create a top-level domain", a, "POST", base, storage.Domain{Name: "media"}, http.StatusForbidden},
		{"root creates media", root, "POST", base, storage.Domain{Name: "media"}, http.StatusCreated},
		{"alice is not yet an admin of media", a, "POST", base, storage.Domain{Name: "media.news"}, http.StatusForbidden},
		{"root delegates media to alice", root, "POST", base + "/media/admins", api.DomainAdminRequest{Principal: alice}, http.StatusOK},
		{"alice creates a subdomain", a, "POST", base, storage.Domain{Name: "media.news"}, http.StatusCreated},
		{"alice creates a grandchild through an ancestor grant", a, "POST", base, storage.Domain{Name: "media.news.web"}, http.StatusCreated},
		{"bob is not an admin anywhere", b, "POST", base, storage.Domain{Name: "media.sports"}, http.StatusForbidden},
		{"bob cannot grant himself admin", b, "POST", base + "/media/admins", api.DomainAdminRequest{Principal: bob}, http.StatusForbidden},
		{"a parent with children cannot be deleted", root, "DELETE", base + "/media.news", nil, http.StatusConflict},
		{"alice deletes a leaf under her domain", a, "DELETE", base + "/media.news.web", nil, http.StatusNoContent},
		{"alice cannot delete the domain she was given", a, "DELETE", base + "/media", nil, http.StatusForbidden},
		{"an orphan is rejected", root, "POST", base, storage.Domain{Name: "ghost.town"}, http.StatusBadRequest},
		{"an invalid name is rejected", root, "POST", base, storage.Domain{Name: "Media"}, http.StatusBadRequest},
		{"root revokes alice", root, "DELETE", base + "/media/admins?principal=" + url.QueryEscape(alice), nil, http.StatusOK},
		{"revoked alice can no longer create under media", a, "POST", base, storage.Domain{Name: "media.sports"}, http.StatusForbidden},
		{"her own grant on media.news is separate and survives", a, "POST", base, storage.Domain{Name: "media.news.api"}, http.StatusCreated},
	}
	for _, st := range steps {
		code, body := call(t, st.client, st.method, st.url, st.body)
		if code != st.want {
			t.Fatalf("%s: got %d %s, want %d", st.name, code, body, st.want)
		}
	}

	// The creator administers what it created when no admins are given.
	_, body := call(t, a, "GET", base+"/media.news", nil)
	var d storage.Domain
	if err := json.Unmarshal(body, &d); err != nil || len(d.Admins) != 1 || d.Admins[0] != alice {
		t.Errorf("creator should be the admin of media.news: %s", body)
	}
}

func TestDomainHierarchyReachesPolicy(t *testing.T) {
	env := newDomainEnv(t, `permit (principal in Domain::"media", action == Action::"read", resource);`)
	root := env.as(t, rootAdmin)
	base := env.srv.URL + "/v1/domains"
	eval := func() bool {
		code, body := call(t, root, "POST", env.srv.URL+"/access/v1/evaluation", policy.EvalRequest{
			Subject:  policy.Entity{Type: "Spiffe", ID: "spiffe://omega.local/media/news/web"},
			Action:   policy.Action{Name: "read"},
			Resource: policy.Entity{Type: "Doc", ID: "d"},
		})
		if code != http.StatusOK {
			t.Fatalf("evaluate: %d %s", code, body)
		}
		var r policy.EvalResponse
		_ = json.Unmarshal(body, &r)
		return r.Decision
	}
	if eval() {
		t.Fatal("no domains yet, so nothing is in Domain::\"media\"")
	}
	for _, n := range []string{"media", "media.news"} {
		if code, body := call(t, root, "POST", base, storage.Domain{Name: n}); code != http.StatusCreated {
			t.Fatalf("create %s: %d %s", n, code, body)
		}
	}
	if !eval() {
		t.Fatal("a workload under media/news is in Domain::\"media\" once the domains exist")
	}

	events, err := env.store.ListAudit(t.Context(), 0, 10)
	if err != nil {
		t.Fatal(err)
	}
	var creates int
	for _, ev := range events {
		if ev.Kind == "domain.create" && ev.Actor == rootAdmin {
			creates++
		}
	}
	if creates != 2 {
		t.Errorf("domain.create rows with the caller as actor: %d", creates)
	}
}

func TestDomainHardening(t *testing.T) {
	env := newDomainEnv(t, "")
	base := env.srv.URL + "/v1/domains"
	root, b := env.as(t, rootAdmin), env.as(t, bob)
	if code, body := call(t, root, "POST", base, storage.Domain{Name: "media", Admins: []string{alice}}); code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, body)
	}

	// A denied write is audited.
	if code, _ := call(t, b, "POST", base+"/media/admins", api.DomainAdminRequest{Principal: bob}); code != http.StatusForbidden {
		t.Fatalf("bob grant: %d", code)
	}
	events, _ := env.store.ListAudit(t.Context(), 0, 20)
	var denied bool
	for _, ev := range events {
		if ev.Kind == "domain.admin.add" && ev.Decision == "deny" && ev.Actor == bob && ev.Subject == "media" {
			denied = true
		}
	}
	if !denied {
		t.Error("the refused grant must be audited")
	}

	// An invalid path name is rejected before any lookup.
	if code, _ := call(t, root, "DELETE", base+"/Not..Valid", nil); code != http.StatusBadRequest {
		t.Errorf("invalid name: %d", code)
	}

	// Admin lists are only shown to authenticated callers.
	_, body := call(t, b, "GET", base+"/media", nil)
	if !bytes.Contains(body, []byte(alice)) {
		t.Errorf("an authenticated caller sees the admins: %s", body)
	}
}

func TestDomainAdminsHiddenFromAnonymousReads(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.CreateDomain(t.Context(), storage.Domain{Name: "media", Admins: []string{alice}}); err != nil {
		t.Fatal(err)
	}
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	tca := newTestCA(t)
	srv := httptest.NewUnstartedServer(api.NewServer(store, ca, policy.New()).WithRequireAuth(true).Handler())
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{tca.issue(t, "omega-server", "", []net.IP{net.ParseIP("127.0.0.1")})},
		ClientCAs:    tca.pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	for _, path := range []string{"/v1/domains/media", "/v1/domains"} {
		_, body := call(t, clientWith(tca, nil), "GET", srv.URL+path, nil)
		if bytes.Contains(body, []byte(alice)) {
			t.Errorf("%s leaks admins to an anonymous caller: %s", path, body)
		}
	}
}

func TestPolicyFailsClosedWhenDirectoryIsStale(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatal(err)
	}
	s := api.NewServer(store, ca, policy.New())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go s.RunDirectorySync(ctx, 20*time.Millisecond)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	eval := func() int {
		resp, err := http.Post(srv.URL+"/access/v1/evaluation", "application/json",
			strings.NewReader(`{"subject":{"type":"User","id":"u"},"action":{"name":"read"},"resource":{"type":"Doc","id":"d"}}`))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	time.Sleep(60 * time.Millisecond)
	if code := eval(); code != http.StatusOK {
		t.Fatalf("fresh directory: status %d", code)
	}
	// Reloads now fail, so after three intervals evaluation must stop.
	_ = store.Close()
	time.Sleep(150 * time.Millisecond)
	if code := eval(); code != http.StatusServiceUnavailable {
		t.Fatalf("stale directory: status %d, want 503", code)
	}
}
