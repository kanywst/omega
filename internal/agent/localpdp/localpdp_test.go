package localpdp_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/agent/localpdp"
	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

type controlPlane struct {
	srv    *httptest.Server
	store  *storage.Store
	pdp    *policy.Engine
	api    *api.Server
	dir    string
	client *http.Client
	// clientFor returns a client presenting an SVID for id.
	clientFor func(id string) *http.Client
}

const agentID = "spiffe://omega.local/nodes/n1"

func newControlPlane(t *testing.T, cedarSrc string) *controlPlane {
	t.Helper()
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
	pdir := filepath.Join(dir, "policy")
	if err := os.MkdirAll(pdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pdir, "p.cedar"), []byte(cedarSrc), 0o644); err != nil {
		t.Fatal(err)
	}
	pdp := policy.New()
	if err := pdp.LoadDir(pdir); err != nil {
		t.Fatal(err)
	}
	tca, tcaKey, pool := newTestCA(t)
	s := api.NewServer(store, ca, pdp).WithRequireAuth(true).WithDecisionRecorders([]string{"spiffe://omega.local/nodes/"})
	srv := httptest.NewUnstartedServer(s.Handler())
	srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{issue(t, tca, tcaKey, "", net.ParseIP("127.0.0.1"))}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	clientFor := func(id string) *http.Client {
		cert := issue(t, tca, tcaKey, id, nil)
		return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, Certificates: []tls.Certificate{cert}}}}
	}
	return &controlPlane{srv: srv, store: store, pdp: pdp, api: s, dir: pdir, client: clientFor(agentID), clientFor: clientFor}
}

func evalReq(id, action string) policy.EvalRequest {
	return policy.EvalRequest{
		Subject:  policy.Entity{Type: "Spiffe", ID: id},
		Action:   policy.Action{Name: action},
		Resource: policy.Entity{Type: "Doc", ID: "d"},
	}
}

func TestLocalPDPDecidesLikeTheControlPlaneAndAuditsCentrally(t *testing.T) {
	cp := newControlPlane(t, `permit (principal in Domain::"media", action == Action::"read", resource);`)
	ctx := context.Background()
	if _, err := cp.store.CreateDomain(ctx, storage.Domain{Name: "media"}); err != nil {
		t.Fatal(err)
	}
	if err := cp.api.RefreshDirectory(ctx); err != nil {
		t.Fatal(err)
	}

	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.client})
	if _, err := p.Evaluate(evalReq("spiffe://omega.local/media/web", "read")); err == nil {
		t.Fatal("before the first sync the local PDP must refuse to decide")
	}
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	rev, _, _ := p.Status()

	allow, err := p.Evaluate(evalReq("spiffe://omega.local/media/web", "read"))
	if err != nil || !allow.Decision {
		t.Fatalf("media workload: %+v %v", allow, err)
	}
	deny, err := p.Evaluate(evalReq("spiffe://omega.local/sports/web", "read"))
	if err != nil || deny.Decision {
		t.Fatalf("sports workload: %+v %v", deny, err)
	}

	// An unchanged bundle is a 304 and keeps the revision.
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if again, _, _ := p.Status(); again != rev {
		t.Fatalf("revision changed without a change: %s -> %s", rev, again)
	}

	if err := p.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, pending := p.Status(); pending != 0 {
		t.Fatalf("pending after flush: %d", pending)
	}
	events, err := cp.store.ListAudit(ctx, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	var local int
	for _, ev := range events {
		if ev.Kind == "access.evaluate.local" && ev.Actor == agentID && strings.Contains(string(ev.Payload), `"source":"local"`) && strings.Contains(string(ev.Payload), rev) {
			local++
		}
	}
	if local != 2 {
		t.Fatalf("local decisions in the central audit chain: %d, want 2", local)
	}

	// A policy change reaches the node on the next sync.
	if err := os.WriteFile(filepath.Join(cp.dir, "p.cedar"), []byte(`forbid (principal, action, resource);`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := cp.pdp.LoadDir(cp.dir); err != nil {
		t.Fatal(err)
	}
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := p.Evaluate(evalReq("spiffe://omega.local/media/web", "read")); r.Decision {
		t.Fatal("the new policy must apply after sync")
	}
}

func TestLocalPDPFailsClosed(t *testing.T) {
	cp := newControlPlane(t, `permit (principal, action, resource);`)
	ctx := context.Background()

	stale := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.client, SyncInterval: 10 * time.Millisecond, MaxAge: 50 * time.Millisecond})
	if err := stale.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := stale.Evaluate(evalReq("spiffe://omega.local/x", "read")); err == nil {
		t.Fatal("a bundle older than max-age must not be used")
	}

	full := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.client, BufferSize: 2})
	if err := full.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := full.Evaluate(evalReq("spiffe://omega.local/x", "read")); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := full.Evaluate(evalReq("spiffe://omega.local/x", "read")); err == nil {
		t.Fatal("with the decision buffer full the PDP must refuse rather than decide unrecorded")
	}
	if err := full.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := full.Evaluate(evalReq("spiffe://omega.local/x", "read")); err != nil {
		t.Fatalf("after a flush it decides again: %v", err)
	}

	// Over HTTP the refusal is a 503.
	srv := httptest.NewServer(stale.Handler())
	t.Cleanup(srv.Close)
	body, _ := json.Marshal(evalReq("spiffe://omega.local/x", "read"))
	resp, err := http.Post(srv.URL+"/access/v1/evaluation", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("stale over HTTP: %d", resp.StatusCode)
	}
}

func TestLocalPDPKeepsDecisionsWhenTheControlPlaneIsDown(t *testing.T) {
	cp := newControlPlane(t, `permit (principal, action, resource);`)
	ctx := context.Background()
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.client})
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Evaluate(evalReq("spiffe://omega.local/x", "read")); err != nil {
		t.Fatal(err)
	}
	cp.srv.Close()
	if err := p.Flush(ctx); err == nil {
		t.Fatal("flush to a closed control plane must fail")
	}
	if _, _, pending := p.Status(); pending != 1 {
		t.Fatalf("a failed flush keeps the decision: %d pending", pending)
	}
}

func TestLocalPDPRefusesOversizedRequests(t *testing.T) {
	cp := newControlPlane(t, `permit (principal, action, resource);`)
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.client})
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	big := `{"subject":{"type":"Spiffe","id":"x"},"action":{"name":"read"},"resource":{"type":"Doc","id":"d"},"context":{"pad":"` + strings.Repeat("a", localpdp.MaxRequestBytes) + `"}}`
	resp, err := http.Post(srv.URL+"/access/v1/evaluation", "application/json", strings.NewReader(big))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request: %d", resp.StatusCode)
	}
	if _, _, pending := p.Status(); pending != 0 {
		t.Fatalf("an oversized request must not be decided: %d pending", pending)
	}
}

func TestLocalPDPSplitsLargeBacklogs(t *testing.T) {
	cp := newControlPlane(t, `permit (principal, action, resource);`)
	ctx := context.Background()
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.client})
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	// About 40 KiB each, so the backlog is several MiB: far more than
	// one request body the control plane accepts.
	pad := strings.Repeat("a", 40<<10)
	const n = 60
	for range n {
		req := evalReq("spiffe://omega.local/x", "read")
		req.Context = map[string]any{"pad": pad}
		if _, err := p.Evaluate(req); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Flush(ctx); err != nil {
		t.Fatalf("a large backlog must drain in batches: %v", err)
	}
	if _, _, pending := p.Status(); pending != 0 {
		t.Fatalf("pending after flush: %d", pending)
	}
}

func TestLocalPDPFromAnUnlistedAgentStaysQueued(t *testing.T) {
	cp := newControlPlane(t, `permit (principal, action, resource);`)
	ctx := context.Background()
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.clientFor("spiffe://omega.local/media/web")})
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Evaluate(evalReq("spiffe://omega.local/x", "read")); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(ctx); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a workload that is not a decision recorder must be refused: %v", err)
	}
	if _, _, pending := p.Status(); pending != 1 {
		t.Fatalf("refused decisions stay queued, so the PDP eventually fails closed: %d", pending)
	}
}
