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
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

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
	// The server projects the directory, trust domain included, before
	// it serves.
	if err := s.RefreshDirectory(context.Background()); err != nil {
		t.Fatal(err)
	}
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

	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, TrustDomain: "omega.local", HTTPClient: cp.client})
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

	stale := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, TrustDomain: "omega.local", HTTPClient: cp.client, SyncInterval: 10 * time.Millisecond, MaxAge: 50 * time.Millisecond})
	if err := stale.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := stale.Evaluate(evalReq("spiffe://omega.local/x", "read")); err == nil {
		t.Fatal("a bundle older than max-age must not be used")
	}

	full := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, TrustDomain: "omega.local", HTTPClient: cp.client, BufferSize: 2})
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
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, TrustDomain: "omega.local", HTTPClient: cp.client})
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
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, TrustDomain: "omega.local", HTTPClient: cp.client})
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
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, TrustDomain: "omega.local", HTTPClient: cp.client})
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

func TestLocalPDPOfAnUnlistedAgentNeverDecides(t *testing.T) {
	cp := newControlPlane(t, `permit (principal, action, resource);`)
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, TrustDomain: "omega.local", HTTPClient: cp.clientFor("spiffe://omega.local/media/web")})
	if err := p.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a workload that is not a decision recorder must not get the bundle: %v", err)
	}
	if _, err := p.Evaluate(evalReq("spiffe://omega.local/x", "read")); err == nil {
		t.Fatal("without a bundle the PDP must not decide")
	}
}

func TestLocalPDPRefusesABundleForAnotherTrustDomain(t *testing.T) {
	cp := newControlPlane(t, `permit (principal, action, resource);`)
	p := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.client, TrustDomain: "other.example"})
	if err := p.Sync(context.Background()); err == nil || !strings.Contains(err.Error(), "trust domain") {
		t.Fatalf("a bundle for another trust domain must be refused: %v", err)
	}
	ok := localpdp.New(localpdp.Config{ServerURL: cp.srv.URL, HTTPClient: cp.client, TrustDomain: "omega.local"})
	if err := ok.Sync(context.Background()); err != nil {
		t.Fatalf("own trust domain: %v", err)
	}
}

// fakeRecorder serves a real bundle and answers decision batches with
// the scripted responses, recording how many decisions each batch held.
func fakeRecorder(t *testing.T, replies ...func(w http.ResponseWriter, n int)) (*httptest.Server, *[]int) {
	t.Helper()
	b, err := testBundle()
	if err != nil {
		t.Fatal(err)
	}
	var sizes []int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(b)
			return
		}
		var batch api.DecisionBatch
		_ = json.NewDecoder(r.Body).Decode(&batch)
		mu.Lock()
		sizes = append(sizes, len(batch.Decisions))
		i := len(sizes) - 1
		mu.Unlock()
		if i < len(replies) {
			replies[i](w, len(batch.Decisions))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &sizes
}

func TestLocalPDPDropsWhatWasRecordedBeforeRetrying(t *testing.T) {
	srv, sizes := fakeRecorder(t, func(w http.ResponseWriter, _ int) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"disk full","recorded":2}`))
	})
	ctx := context.Background()
	p := localpdp.New(localpdp.Config{ServerURL: srv.URL, TrustDomain: "omega.local"})
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := p.Evaluate(evalReq("spiffe://omega.local/x", "read")); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Flush(ctx); err == nil {
		t.Fatal("a failed batch is an error")
	}
	if _, _, pending := p.Status(); pending != 1 {
		t.Fatalf("the two recorded decisions must be dropped: %d pending", pending)
	}
	if err := p.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if got := *sizes; len(got) != 2 || got[1] != 1 {
		t.Fatalf("retry must resend only the unrecorded decision: %v", got)
	}
}

func TestLocalPDPIsolatesARejectedDecisionAndReportsTheLoss(t *testing.T) {
	var (
		mu       sync.Mutex
		recorded []string
		dropped  int
	)
	b, err := testBundle()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(b)
			return
		}
		var batch api.DecisionBatch
		_ = json.NewDecoder(r.Body).Decode(&batch)
		for _, d := range batch.Decisions {
			if d.Request.Subject.ID == "bad" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		mu.Lock()
		dropped += batch.Dropped
		for _, d := range batch.Decisions {
			recorded = append(recorded, d.Request.Subject.ID)
		}
		mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	p := localpdp.New(localpdp.Config{ServerURL: srv.URL, TrustDomain: "omega.local"})
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"a", "b", "bad", "c", "d"} {
		if _, err := p.Evaluate(evalReq(id, "read")); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if _, _, pending := p.Status(); pending != 0 {
		t.Fatalf("a rejected decision must not block the queue: %d pending", pending)
	}
	if len(recorded) != 4 || dropped != 1 {
		t.Fatalf("every other decision is recorded and the loss is reported: %v, dropped %d", recorded, dropped)
	}
}

func TestLocalPDPBufferIsAHardCap(t *testing.T) {
	srv, _ := fakeRecorder(t)
	p := localpdp.New(localpdp.Config{ServerURL: srv.URL, TrustDomain: "omega.local", BufferSize: 5})
	if err := p.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = p.Evaluate(evalReq("spiffe://omega.local/x", "read"))
		}()
	}
	wg.Wait()
	if _, _, pending := p.Status(); pending > 5 {
		t.Fatalf("buffer overrun: %d pending", pending)
	}
}

func TestLocalPDPStopsDroppingWhenEverythingIsRejected(t *testing.T) {
	srv, _ := fakeRecorder(t, func() []func(http.ResponseWriter, int) {
		var out []func(http.ResponseWriter, int)
		for range 100 {
			out = append(out, func(w http.ResponseWriter, _ int) { w.WriteHeader(http.StatusBadRequest) })
		}
		return out
	}()...)
	ctx := context.Background()
	p := localpdp.New(localpdp.Config{ServerURL: srv.URL, TrustDomain: "omega.local"})
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := p.Evaluate(evalReq("spiffe://omega.local/x", "read")); err != nil {
			t.Fatal(err)
		}
	}
	// Whether it stops at the streak limit or at the rejected loss
	// report, it must stop: never empty the queue unrecorded.
	for range 5 {
		if err := p.Flush(ctx); err == nil {
			t.Fatal("a control plane rejecting everything must make Flush fail")
		}
	}
	if _, _, pending := p.Status(); pending < 10-3 {
		t.Fatalf("at most 3 decisions may be dropped; %d left", pending)
	}
}

func TestLocalPDPLossReportKeepsItsIDAcrossRetries(t *testing.T) {
	var (
		mu      sync.Mutex
		reports []api.DecisionBatch
	)
	b, err := testBundle()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_ = json.NewEncoder(w).Encode(b)
			return
		}
		var batch api.DecisionBatch
		_ = json.NewDecoder(r.Body).Decode(&batch)
		if len(batch.Decisions) > 0 && batch.Decisions[0].Request.Subject.ID == "bad" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if batch.Dropped > 0 {
			mu.Lock()
			reports = append(reports, batch)
			first := len(reports) == 1
			mu.Unlock()
			if first {
				w.WriteHeader(http.StatusBadGateway)
			}
		}
	}))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	p := localpdp.New(localpdp.Config{ServerURL: srv.URL, TrustDomain: "omega.local"})
	if err := p.Sync(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Evaluate(evalReq("bad", "read")); err != nil {
		t.Fatal(err)
	}
	if err := p.Flush(ctx); err == nil {
		t.Fatal("the first loss report fails")
	}
	if err := p.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(reports) != 2 || reports[0].LossID == "" || reports[0].LossID != reports[1].LossID || len(reports[1].DroppedIDs) != 1 || len(reports[1].DroppedDigests) != 1 {
		t.Fatalf("a retried loss report must keep its id and name the dropped decision: %+v", reports)
	}
}

// testBundle is an empty policy bundle for omega.local.
func testBundle() (policy.Bundle, error) {
	e := policy.New()
	e.SetDirectory(policy.Directory{TrustDomain: spiffeid.RequireTrustDomainFromString("omega.local")})
	return e.Bundle()
}

func TestLocalPDPNeedsATrustDomain(t *testing.T) {
	srv, _ := fakeRecorder(t)
	p := localpdp.New(localpdp.Config{ServerURL: srv.URL})
	if err := p.Sync(context.Background()); err == nil {
		t.Fatal("without a trust domain no bundle may be loaded")
	}
}
