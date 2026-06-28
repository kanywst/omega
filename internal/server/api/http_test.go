package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authnv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/attest"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

var b64RawURL = base64.RawURLEncoding

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return newTestServerWithPolicy(t, policy.New())
}

func newTestServerWithPolicy(t *testing.T, pdp *policy.Engine) *httptest.Server {
	t.Helper()
	srv, _ := newTestServerWithStore(t, pdp)
	return srv
}

func newTestServerWithStore(t *testing.T, pdp *policy.Engine) (*httptest.Server, *storage.Store) {
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
	srv := httptest.NewServer(api.NewServer(store, ca, pdp).Handler())
	t.Cleanup(srv.Close)
	return srv, store
}

func TestSpireUpstreamDisablesIssuance(t *testing.T) {
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Borrow a built-in CA's bundle as the "upstream" trust material.
	upstreamCA, err := identity.LoadOrCreate(filepath.Join(dir, "upstream"), "upstream.example")
	if err != nil {
		t.Fatalf("upstream ca: %v", err)
	}
	src, err := identity.NewUpstreamSource("upstream.example", upstreamCA.BundlePEM())
	if err != nil {
		t.Fatalf("NewUpstreamSource: %v", err)
	}

	srv := httptest.NewServer(api.NewServer(store, src, policy.New()).Handler())
	t.Cleanup(srv.Close)

	// Issuance routes report 501 in spire-upstream mode.
	for _, path := range []string{"/v1/svid", "/v1/svid/jwt", "/v1/attest/k8s", "/v1/token/exchange", "/v1/oidc/exchange"} {
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("post %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotImplemented {
			t.Errorf("POST %s status = %d, want 501", path, resp.StatusCode)
		}
	}

	// The upstream trust bundle is still served.
	resp, err := http.Get(srv.URL + "/v1/bundle")
	if err != nil {
		t.Fatalf("get bundle: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/bundle status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != string(upstreamCA.BundlePEM()) {
		t.Fatal("GET /v1/bundle did not serve the upstream bundle")
	}
}

func TestHTTPDomainRoundTrip(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Post(srv.URL+"/v1/domains", "application/json", strings.NewReader(`{"name":"example","description":"hi"}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create status: got %d want 201", resp.StatusCode)
	}

	resp2, err := http.Get(srv.URL + "/v1/domains/example")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("get status: got %d want 200", resp2.StatusCode)
	}
	var d storage.Domain
	if err := json.NewDecoder(resp2.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.Name != "example" || d.Description != "hi" {
		t.Errorf("got %+v", d)
	}

	resp3, err := http.Post(srv.URL+"/v1/domains", "application/json", strings.NewReader(`{"name":"example"}`))
	if err != nil {
		t.Fatalf("dup post: %v", err)
	}
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusConflict {
		t.Fatalf("dup status: got %d want 409", resp3.StatusCode)
	}

	resp4, err := http.Get(srv.URL + "/v1/domains/nope")
	if err != nil {
		t.Fatalf("404 get: %v", err)
	}
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusNotFound {
		t.Fatalf("404 status: got %d want 404", resp4.StatusCode)
	}
}

func TestHTTPSVIDRoundTrip(t *testing.T) {
	srv := newTestServer(t)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(api.IssueSVIDRequest{
		SPIFFEID: "spiffe://omega.local/example/web",
		CSR:      string(csrPEM),
	})
	resp, err := http.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post svid: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("svid status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.IssueSVIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}

	block, _ := pem.Decode([]byte(out.SVID))
	if block == nil {
		t.Fatal("svid pem decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse svid: %v", err)
	}
	if len(cert.URIs) != 1 || cert.URIs[0].String() != "spiffe://omega.local/example/web" {
		t.Errorf("svid URI: %v", cert.URIs)
	}

	caBlock, _ := pem.Decode([]byte(out.Bundle))
	caCert, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("svid does not chain to bundle: %v", err)
	}

	bundleResp, err := http.Get(srv.URL + "/v1/bundle")
	if err != nil {
		t.Fatalf("bundle get: %v", err)
	}
	defer bundleResp.Body.Close()
	if bundleResp.StatusCode != http.StatusOK {
		t.Fatalf("bundle status: %d", bundleResp.StatusCode)
	}
}

func TestHTTPAccessEvaluationAllow(t *testing.T) {
	pdp := policy.New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(`permit (
  principal == Spiffe::"spiffe://omega.local/example/web",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := pdp.LoadDir(dir); err != nil {
		t.Fatalf("load policy: %v", err)
	}
	srv := newTestServerWithPolicy(t, pdp)

	body := []byte(`{
  "subject":  {"type":"Spiffe","id":"spiffe://omega.local/example/web"},
  "action":   {"name":"GET"},
  "resource": {"type":"HttpPath","id":"/api/foo"}
}`)
	resp, err := http.Post(srv.URL+"/access/v1/evaluation", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out policy.EvalResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out.Decision {
		t.Errorf("decision: got false want true (reasons=%v)", out.Reasons)
	}
}

func TestHTTPAccessEvaluationDenyByDefault(t *testing.T) {
	srv := newTestServer(t)
	body := []byte(`{
  "subject":  {"type":"Spiffe","id":"spiffe://omega.local/example/web"},
  "action":   {"name":"GET"},
  "resource": {"type":"HttpPath","id":"/api/foo"}
}`)
	resp, err := http.Post(srv.URL+"/access/v1/evaluation", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: %d", resp.StatusCode)
	}
	var out policy.EvalResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Decision {
		t.Errorf("expected default deny, got allow")
	}
}

func TestHTTPAccessEvaluationsBatch(t *testing.T) {
	pdp := policy.New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(`permit (
  principal == Spiffe::"spiffe://omega.local/example/web",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := pdp.LoadDir(dir); err != nil {
		t.Fatalf("load policy: %v", err)
	}
	srv := newTestServerWithPolicy(t, pdp)

	body := []byte(`{
  "subject": {"type":"Spiffe","id":"spiffe://omega.local/example/web"},
  "action":  {"name":"GET"},
  "evaluations": [
    {"resource": {"type":"HttpPath","id":"/api/foo"}},
    {"resource": {"type":"HttpPath","id":"/api/bar"}},
    {"resource": {"type":"HttpPath","id":"/api/foo"}, "action": {"name":"DELETE"}}
  ]
}`)
	resp, err := http.Post(srv.URL+"/access/v1/evaluations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.BatchEvalResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got := len(out.Evaluations); got != 3 {
		t.Fatalf("evaluations: got %d want 3", got)
	}
	// Order is preserved: foo (allow), bar (deny by default), foo+DELETE (deny).
	if !out.Evaluations[0].Decision {
		t.Errorf("eval[0]: expected allow on /api/foo + GET")
	}
	if out.Evaluations[1].Decision {
		t.Errorf("eval[1]: expected deny on /api/bar (no policy)")
	}
	if out.Evaluations[2].Decision {
		t.Errorf("eval[2]: expected deny on /api/foo + DELETE (action override)")
	}
}

func TestHTTPAccessEvaluationsEmptyArrayReturnsEmptyResponse(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Post(srv.URL+"/access/v1/evaluations", "application/json",
		strings.NewReader(`{"evaluations": []}`))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var out api.BatchEvalResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Evaluations) != 0 {
		t.Errorf("evaluations: got %d want 0", len(out.Evaluations))
	}
}

func TestHTTPAccessEvaluationsRejectsOversizedBatch(t *testing.T) {
	srv := newTestServer(t)
	// One more than the cap. Each sub-request is a complete EvalRequest
	// so this is the cap path specifically, not the validation path.
	n := api.MaxBatchEvaluations + 1
	subs := make([]string, n)
	for i := range subs {
		subs[i] = `{"resource":{"type":"HttpPath","id":"/"}}`
	}
	body := []byte(`{
  "subject": {"type":"Spiffe","id":"spiffe://omega.local/x"},
  "action":  {"name":"GET"},
  "evaluations": [` + strings.Join(subs, ",") + `]
}`)
	resp, err := http.Post(srv.URL+"/access/v1/evaluations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestHTTPAccessEvaluationsRejectsIncompleteSubrequest(t *testing.T) {
	srv := newTestServer(t)
	// No top-level resource and the sole sub-request omits it too -
	// merging cannot produce a complete EvalRequest.
	body := []byte(`{
  "subject": {"type":"Spiffe","id":"spiffe://omega.local/x"},
  "action":  {"name":"GET"},
  "evaluations": [{}]
}`)
	resp, err := http.Post(srv.URL+"/access/v1/evaluations", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestHTTPSearchSubjectFiltersCandidates(t *testing.T) {
	pdp := policy.New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(`permit (
  principal == Spiffe::"spiffe://omega.local/alice",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := pdp.LoadDir(dir); err != nil {
		t.Fatalf("load policy: %v", err)
	}
	srv := newTestServerWithPolicy(t, pdp)

	body := []byte(`{
  "subjects": [
    {"type":"Spiffe","id":"spiffe://omega.local/alice"},
    {"type":"Spiffe","id":"spiffe://omega.local/bob"}
  ],
  "action":   {"name":"GET"},
  "resource": {"type":"HttpPath","id":"/api/foo"}
}`)
	resp, err := http.Post(srv.URL+"/access/v1/search/subject", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.SubjectSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].ID != "spiffe://omega.local/alice" {
		t.Errorf("results: got %v want [alice]", out.Results)
	}
}

func TestHTTPSearchResourceFiltersCandidates(t *testing.T) {
	pdp := policy.New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(`permit (
  principal == Spiffe::"spiffe://omega.local/alice",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := pdp.LoadDir(dir); err != nil {
		t.Fatalf("load policy: %v", err)
	}
	srv := newTestServerWithPolicy(t, pdp)

	body := []byte(`{
  "resources": [
    {"type":"HttpPath","id":"/api/foo"},
    {"type":"HttpPath","id":"/api/bar"}
  ],
  "subject": {"type":"Spiffe","id":"spiffe://omega.local/alice"},
  "action":  {"name":"GET"}
}`)
	resp, err := http.Post(srv.URL+"/access/v1/search/resource", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.ResourceSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].ID != "/api/foo" {
		t.Errorf("results: got %v want [/api/foo]", out.Results)
	}
}

func TestHTTPSearchActionFiltersCandidates(t *testing.T) {
	pdp := policy.New()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.cedar"), []byte(`permit (
  principal == Spiffe::"spiffe://omega.local/alice",
  action == Action::"GET",
  resource == HttpPath::"/api/foo"
);
`), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	if err := pdp.LoadDir(dir); err != nil {
		t.Fatalf("load policy: %v", err)
	}
	srv := newTestServerWithPolicy(t, pdp)

	body := []byte(`{
  "actions":  [{"name":"GET"}, {"name":"DELETE"}],
  "subject":  {"type":"Spiffe","id":"spiffe://omega.local/alice"},
  "resource": {"type":"HttpPath","id":"/api/foo"}
}`)
	resp, err := http.Post(srv.URL+"/access/v1/search/action", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.ActionSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Results) != 1 || out.Results[0].Name != "GET" {
		t.Errorf("results: got %v want [GET]", out.Results)
	}
}

func TestHTTPSearchSubjectRejectsEmptyCandidateList(t *testing.T) {
	srv := newTestServer(t)
	body := []byte(`{"subjects":[],"action":{"name":"GET"},"resource":{"type":"HttpPath","id":"/"}}`)
	resp, err := http.Post(srv.URL+"/access/v1/search/subject", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestHTTPSearchSubjectRejectsOversizedCandidateList(t *testing.T) {
	srv := newTestServer(t)
	n := api.MaxSearchCandidates + 1
	subs := make([]string, n)
	for i := range subs {
		subs[i] = `{"type":"Spiffe","id":"spiffe://omega.local/x"}`
	}
	body := []byte(`{
  "subjects": [` + strings.Join(subs, ",") + `],
  "action":   {"name":"GET"},
  "resource": {"type":"HttpPath","id":"/"}
}`)
	resp, err := http.Post(srv.URL+"/access/v1/search/subject", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestHTTPAccessEvaluationBadRequest(t *testing.T) {
	srv := newTestServer(t)
	body := []byte(`{"subject":{"type":"","id":""},"action":{"name":""},"resource":{"type":"","id":""}}`)
	resp, err := http.Post(srv.URL+"/access/v1/evaluation", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestHTTPAuditCapturesEvents(t *testing.T) {
	srv := newTestServer(t)

	if _, err := http.Post(srv.URL+"/v1/domains", "application/json",
		strings.NewReader(`{"name":"audit-domain"}`)); err != nil {
		t.Fatalf("post domain: %v", err)
	}

	body := []byte(`{
  "subject":  {"type":"Spiffe","id":"spiffe://omega.local/example/web"},
  "action":   {"name":"GET"},
  "resource": {"type":"HttpPath","id":"/api/foo"}
}`)
	if _, err := http.Post(srv.URL+"/access/v1/evaluation", "application/json", bytes.NewReader(body)); err != nil {
		t.Fatalf("post eval: %v", err)
	}

	resp, err := http.Get(srv.URL + "/v1/audit?limit=10")
	if err != nil {
		t.Fatalf("get audit: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("audit status: %d", resp.StatusCode)
	}
	var page struct {
		Items []storage.AuditEvent `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&page); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	if len(page.Items) < 2 {
		t.Fatalf("audit items: got %d want >= 2", len(page.Items))
	}
	kinds := make(map[string]bool)
	for _, ev := range page.Items {
		kinds[ev.Kind] = true
	}
	if !kinds["domain.create"] || !kinds["access.evaluate"] {
		t.Errorf("missing audit kinds: %v", kinds)
	}

	verifyResp, err := http.Get(srv.URL + "/v1/audit/verify")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer verifyResp.Body.Close()
	var verify struct {
		Valid       bool  `json:"valid"`
		FirstBadSeq int64 `json:"first_bad_seq"`
	}
	if err := json.NewDecoder(verifyResp.Body).Decode(&verify); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if !verify.Valid {
		t.Errorf("audit chain invalid at seq %d", verify.FirstBadSeq)
	}
}

// Anchored verification needs both expected_head and expected_count;
// supplying only one must 400 rather than silently running an unanchored
// walk that skips the truncation check the caller asked for.
func TestHTTPAuditVerifyAnchorRequiresBothParams(t *testing.T) {
	srv := newTestServer(t)
	defer srv.Close()
	// Only one of the pair, a non-integer count, and a negative count must
	// all 400 rather than run an unanchored or never-firing truncation check.
	for _, q := range []string{
		"expected_count=5",
		"expected_head=abc123",
		"expected_head=abc123&expected_count=-1",
		"expected_head=abc123&expected_count=nope",
	} {
		resp, err := http.Get(srv.URL + "/v1/audit/verify?" + q)
		if err != nil {
			t.Fatalf("get %s: %v", q, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("verify?%s: got %d want 400", q, resp.StatusCode)
		}
	}
}

func TestHTTPJWTSVIDIssueAndBundle(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(api.IssueJWTSVIDRequest{
		SPIFFEID:   "spiffe://omega.local/example/web",
		Audience:   []string{"https://api.example.com"},
		TTLSeconds: 60,
	})
	resp, err := http.Post(srv.URL+"/v1/svid/jwt", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.IssueJWTSVIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Token == "" || out.SPIFFEID != "spiffe://omega.local/example/web" {
		t.Errorf("bad response: %+v", out)
	}
	if out.KeyID == "" {
		t.Error("missing kid")
	}

	bResp, err := http.Get(srv.URL + "/v1/jwt/bundle")
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	defer bResp.Body.Close()
	if bResp.StatusCode != http.StatusOK {
		t.Fatalf("bundle status: %d", bResp.StatusCode)
	}
	if ct := bResp.Header.Get("Content-Type"); ct != "application/jwk-set+json" {
		t.Errorf("content-type: %q", ct)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.NewDecoder(bResp.Body).Decode(&jwks); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] != out.KeyID {
		t.Errorf("kid mismatch: jwks=%v out=%s", jwks.Keys, out.KeyID)
	}
}

func TestHTTPJWTSVIDBindsToCertThumbprint(t *testing.T) {
	srv := newTestServer(t)

	body, _ := json.Marshal(api.IssueJWTSVIDRequest{
		SPIFFEID:           "spiffe://omega.local/example/web",
		Audience:           []string{"aud"},
		BindCertThumbprint: "AAAA-test-thumbprint",
	})
	resp, err := http.Post(srv.URL+"/v1/svid/jwt", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.IssueJWTSVIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	parts := strings.Split(out.Token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %s", out.Token)
	}
	payload, err := base64DecodeRawURL(parts[1])
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("missing cnf claim: %v", claims)
	}
	if cnf["x5t#S256"] != "AAAA-test-thumbprint" {
		t.Errorf("cnf x5t#S256: got %v want AAAA-test-thumbprint", cnf["x5t#S256"])
	}
}

func base64DecodeRawURL(s string) ([]byte, error) {
	return b64RawURL.DecodeString(s)
}

func TestHTTPJWTSVIDRejectsEmptyAudience(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(api.IssueJWTSVIDRequest{
		SPIFFEID: "spiffe://omega.local/x",
	})
	resp, err := http.Post(srv.URL+"/v1/svid/jwt", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestHTTPSVIDRejectsForeignTrustDomain(t *testing.T) {
	srv := newTestServer(t)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, _ := json.Marshal(api.IssueSVIDRequest{SPIFFEID: "spiffe://other.example/foo", CSR: string(csrPEM)})
	resp, err := http.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

// Followers must reject writes with 503 + Retry-After: 1 so callers
// can transparently retry against the elected leader. Reads (GETs)
// stay open so observability and bundle distribution keep working.
func TestHTTPLeaderGate(t *testing.T) {
	srv, store := newTestServerWithStore(t, policy.New())
	store.SetLeaderForTest(true, false)

	cases := []struct {
		method, path, body string
	}{
		{"POST", "/v1/domains", `{"name":"x"}`},
		{"POST", "/v1/svid", `{"spiffe_id":"spiffe://omega.local/x","csr":""}`},
		{"POST", "/access/v1/evaluation", `{"subject":{"type":"Spiffe","id":"spiffe://omega.local/x"},"action":{"name":"GET"},"resource":{"type":"HttpPath","id":"/"}}`},
		{"POST", "/access/v1/evaluations", `{"subject":{"type":"Spiffe","id":"spiffe://omega.local/x"},"action":{"name":"GET"},"evaluations":[{"resource":{"type":"HttpPath","id":"/a"}}]}`},
		{"POST", "/v1/svid/jwt", `{"spiffe_id":"spiffe://omega.local/x","audience":["a"]}`},
		{"POST", "/v1/attest/k8s", `{"token":"x","csr":""}`},
		{"POST", "/v1/oidc/exchange", `{"idp":"x","id_token":"y","audience":["z"]}`},
	}
	for _, tc := range cases {
		req, _ := http.NewRequest(tc.method, srv.URL+tc.path, strings.NewReader(tc.body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", tc.method, tc.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("%s %s: status got %d want 503", tc.method, tc.path, resp.StatusCode)
		}
		if got := resp.Header.Get("Retry-After"); got != "1" {
			t.Errorf("%s %s: Retry-After got %q want %q", tc.method, tc.path, got, "1")
		}
	}

	// GET endpoints must stay open even on a follower.
	resp, err := http.Get(srv.URL + "/v1/domains")
	if err != nil {
		t.Fatalf("GET /v1/domains: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("GET /v1/domains on follower: got %d want 200", resp.StatusCode)
	}

	// /v1/leader must reflect the simulated state.
	resp, err = http.Get(srv.URL + "/v1/leader")
	if err != nil {
		t.Fatalf("GET /v1/leader: %v", err)
	}
	defer resp.Body.Close()
	var ls struct {
		IsLeader bool `json:"is_leader"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ls); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ls.IsLeader {
		t.Errorf("/v1/leader: got is_leader=true on follower")
	}

	// Promote the store to leader and confirm writes succeed again.
	store.SetLeaderForTest(true, true)
	resp, err = http.Post(srv.URL+"/v1/domains", "application/json", strings.NewReader(`{"name":"after-promotion"}`))
	if err != nil {
		t.Fatalf("post after promotion: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("after promotion: got %d want 201", resp.StatusCode)
	}
}

// newK8sAttestServer builds an httptest.Server whose `/v1/attest/k8s`
// endpoint is wired to a fake K8s clientset that returns the supplied
// TokenReview status. Returns the test server and the same store the
// handler writes audit rows into.
func newK8sAttestServer(t *testing.T, trStatus authnv1.TokenReviewStatus, template string) (*httptest.Server, *storage.Store) {
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
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		tr := action.(k8stesting.CreateAction).GetObject().(*authnv1.TokenReview)
		tr.Status = trStatus
		return true, tr, nil
	})
	attestor := attest.NewK8sAttestor(client, nil)
	srv := httptest.NewServer(
		api.NewServer(store, ca, policy.New()).
			WithK8sAttestor(attestor, template).
			Handler(),
	)
	t.Cleanup(srv.Close)
	return srv, store
}

func TestAttestK8sIssuesSVIDFromValidToken(t *testing.T) {
	srv, _ := newK8sAttestServer(t, authnv1.TokenReviewStatus{
		Authenticated: true,
		User:          authnv1.UserInfo{Username: "system:serviceaccount:apps:web"},
	}, "spiffe://omega.local/k8s/{namespace}/{serviceaccount}")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	body, _ := json.Marshal(api.K8sAttestRequest{Token: "fake.jwt.token", CSR: string(csrPEM)})
	resp, err := http.Post(srv.URL+"/v1/attest/k8s", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
	var out api.K8sAttestResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.SPIFFEID != "spiffe://omega.local/k8s/apps/web" {
		t.Errorf("spiffe_id: got %q", out.SPIFFEID)
	}
	if !strings.Contains(out.SVID, "BEGIN CERTIFICATE") {
		t.Errorf("svid not PEM: %s", out.SVID)
	}
}

func TestAttestK8sReturns401OnUnauthenticatedToken(t *testing.T) {
	srv, _ := newK8sAttestServer(t, authnv1.TokenReviewStatus{
		Authenticated: false,
		Error:         "token expired",
	}, "spiffe://omega.local/k8s/{namespace}/{serviceaccount}")
	body, _ := json.Marshal(api.K8sAttestRequest{Token: "expired", CSR: "irrelevant"})
	resp, err := http.Post(srv.URL+"/v1/attest/k8s", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
}

func TestAttestK8sRejectsTemplateOutOfTrustDomain(t *testing.T) {
	srv, _ := newK8sAttestServer(t, authnv1.TokenReviewStatus{
		Authenticated: true,
		User:          authnv1.UserInfo{Username: "system:serviceaccount:apps:web"},
	}, "spiffe://other.example/k8s/{namespace}/{serviceaccount}")

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, _ := json.Marshal(api.K8sAttestRequest{Token: "ok", CSR: string(csrPEM)})

	resp, err := http.Post(srv.URL+"/v1/attest/k8s", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestAttestK8sReturns502OnApiserverFailure(t *testing.T) {
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
	// Reactor returns a plain error from the Create call - the
	// apiserver was unreachable, no TokenReviewStatus was produced.
	// Handler must answer 502 and NOT write an audit-deny row.
	client := fake.NewSimpleClientset()
	client.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("apiserver unreachable")
	})
	attestor := attest.NewK8sAttestor(client, nil)
	srv := httptest.NewServer(
		api.NewServer(store, ca, policy.New()).
			WithK8sAttestor(attestor, "spiffe://omega.local/k8s/{namespace}/{serviceaccount}").
			Handler(),
	)
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(api.K8sAttestRequest{Token: "x", CSR: "y"})
	resp, err := http.Post(srv.URL+"/v1/attest/k8s", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502", resp.StatusCode)
	}
	events, err := store.ListAudit(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	for _, ev := range events {
		if ev.Kind == "attest.k8s" {
			t.Fatalf("apiserver failure must not produce an attest.k8s audit row, got: %+v", ev)
		}
	}
}

func TestAttestK8sReturns404WhenNotConfigured(t *testing.T) {
	srv := newTestServer(t)
	body, _ := json.Marshal(api.K8sAttestRequest{Token: "x", CSR: ""})
	resp, err := http.Post(srv.URL+"/v1/attest/k8s", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", resp.StatusCode)
	}
}

func TestOIDCDiscoveryReturns404WhenIssuerNotConfigured(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", resp.StatusCode)
	}
}

func TestOIDCDiscoveryReturnsDocumentWhenIssuerConfigured(t *testing.T) {
	const wantIss = "https://omega.example.com"
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.New(identity.Config{
		Kind:        identity.KindDisk,
		TrustDomain: "omega.local",
		Issuer:      wantIss,
		Dir:         filepath.Join(dir, "ca"),
	})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	srv := httptest.NewServer(api.NewServer(store, ca, policy.New()).Handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type: got %q want application/json", got)
	}
	var doc api.OIDCDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Issuer != wantIss {
		t.Errorf("issuer: got %q want %q", doc.Issuer, wantIss)
	}
	if doc.JWKSURI != wantIss+"/v1/jwt/bundle" {
		t.Errorf("jwks_uri: got %q want %q", doc.JWKSURI, wantIss+"/v1/jwt/bundle")
	}
	if got := strings.Join(doc.IDTokenSigningAlgValuesSupported, ","); got != "ES256" {
		t.Errorf("alg: got %q want ES256", got)
	}
}

func TestAuthzenDiscoveryUsesIssuerURLWhenConfigured(t *testing.T) {
	const wantIss = "https://omega.example.com"
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.New(identity.Config{
		Kind:        identity.KindDisk,
		TrustDomain: "omega.local",
		Issuer:      wantIss,
		Dir:         filepath.Join(dir, "ca"),
	})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	srv := httptest.NewServer(api.NewServer(store, ca, policy.New()).Handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/.well-known/authzen-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type: got %q want application/json", got)
	}
	var doc api.AuthzenDiscoveryResponse
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.PolicyDecisionPoint != wantIss {
		t.Errorf("pdp: got %q want %q", doc.PolicyDecisionPoint, wantIss)
	}
	if doc.AccessEvaluationEndpoint != wantIss+"/access/v1/evaluation" {
		t.Errorf("evaluation: got %q", doc.AccessEvaluationEndpoint)
	}
	if doc.AccessEvaluationsEndpoint != wantIss+"/access/v1/evaluations" {
		t.Errorf("evaluations: got %q", doc.AccessEvaluationsEndpoint)
	}
}

func TestSPIFFEBundleReturnsTDFDocument(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/v1/spiffe-bundle")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/json" {
		t.Errorf("content-type: got %q want application/json", got)
	}
	var doc struct {
		Sequence    int64            `json:"spiffe_sequence"`
		RefreshHint int              `json:"spiffe_refresh_hint"`
		Keys        []map[string]any `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if doc.Sequence < 1 {
		t.Errorf("sequence: got %d want >=1", doc.Sequence)
	}
	if doc.RefreshHint != 300 {
		t.Errorf("refresh_hint default: got %d want 300", doc.RefreshHint)
	}
	if len(doc.Keys) < 2 {
		t.Fatalf("keys: got %d entries, want at least one x509-svid and one jwt-svid", len(doc.Keys))
	}
}

func TestAuthzenDiscoveryReturns404WhenIssuerNotConfigured(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/.well-known/authzen-configuration")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", resp.StatusCode)
	}
}

// Every JSON endpoint caps the request body via http.MaxBytesReader, so
// an over-large body is rejected before omega buffers it (memory-
// exhaustion DoS). createDomain stands in for all of them since they
// share the decodeJSONBody helper.
func TestHTTPRejectsOversizedBody(t *testing.T) {
	srv := newTestServer(t)
	big := strings.Repeat("a", 2<<20) // 2 MiB, above the 1 MiB cap
	body := `{"name":"x","description":"` + big + `"}`
	resp, err := http.Post(srv.URL+"/v1/domains", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge && resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 413 or 400 for oversized body, got %d", resp.StatusCode)
	}
}
