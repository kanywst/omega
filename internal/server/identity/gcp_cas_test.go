package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"golang.org/x/oauth2"

	"github.com/kanywst/omega/internal/server/identity"
)

const (
	testGCPCASPool  = "projects/demo-project/locations/us-central1/caPools/omega-pool"
	testGCPCASToken = "ya29.test-token"
)

// casFixture is a fake Certificate Authority Service answering the two
// v1 calls omega makes: POST /v1/<pool>:fetchCaCerts and
// POST /v1/<pool>/certificates. The pool holds a root and a subordinate
// issuing CA so the tests cover the chain shape a real pool returns.
type casFixture struct {
	server *httptest.Server

	rootPEM  []byte
	subCert  *x509.Certificate
	subKey   *ecdsa.PrivateKey
	subPEM   []byte
	rootCert *x509.Certificate
	rootKey  *ecdsa.PrivateKey

	fetchHits  atomic.Int64
	createHits atomic.Int64
	fetchFail  atomic.Bool

	mu        sync.Mutex
	lastQuery url.Values
	lastBody  map[string]any
	// mutate, when set, edits the leaf template before signing so a
	// test can simulate a misbehaving pool.
	mutate func(tpl *x509.Certificate, pub any) any
	// rawCreate, when set, replaces the whole create response.
	rawCreate func(w http.ResponseWriter)
	// signCert / signKey, when set, sign leaves instead of the
	// fixture's issuing CA; extraCA is appended to fetchCaCerts.
	signCert *x509.Certificate
	signKey  *ecdsa.PrivateKey
	extraCA  []byte
}

// newCA mints a CA certificate signed by parent (self-signed when nil).
func newCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	if parent == nil {
		parent, parentKey = tpl, key
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &key.PublicKey, parentKey)
	if err != nil {
		t.Fatalf("sign %s: %v", cn, err)
	}
	cert, _ := x509.ParseCertificate(der)
	return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newCASFixture(t *testing.T) *casFixture {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen root key: %v", err)
	}
	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "CAS Mock Root"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("self-sign root: %v", err)
	}
	rootCert, _ := x509.ParseCertificate(rootDER)
	subKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen sub key: %v", err)
	}
	subTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "CAS Mock Issuing CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	subDER, err := x509.CreateCertificate(rand.Reader, subTpl, rootCert, &subKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("sign sub: %v", err)
	}
	subCert, _ := x509.ParseCertificate(subDER)
	f := &casFixture{
		rootPEM:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		rootCert: rootCert,
		rootKey:  rootKey,
		subCert:  subCert,
		subKey:   subKey,
		subPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subDER}),
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+testGCPCASPool+":fetchCaCerts", f.handleFetch)
	mux.HandleFunc("/v1/"+testGCPCASPool+"/certificates", f.handleCreate)
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func (f *casFixture) authorized(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method", http.StatusMethodNotAllowed)
		return false
	}
	if r.Header.Get("Authorization") != "Bearer "+testGCPCASToken {
		http.Error(w, `{"error":{"code":403,"status":"PERMISSION_DENIED"}}`, http.StatusForbidden)
		return false
	}
	return true
}

func (f *casFixture) handleFetch(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(w, r) {
		return
	}
	f.fetchHits.Add(1)
	if f.fetchFail.Load() {
		http.Error(w, `{"error":{"code":503,"status":"UNAVAILABLE"}}`, http.StatusServiceUnavailable)
		return
	}
	// Two CAs in the pool sharing a root: the root must appear once in
	// the bundle omega builds.
	chains := []map[string]any{
		{"certificates": []string{string(f.subPEM), string(f.rootPEM)}},
		{"certificates": []string{string(f.rootPEM)}},
	}
	f.mu.Lock()
	if f.extraCA != nil {
		chains = append(chains, map[string]any{"certificates": []string{string(f.extraCA), string(f.rootPEM)}})
	}
	f.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"caCerts": chains})
}

func (f *casFixture) handleCreate(w http.ResponseWriter, r *http.Request) {
	if !f.authorized(w, r) {
		return
	}
	f.createHits.Add(1)
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.lastQuery = r.URL.Query()
	f.lastBody = body
	mutate, rawCreate := f.mutate, f.rawCreate
	signCert, signKey := f.subCert, f.subKey
	if f.signCert != nil {
		signCert, signKey = f.signCert, f.signKey
	}
	f.mu.Unlock()
	if rawCreate != nil {
		rawCreate(w)
		return
	}
	var req struct {
		Lifetime string `json:"lifetime"`
		Config   struct {
			SubjectConfig struct {
				SubjectAltName struct {
					URIs []string `json:"uris"`
				} `json:"subjectAltName"`
			} `json:"subjectConfig"`
			PublicKey struct {
				Key    []byte `json:"key"`
				Format string `json:"format"`
			} `json:"publicKey"`
		} `json:"config"`
	}
	raw, _ := json.Marshal(body)
	if err := json.Unmarshal(raw, &req); err != nil {
		http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
		return
	}
	if !regexp.MustCompile(`^omega-[0-9a-f]{32}$`).MatchString(r.URL.Query().Get("certificateId")) {
		http.Error(w, "bad certificateId", http.StatusBadRequest)
		return
	}
	if req.Config.PublicKey.Format != "PEM" {
		http.Error(w, "bad key format", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode(req.Config.PublicKey.Key)
	if block == nil || block.Type != "PUBLIC KEY" {
		http.Error(w, "public key is not PEM", http.StatusBadRequest)
		return
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		http.Error(w, "parse key: "+err.Error(), http.StatusBadRequest)
		return
	}
	lifetime, err := time.ParseDuration(req.Lifetime)
	if err != nil {
		http.Error(w, "lifetime: "+err.Error(), http.StatusBadRequest)
		return
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(lifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		// CA:FALSE, as CAS issues an end-entity certificate.
		BasicConstraintsValid: true,
	}
	for _, s := range req.Config.SubjectConfig.SubjectAltName.URIs {
		if u, err := url.Parse(s); err == nil {
			tpl.URIs = append(tpl.URIs, u)
		}
	}
	if mutate != nil {
		pub = mutate(tpl, pub)
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, signCert, pub, signKey)
	if err != nil {
		http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"name":                "projects/x/certificates/y",
		"pemCertificate":      string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"pemCertificateChain": []string{string(f.subPEM), string(f.rootPEM)},
	})
}

func (f *casFixture) config(t *testing.T) identity.Config {
	t.Helper()
	return identity.Config{
		Kind:              identity.KindGCPCAS,
		TrustDomain:       "omega.local",
		Dir:               filepath.Join(t.TempDir(), "ca"),
		GCPCASPool:        testGCPCASPool,
		GCPCASEndpoint:    f.server.URL,
		GCPCASTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: testGCPCASToken}),
	}
}

func newCASAuthority(t *testing.T, f *casFixture) identity.Authority {
	t.Helper()
	a, err := identity.New(f.config(t))
	if err != nil {
		t.Fatalf("new gcp-cas authority: %v", err)
	}
	return a
}

func TestGCPCASIssueSVID_RoundTrip(t *testing.T) {
	f := newCASFixture(t)
	cfg := f.config(t)
	cfg.GCPCASIssuingCA = "issuing-ca-1"
	cfg.GCPCASCertificateTemplate = "projects/demo-project/locations/us-central1/certificateTemplates/spiffe"
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if f.fetchHits.Load() != 1 {
		t.Fatalf("expected one boot-time fetchCaCerts probe, got %d", f.fetchHits.Load())
	}

	csr, _ := vaultIssueCSR(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/ns/prod/sa/web")
	svid, err := a.IssueSVID(id, csr)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The bundle holds the issuing CA and the root, the shared root once.
	var bundle []*x509.Certificate
	for rest := svid.BundlePEM; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			t.Fatalf("parse bundle cert: %v", err)
		}
		bundle = append(bundle, c)
	}
	if len(bundle) != 2 {
		t.Fatalf("bundle has %d certificates, want 2 (issuing CA + root, deduplicated)", len(bundle))
	}

	// The leaf alone verifies against the bundle: the subordinate CA is
	// a trust anchor in it, which is what a workload relies on.
	leafBlock, _ := pem.Decode(svid.CertPEM)
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	roots := x509.NewCertPool()
	for _, c := range bundle {
		roots.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("leaf does not chain to the pool bundle: %v", err)
	}
	if len(leaf.URIs) != 1 || leaf.URIs[0].String() != id.String() {
		t.Errorf("leaf URI SANs = %v, want [%s]", leaf.URIs, id)
	}
	if got := leaf.NotAfter.Sub(leaf.NotBefore); got < 30*time.Minute || got > 32*time.Minute {
		t.Errorf("leaf validity %v, want about 30m", got)
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if got := f.lastQuery.Get("issuingCertificateAuthorityId"); got != "issuing-ca-1" {
		t.Errorf("issuingCertificateAuthorityId = %q", got)
	}
	if got := f.lastBody["certificateTemplate"]; got != cfg.GCPCASCertificateTemplate {
		t.Errorf("certificateTemplate = %v", got)
	}
	if got := f.lastBody["lifetime"]; got != "1800s" {
		t.Errorf("lifetime = %v, want 1800s", got)
	}
}

func TestGCPCASJWTSVIDStaysLocal(t *testing.T) {
	f := newCASFixture(t)
	a := newCASAuthority(t, f)
	id := spiffeid.RequireFromString("spiffe://omega.local/web")
	tok, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue jwt: %v", err)
	}
	got, err := a.ValidateJWTSVID(tok.Token, "aud")
	if err != nil || got != id {
		t.Fatalf("validate jwt: %v %v", got, err)
	}
	if f.createHits.Load() != 0 {
		t.Errorf("JWT-SVID issuance must not call CAS, got %d create calls", f.createHits.Load())
	}
}

func TestGCPCASRejectsBadRequests(t *testing.T) {
	f := newCASFixture(t)
	a := newCASAuthority(t, f)
	csr, _ := vaultIssueCSR(t)
	if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://other.example/x"), csr); err == nil {
		t.Error("expected error for foreign trust domain")
	}
	if _, err := a.IssueSVID(spiffeid.ID{}, csr); err == nil {
		t.Error("expected error for empty id")
	}
	if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/x"), nil); err == nil {
		t.Error("expected error for nil csr")
	}
	if f.createHits.Load() != 0 {
		t.Errorf("rejected requests must not reach CAS, got %d", f.createHits.Load())
	}
}

func TestGCPCASRejectsMisissuedCertificates(t *testing.T) {
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		mutate  func(tpl *x509.Certificate, pub any) any
		raw     func(w http.ResponseWriter)
		wantErr string
	}{
		{name: "ca certificate", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.IsCA, tpl.BasicConstraintsValid = true, true
			return pub
		}, wantErr: "not marked CA:FALSE"},
		{name: "no basic constraints", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.BasicConstraintsValid = false
			return pub
		}, wantErr: "not marked CA:FALSE"},
		{name: "cert sign usage", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.KeyUsage |= x509.KeyUsageCertSign
			return pub
		}, wantErr: "key usage"},
		{name: "other public key", mutate: func(_ *x509.Certificate, _ any) any {
			return &otherKey.PublicKey
		}, wantErr: "public key does not match"},
		{name: "san dropped", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.URIs = nil
			return pub
		}, wantErr: "SAN passthrough"},
		{name: "extra uri san", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.URIs = append(tpl.URIs, &url.URL{Scheme: "spiffe", Host: "omega.local", Path: "/admin"})
			return pub
		}, wantErr: "not exactly the requested SPIFFE ID"},
		{name: "dns san", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.DNSNames = []string{"admin.example"}
			return pub
		}, wantErr: "DNS, IP or email SANs"},
		{name: "back-dated", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.NotBefore = time.Now().Add(-48 * time.Hour)
			return pub
		}, wantErr: "notBefore"},
		{name: "future-dated", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.NotBefore = time.Now().Add(time.Hour)
			return pub
		}, wantErr: "notBefore"},
		{name: "expired", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.NotBefore, tpl.NotAfter = time.Now().Add(-2*time.Minute), time.Now().Add(-time.Minute)
			return pub
		}, wantErr: "already expired"},
		{name: "long lifetime", mutate: func(tpl *x509.Certificate, pub any) any {
			tpl.NotAfter = time.Now().Add(24 * time.Hour)
			return pub
		}, wantErr: "longer than"},
		{name: "no certificate", raw: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{}`))
		}, wantErr: "no pemCertificate"},
		{name: "not pem", raw: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"pemCertificate":"garbage"}`))
		}, wantErr: "not PEM"},
		{name: "not a certificate", raw: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`{"pemCertificate":"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"}`))
		}, wantErr: "parse certificate"},
		{name: "not json", raw: func(w http.ResponseWriter) {
			_, _ = w.Write([]byte(`<html>`))
		}, wantErr: "decode"},
		{name: "upstream error", raw: func(w http.ResponseWriter) {
			http.Error(w, `{"error":{"code":400,"status":"FAILED_PRECONDITION"}}`, http.StatusBadRequest)
		}, wantErr: "returned 400"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newCASFixture(t)
			f.mutate, f.rawCreate = tc.mutate, tc.raw
			a := newCASAuthority(t, f)
			csr, _ := vaultIssueCSR(t)
			_, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/web"), csr)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), testGCPCASToken) {
				t.Fatalf("error leaks the bearer token: %v", err)
			}
		})
	}
}

func TestGCPCASServesStaleBundleWhenFetchFails(t *testing.T) {
	f := newCASFixture(t)
	cfg := f.config(t)
	cfg.GCPCASBundleTTL = time.Millisecond
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	want := a.BundlePEM()
	time.Sleep(5 * time.Millisecond)

	f.fetchFail.Store(true)
	before := f.fetchHits.Load()
	if got := a.BundlePEM(); string(got) != string(want) || len(got) == 0 {
		t.Fatalf("expected the stale bundle while CAS is down, got %q", got)
	}
	if f.fetchHits.Load() == before {
		t.Fatal("expected a refresh attempt after the TTL lapsed")
	}

	f.fetchFail.Store(false)
	time.Sleep(5 * time.Millisecond)
	if got := a.BundlePEM(); string(got) != string(want) {
		t.Fatalf("bundle after recovery = %q", got)
	}
}

func TestGCPCASBundleIsCached(t *testing.T) {
	f := newCASFixture(t)
	a := newCASAuthority(t, f)
	b := a.BundlePEM()
	b[0] = 'X' // the caller's copy is its own
	for range 5 {
		if got := a.BundlePEM(); got[0] != '-' {
			t.Fatal("BundlePEM returned the cached buffer, not a copy")
		}
	}
	if f.fetchHits.Load() != 1 {
		t.Errorf("expected the boot probe only, got %d fetches", f.fetchHits.Load())
	}
}

func TestGCPCASBootProbeFails(t *testing.T) {
	t.Run("bad token", func(t *testing.T) {
		f := newCASFixture(t)
		cfg := f.config(t)
		cfg.GCPCASTokenSource = oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "WRONG"})
		_, err := identity.New(cfg)
		if err == nil || !strings.Contains(err.Error(), "fetchCaCerts probe") || !strings.Contains(err.Error(), "403") {
			t.Fatalf("expected a 403 boot probe failure, got %v", err)
		}
		if strings.Contains(err.Error(), "WRONG") {
			t.Fatalf("error leaks the bearer token: %v", err)
		}
	})
	for name, body := range map[string]string{
		"empty pool": `{"caCerts":[]}`,
		"not pem":    `{"caCerts":[{"certificates":["garbage"]}]}`,
		"bad der":    `{"caCerts":[{"certificates":["-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"]}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			_, err := identity.New(identity.Config{
				Kind: identity.KindGCPCAS, TrustDomain: "omega.local",
				Dir: t.TempDir(), GCPCASPool: testGCPCASPool, GCPCASEndpoint: srv.URL,
				GCPCASTokenSource: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: testGCPCASToken}),
			})
			if err == nil || !strings.Contains(err.Error(), "fetchCaCerts probe") {
				t.Fatalf("expected boot probe failure, got %v", err)
			}
		})
	}
}

func TestGCPCASConfigValidation(t *testing.T) {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: testGCPCASToken})
	base := func(t *testing.T) identity.Config {
		return identity.Config{
			Kind: identity.KindGCPCAS, TrustDomain: "omega.local", Dir: t.TempDir(),
			GCPCASPool: testGCPCASPool, GCPCASEndpoint: "https://privateca.example", GCPCASTokenSource: ts,
		}
	}
	cases := []struct {
		name    string
		edit    func(*identity.Config)
		wantErr string
	}{
		{"no dir", func(c *identity.Config) { c.Dir = "" }, "data-dir"},
		{"no pool", func(c *identity.Config) { c.GCPCASPool = "" }, "requires GCPCASPool"},
		{"short pool", func(c *identity.Config) { c.GCPCASPool = "omega-pool" }, "GCPCASPool must be"},
		{"pool with query", func(c *identity.Config) { c.GCPCASPool = testGCPCASPool + "?x=1" }, "GCPCASPool must be"},
		{"bad issuing ca", func(c *identity.Config) { c.GCPCASIssuingCA = "a/b" }, "GCPCASIssuingCA"},
		{"bad template", func(c *identity.Config) { c.GCPCASCertificateTemplate = "spiffe" }, "GCPCASCertificateTemplate"},
		{"http endpoint", func(c *identity.Config) { c.GCPCASEndpoint = "http://privateca.example" }, "must use https"},
		{"ftp endpoint", func(c *identity.Config) { c.GCPCASEndpoint = "ftp://privateca.example" }, "must be http(s)"},
		{"endpoint without host", func(c *identity.Config) { c.GCPCASEndpoint = "https://" }, "base URL"},
		{"endpoint with query", func(c *identity.Config) { c.GCPCASEndpoint = "https://privateca.example?x=1" }, "base URL"},
		{"unparseable endpoint", func(c *identity.Config) { c.GCPCASEndpoint = "https://[::1" }, "endpoint"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base(t)
			tc.edit(&cfg)
			_, err := identity.New(cfg)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestGCPCASLoopbackEndpointsAllowHTTP(t *testing.T) {
	f := newCASFixture(t)
	for _, host := range []string{"localhost", "127.0.0.1"} {
		cfg := f.config(t)
		cfg.GCPCASEndpoint = strings.Replace(f.server.URL, "127.0.0.1", host, 1) + "/"
		if _, err := identity.New(cfg); err != nil {
			t.Errorf("%s: %v", host, err)
		}
	}
}

func TestGCPCASDefaultCredentialsMissing(t *testing.T) {
	// Point ADC at a file that does not exist so the lookup fails fast
	// and never reaches the metadata server.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
	_, err := identity.New(identity.Config{
		Kind: identity.KindGCPCAS, TrustDomain: "omega.local", Dir: t.TempDir(),
		GCPCASPool: testGCPCASPool,
	})
	if err == nil || !strings.Contains(err.Error(), "application default credentials") {
		t.Fatalf("expected an ADC error, got %v", err)
	}
}

func TestGCPCASRejectsLeafOutsideThePool(t *testing.T) {
	f := newCASFixture(t)
	a := newCASAuthority(t, f)
	// A CA CAS never published in fetchCaCerts signs the leaf.
	foreign, foreignKey, _ := newCA(t, "Foreign CA", nil, nil)
	f.mu.Lock()
	f.signCert, f.signKey = foreign, foreignKey
	f.mu.Unlock()
	before := f.fetchHits.Load()
	csr, _ := vaultIssueCSR(t)
	_, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/web"), csr)
	if err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Fatalf("err = %v, want a chain verification failure", err)
	}
	if f.fetchHits.Load() != before+1 {
		t.Errorf("expected one bundle refresh before rejecting, got %d", f.fetchHits.Load()-before)
	}
}

func TestGCPCASPicksUpANewPoolCAOnIssue(t *testing.T) {
	f := newCASFixture(t)
	a := newCASAuthority(t, f)
	// A CA added to the pool after the bundle was cached signs the next
	// leaf; issuance refreshes the bundle instead of failing.
	newSub, newSubKey, newSubPEM := newCA(t, "CAS Mock Issuing CA 2", f.rootCert, f.rootKey)
	f.mu.Lock()
	f.signCert, f.signKey, f.extraCA = newSub, newSubKey, newSubPEM
	f.mu.Unlock()
	csr, _ := vaultIssueCSR(t)
	svid, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/web"), csr)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(string(svid.BundlePEM), strings.TrimSpace(string(newSubPEM))) {
		t.Error("returned bundle does not include the new pool CA")
	}
	if !strings.Contains(string(a.BundlePEM()), strings.TrimSpace(string(newSubPEM))) {
		t.Error("cached bundle was not updated")
	}
}

func TestGCPCASBacksOffAfterAFailedRefresh(t *testing.T) {
	f := newCASFixture(t)
	cfg := f.config(t)
	cfg.GCPCASBundleTTL = time.Millisecond
	a, err := identity.New(cfg)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	f.fetchFail.Store(true)
	before := f.fetchHits.Load()
	for range 5 {
		if len(a.BundlePEM()) == 0 {
			t.Fatal("expected the stale bundle")
		}
	}
	if got := f.fetchHits.Load() - before; got != 1 {
		t.Fatalf("expected one refresh attempt within the retry interval, got %d", got)
	}
}

func TestGCPCASIssueRefreshHonoursBackoff(t *testing.T) {
	f := newCASFixture(t)
	a := newCASAuthority(t, f)
	foreign, foreignKey, _ := newCA(t, "Foreign CA", nil, nil)
	f.mu.Lock()
	f.signCert, f.signKey = foreign, foreignKey
	f.mu.Unlock()
	f.fetchFail.Store(true)
	before := f.fetchHits.Load()
	for range 3 {
		csr, _ := vaultIssueCSR(t)
		if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/web"), csr); err == nil {
			t.Fatal("expected a chain failure")
		}
	}
	if got := f.fetchHits.Load() - before; got != 1 {
		t.Fatalf("expected one fetchCaCerts during the backoff window, got %d", got)
	}
}

func TestGCPCASRejectsLeafFromExpiredCA(t *testing.T) {
	f := newCASFixture(t)
	a := newCASAuthority(t, f)
	// An intermediate that has expired but is still published: the leaf
	// must fail the chain check at the current time.
	expiredTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Expired CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(-24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, err := x509.CreateCertificate(rand.Reader, expiredTpl, f.rootCert, &key.PublicKey, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	expired, _ := x509.ParseCertificate(der)
	f.mu.Lock()
	f.signCert, f.signKey = expired, key
	f.extraCA = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	f.mu.Unlock()
	csr, _ := vaultIssueCSR(t)
	if _, err := a.IssueSVID(spiffeid.RequireFromString("spiffe://omega.local/web"), csr); err == nil || !strings.Contains(err.Error(), "does not chain") {
		t.Fatalf("err = %v, want a chain failure for an expired CA", err)
	}
}
