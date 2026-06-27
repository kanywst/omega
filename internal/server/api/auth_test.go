package api_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// testCA is a tiny in-test certificate authority used to mint the server
// listener cert and the client SVIDs the mTLS auth path verifies.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ca key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "omega-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("ca cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &testCA{cert: cert, key: key, pool: pool}
}

// issue mints a leaf certificate signed by the CA. uriSAN, when
// non-empty, becomes a spiffe:// URI SAN; ips populate IP SANs (used for
// the server cert so the client can verify 127.0.0.1).
func (ca *testCA) issue(t *testing.T, cn, uriSAN string, ips []net.IP, extraURIs ...string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses:  ips,
	}
	if uriSAN != "" {
		u, err := url.Parse(uriSAN)
		if err != nil {
			t.Fatalf("uri san: %v", err)
		}
		tmpl.URIs = []*url.URL{u}
	}
	for _, extra := range extraURIs {
		u, err := url.Parse(extra)
		if err != nil {
			t.Fatalf("extra uri san: %v", err)
		}
		tmpl.URIs = append(tmpl.URIs, u)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatalf("leaf cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: nil}
}

// newAuthTestServer starts an mTLS httptest server backed by a real
// storage + identity stack, with requireAuth toggled per the argument.
func newAuthTestServer(t *testing.T, requireAuth bool) (*httptest.Server, *testCA) {
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
	handler := api.NewServer(store, ca, policy.New()).WithRequireAuth(requireAuth).Handler()

	tca := newTestCA(t)
	serverCert := tca.issue(t, "omega-server", "", []net.IP{net.ParseIP("127.0.0.1")})
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    tca.pool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, tca
}

// clientWith builds an HTTP client that trusts the test CA for the
// server cert and, when clientCert is non-nil, presents it for mTLS.
func clientWith(tca *testCA, clientCert *tls.Certificate) *http.Client {
	tc := &tls.Config{
		RootCAs:    tca.pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	}
	if clientCert != nil {
		tc.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}}
}

func svidBody(t *testing.T, spiffeID string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("csr key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	body, _ := json.Marshal(api.IssueSVIDRequest{SPIFFEID: spiffeID, CSR: string(csrPEM)})
	return body
}

// With require-auth on, a request that presents no client certificate is
// rejected outright at the mTLS handshake (RequireAndVerifyClientCert),
// so the issuance handler never runs.
func TestRequireAuth_NoClientCert_Rejected(t *testing.T) {
	srv, tca := newAuthTestServer(t, true)
	client := clientWith(tca, nil)
	_, err := client.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(svidBody(t, "spiffe://omega.local/web")))
	if err == nil {
		t.Fatal("expected the mTLS handshake to reject a client with no certificate")
	}
}

// A client cert that chains to the CA but carries no spiffe:// URI SAN
// passes the TLS handshake but is rejected by the auth middleware with
// 401 on a gated endpoint.
func TestRequireAuth_NonSPIFFECert_401(t *testing.T) {
	srv, tca := newAuthTestServer(t, true)
	cert := tca.issue(t, "no-spiffe", "", nil)
	client := clientWith(tca, &cert)
	resp, err := client.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(svidBody(t, "spiffe://omega.local/web")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 401 (body=%s)", resp.StatusCode, raw)
	}
}

// An X.509-SVID has exactly one URI SAN. A cert carrying the spiffe id
// plus a second URI SAN must be rejected (401), not have its first URI
// silently picked — otherwise a broader client-CA could smuggle a SAN.
func TestRequireAuth_MultipleURISANs_401(t *testing.T) {
	srv, tca := newAuthTestServer(t, true)
	cert := tca.issue(t, "web", "spiffe://omega.local/web", nil, "https://evil.example/extra")
	client := clientWith(tca, &cert)
	resp, err := client.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(svidBody(t, "spiffe://omega.local/web")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 401 (body=%s)", resp.StatusCode, raw)
	}
}

// A caller authenticated as spiffe://omega.local/web may renew its OWN
// identity: issuance succeeds (self-renewal allowed).
func TestRequireAuth_RenewOwnIdentity_OK(t *testing.T) {
	srv, tca := newAuthTestServer(t, true)
	cert := tca.issue(t, "web", "spiffe://omega.local/web", nil)
	client := clientWith(tca, &cert)
	resp, err := client.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(svidBody(t, "spiffe://omega.local/web")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (body=%s)", resp.StatusCode, raw)
	}
}

// The same caller may NOT mint a DIFFERENT identity: cross-identity
// issuance is denied with 403. This is the C1 fix - the spiffe_id is no
// longer trusted from the body when the caller is authenticated.
func TestRequireAuth_MintDifferentIdentity_403(t *testing.T) {
	srv, tca := newAuthTestServer(t, true)
	cert := tca.issue(t, "web", "spiffe://omega.local/web", nil)
	client := clientWith(tca, &cert)
	resp, err := client.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(svidBody(t, "spiffe://omega.local/db")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 403 (body=%s)", resp.StatusCode, raw)
	}
}

// The JWT-SVID issuance path enforces the same binding.
func TestRequireAuth_JWT_Binding(t *testing.T) {
	srv, tca := newAuthTestServer(t, true)
	cert := tca.issue(t, "web", "spiffe://omega.local/web", nil)
	client := clientWith(tca, &cert)

	own, _ := json.Marshal(api.IssueJWTSVIDRequest{SPIFFEID: "spiffe://omega.local/web", Audience: []string{"a"}})
	resp, err := client.Post(srv.URL+"/v1/svid/jwt", "application/json", bytes.NewReader(own))
	if err != nil {
		t.Fatalf("post own: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("own jwt: got %d want 200", resp.StatusCode)
	}

	other, _ := json.Marshal(api.IssueJWTSVIDRequest{SPIFFEID: "spiffe://omega.local/db", Audience: []string{"a"}})
	resp2, err := client.Post(srv.URL+"/v1/svid/jwt", "application/json", bytes.NewReader(other))
	if err != nil {
		t.Fatalf("post other: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-identity jwt: got %d want 403", resp2.StatusCode)
	}
}

// Public reads stay reachable under require-auth: a cert with no spiffe
// SAN (401 on issuance) still gets 200 from /healthz and GET /v1/bundle,
// proving the public/gated split is preserved.
func TestRequireAuth_PublicReadsReachable(t *testing.T) {
	srv, tca := newAuthTestServer(t, true)
	cert := tca.issue(t, "anon", "", nil)
	client := clientWith(tca, &cert)
	for _, path := range []string{"/healthz", "/v1/bundle", "/v1/leader", "/v1/domains"} {
		resp, err := client.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("get %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("public read %s: got %d want 200", path, resp.StatusCode)
		}
	}
}

// The audit log exposes every decision's subject and payload, so under
// require-auth its reads are closed too: a cert with no spiffe SAN is 401
// on GET /v1/audit, while a properly authenticated caller gets 200. (It
// is auth-gated but not leader-gated, so followers still serve it.)
func TestRequireAuth_AuditReadsGated(t *testing.T) {
	srv, tca := newAuthTestServer(t, true)

	anonCert := tca.issue(t, "anon", "", nil)
	anon := clientWith(tca, &anonCert)
	resp, err := anon.Get(srv.URL + "/v1/audit")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated audit read: got %d want 401", resp.StatusCode)
	}

	webCert := tca.issue(t, "web", "spiffe://omega.local/web", nil)
	authed := clientWith(tca, &webCert)
	resp2, err := authed.Get(srv.URL + "/v1/audit")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("authenticated audit read: got %d want 200", resp2.StatusCode)
	}
}

// With require-auth OFF, today's open-CA behaviour is preserved: an
// authenticated client may still mint an SVID for an identity that is not
// its own (the flag, not the transport, is what gates issuance).
func TestRequireAuthOff_OpenIssuancePreserved(t *testing.T) {
	srv, tca := newAuthTestServer(t, false)
	cert := tca.issue(t, "web", "spiffe://omega.local/web", nil)
	client := clientWith(tca, &cert)
	resp, err := client.Post(srv.URL+"/v1/svid", "application/json", bytes.NewReader(svidBody(t, "spiffe://omega.local/anything")))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200 (auth off should keep open issuance) (body=%s)", resp.StatusCode, raw)
	}
}
