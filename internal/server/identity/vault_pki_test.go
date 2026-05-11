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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/0-draft/omega/internal/server/identity"
)

// vaultFixture stands up a tiny Vault PKI mock that answers the
// two endpoints omega calls: GET /v1/<mount>/ca_chain and
// POST /v1/<mount>/sign/<role>. The mock generates its own ECDSA
// CA at start so the issued certs chain correctly when omega
// hands them to a consumer.
type vaultFixture struct {
	server    *httptest.Server
	mount     string
	role      string
	token     string
	caKey     *ecdsa.PrivateKey
	caCert    *x509.Certificate
	signHits  atomic.Int64
	chainHits atomic.Int64
}

func newVaultFixture(t *testing.T, mount, role, token string) *vaultFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Vault Mock CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("self-sign ca: %v", err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	v := &vaultFixture{mount: mount, role: role, token: token, caKey: caKey, caCert: caCert}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/"+mount+"/ca_chain", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
		v.chainHits.Add(1)
		_, _ = w.Write(caPEM)
	})
	mux.HandleFunc("/v1/"+mount+"/sign/"+role, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			http.Error(w, "bad token", http.StatusForbidden)
			return
		}
		v.signHits.Add(1)
		var req struct {
			CSR        string `json:"csr"`
			CommonName string `json:"common_name"`
			URISans    string `json:"uri_sans"`
			TTL        string `json:"ttl"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		csrBlock, _ := pem.Decode([]byte(req.CSR))
		if csrBlock == nil {
			http.Error(w, "csr is not PEM", http.StatusBadRequest)
			return
		}
		parsed, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			http.Error(w, "parse csr: "+err.Error(), http.StatusBadRequest)
			return
		}
		leafTpl := &x509.Certificate{
			SerialNumber: big.NewInt(time.Now().UnixNano()),
			Subject:      pkix.Name{CommonName: req.CommonName},
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(30 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		// Stash URI SAN if the request asked for one. omega's caller
		// always sets it; we honour it in the issued leaf so the
		// happy-path test can assert the URI SAN landed.
		if req.URISans != "" {
			if u, err := url.Parse(req.URISans); err == nil {
				leafTpl.URIs = []*url.URL{u}
			}
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, parsed.PublicKey, caKey)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"certificate": string(leafPEM),
				"ca_chain":    []string{string(caPEM)},
			},
		})
	})
	v.server = httptest.NewServer(mux)
	t.Cleanup(v.server.Close)
	return v
}

func newVaultAuthority(t *testing.T, v *vaultFixture) identity.Authority {
	t.Helper()
	a, err := identity.New(identity.Config{
		Kind:          identity.KindVaultPKI,
		TrustDomain:   "omega.local",
		Dir:           filepath.Join(t.TempDir(), "ca"),
		VaultPKIAddr:  v.server.URL,
		VaultPKIToken: v.token,
		VaultPKIMount: v.mount,
		VaultPKIRole:  v.role,
	})
	if err != nil {
		t.Fatalf("new vault-pki authority: %v", err)
	}
	return a
}

func vaultIssueCSR(t *testing.T) (*x509.CertificateRequest, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	return csr, key
}

func TestVaultPKIIssueSVID_RoundTrip(t *testing.T) {
	v := newVaultFixture(t, "pki", "omega", "root-token")
	a := newVaultAuthority(t, v)

	if v.chainHits.Load() < 1 {
		t.Fatalf("expected boot-time ca_chain probe, got %d hits", v.chainHits.Load())
	}

	csr, _ := vaultIssueCSR(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")
	svid, err := a.IssueSVID(id, csr)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// The returned leaf must chain to the Vault mock's CA bundle.
	leafBlock, _ := pem.Decode(svid.CertPEM)
	if leafBlock == nil {
		t.Fatal("leaf pem decode")
	}
	leaf, err := x509.ParseCertificate(leafBlock.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	bundleBlock, _ := pem.Decode(svid.BundlePEM)
	if bundleBlock == nil {
		t.Fatal("bundle pem decode")
	}
	caCert, _ := x509.ParseCertificate(bundleBlock.Bytes)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("leaf does not chain to vault ca: %v", err)
	}

	if v.signHits.Load() != 1 {
		t.Errorf("expected one /sign hit, got %d", v.signHits.Load())
	}
}

func TestVaultPKIRejectsForeignTrustDomain(t *testing.T) {
	v := newVaultFixture(t, "pki", "omega", "tok")
	a := newVaultAuthority(t, v)
	csr, _ := vaultIssueCSR(t)
	other := spiffeid.RequireFromString("spiffe://other.example/foo")
	if _, err := a.IssueSVID(other, csr); err == nil {
		t.Fatal("expected error for foreign trust domain")
	}
}

func TestVaultPKIBootProbeFailsOnBadToken(t *testing.T) {
	v := newVaultFixture(t, "pki", "omega", "good")
	_, err := identity.New(identity.Config{
		Kind:          identity.KindVaultPKI,
		TrustDomain:   "omega.local",
		Dir:           filepath.Join(t.TempDir(), "ca"),
		VaultPKIAddr:  v.server.URL,
		VaultPKIToken: "WRONG",
		VaultPKIMount: "pki",
		VaultPKIRole:  "omega",
	})
	if err == nil || !strings.Contains(err.Error(), "ca_chain probe") {
		t.Fatalf("expected boot-time probe failure, got %v", err)
	}
}

func TestVaultPKIMissingConfigRejected(t *testing.T) {
	cases := []struct {
		name string
		cfg  identity.Config
	}{
		{"no addr", identity.Config{
			Kind: identity.KindVaultPKI, TrustDomain: "omega.local",
			Dir: t.TempDir(), VaultPKIToken: "t", VaultPKIRole: "r",
		}},
		{"no token", identity.Config{
			Kind: identity.KindVaultPKI, TrustDomain: "omega.local",
			Dir: t.TempDir(), VaultPKIAddr: "https://vault.example", VaultPKIRole: "r",
		}},
		{"no role", identity.Config{
			Kind: identity.KindVaultPKI, TrustDomain: "omega.local",
			Dir: t.TempDir(), VaultPKIAddr: "https://vault.example", VaultPKIToken: "t",
		}},
		{"no dir for jwt key", identity.Config{
			Kind: identity.KindVaultPKI, TrustDomain: "omega.local",
			VaultPKIAddr: "https://vault.example", VaultPKIToken: "t", VaultPKIRole: "r",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := identity.New(tc.cfg); err == nil {
				t.Fatal("expected error for missing required config")
			}
		})
	}
}
