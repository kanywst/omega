package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
)

// stepCAFixture stands up a step-ca mock that answers the two
// endpoints omega calls: GET /roots.pem and POST /1.0/sign. The mock
// verifies the OTT signature against the provisioner JWK omega is
// configured with, so a regression that breaks OTT signing trips the
// test instead of silently working against a permissive mock.
type stepCAFixture struct {
	server *httptest.Server

	provisionerName    string
	provisionerKeyPriv []byte // JSON JWK, private
	provisionerKeyPub  jose.JSONWebKey

	caKey      *ecdsa.PrivateKey
	caCert     *x509.Certificate
	caPEM      []byte
	rootSHA    string
	signHits   atomic.Int64
	rootsHits  atomic.Int64
	lastOTTAud string
}

func newStepCAFixture(t *testing.T, provisioner string) *stepCAFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Step Mock CA"},
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

	provKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen provisioner key: %v", err)
	}
	privJWK := jose.JSONWebKey{Key: provKey, KeyID: "test-jwk-1", Algorithm: string(jose.ES256), Use: "sig"}
	pubJWK := privJWK.Public()
	privJSON, err := privJWK.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal priv jwk: %v", err)
	}

	sum := sha256.Sum256(caDER)
	rootSHA := hex.EncodeToString(sum[:])

	f := &stepCAFixture{
		provisionerName:    provisioner,
		provisionerKeyPriv: privJSON,
		provisionerKeyPub:  pubJWK,
		caKey:              caKey,
		caCert:             caCert,
		caPEM:              caPEM,
		rootSHA:            rootSHA,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /roots.pem", func(w http.ResponseWriter, _ *http.Request) {
		f.rootsHits.Add(1)
		_, _ = w.Write(caPEM)
	})
	mux.HandleFunc("POST /1.0/sign", func(w http.ResponseWriter, r *http.Request) {
		f.signHits.Add(1)
		var req struct {
			CSR string `json:"csr"`
			OTT string `json:"ott"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Verify the OTT signature against the provisioner's public
		// JWK and extract the sans / sha for the assertions below.
		sig, err := jose.ParseSigned(req.OTT, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			http.Error(w, "parse ott: "+err.Error(), http.StatusUnauthorized)
			return
		}
		raw, err := sig.Verify(&pubJWK)
		if err != nil {
			http.Error(w, "verify ott: "+err.Error(), http.StatusUnauthorized)
			return
		}
		var claims map[string]any
		if err := json.Unmarshal(raw, &claims); err != nil {
			http.Error(w, "claims: "+err.Error(), http.StatusBadRequest)
			return
		}
		if iss, _ := claims["iss"].(string); iss != provisioner {
			http.Error(w, "iss mismatch", http.StatusUnauthorized)
			return
		}
		if sha, _ := claims["sha"].(string); sha != rootSHA {
			http.Error(w, "sha pin mismatch (OTT was minted for a different root)", http.StatusUnauthorized)
			return
		}
		if aud, _ := claims["aud"].(string); aud != "" {
			f.lastOTTAud = aud
		}
		sans, _ := claims["sans"].([]any)
		var uri *url.URL
		if len(sans) > 0 {
			s, _ := sans[0].(string)
			if u, err := url.Parse(s); err == nil {
				uri = u
			}
		}

		// Sign the CSR with the mock root, copying the SPIFFE URI
		// from the OTT claims (real step-ca enforces that the CSR's
		// SANs match the OTT; the mock follows the spec for the
		// fields the demo asserts on).
		csrBlock, _ := pem.Decode([]byte(req.CSR))
		if csrBlock == nil {
			http.Error(w, "csr is not PEM", http.StatusBadRequest)
			return
		}
		csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
		if err != nil {
			http.Error(w, "parse csr: "+err.Error(), http.StatusBadRequest)
			return
		}
		serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			http.Error(w, "serial: "+err.Error(), http.StatusInternalServerError)
			return
		}
		leafTpl := &x509.Certificate{
			SerialNumber: serial,
			NotBefore:    time.Now().Add(-time.Minute),
			NotAfter:     time.Now().Add(30 * time.Minute),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		}
		if uri != nil {
			leafTpl.URIs = []*url.URL{uri}
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, csr.PublicKey, caKey)
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"crt": string(leafPEM),
			"ca":  string(caPEM),
		})
	})
	f.server = httptest.NewServer(mux)
	t.Cleanup(f.server.Close)
	return f
}

func newStepCAAuthorityForTest(t *testing.T, f *stepCAFixture) identity.Authority {
	t.Helper()
	a, err := identity.New(identity.Config{
		Kind:                    identity.KindStepCA,
		TrustDomain:             "omega.local",
		Dir:                     filepath.Join(t.TempDir(), "ca"),
		StepCAURL:               f.server.URL,
		StepCAProvisionerName:   f.provisionerName,
		StepCAProvisionerKeyPEM: f.provisionerKeyPriv,
	})
	if err != nil {
		t.Fatalf("new step-ca authority: %v", err)
	}
	return a
}

func stepCACSR(t *testing.T) *x509.CertificateRequest {
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
	return csr
}

func TestStepCAIssueSVID_RoundTrip(t *testing.T) {
	f := newStepCAFixture(t, "omega-provisioner")
	a := newStepCAAuthorityForTest(t, f)

	if f.rootsHits.Load() < 1 {
		t.Fatalf("expected boot-time /roots.pem probe, got %d hits", f.rootsHits.Load())
	}

	csr := stepCACSR(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")
	svid, err := a.IssueSVID(id, csr)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Chain check: leaf → mock step-ca root.
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
		t.Errorf("leaf does not chain to step-ca mock root: %v", err)
	}
	// URI SAN comes from the OTT, not the CSR.
	if len(leaf.URIs) == 0 || leaf.URIs[0].String() != id.String() {
		t.Errorf("leaf URI SANs = %v, want one matching %q", leaf.URIs, id)
	}
	if f.signHits.Load() != 1 {
		t.Errorf("expected one /1.0/sign hit, got %d", f.signHits.Load())
	}
	if !strings.HasSuffix(f.lastOTTAud, "/1.0/sign") {
		t.Errorf("OTT aud claim was %q, want suffix /1.0/sign", f.lastOTTAud)
	}
}

func TestStepCARejectsForeignTrustDomain(t *testing.T) {
	f := newStepCAFixture(t, "omega-provisioner")
	a := newStepCAAuthorityForTest(t, f)
	other := spiffeid.RequireFromString("spiffe://other.example/foo")
	if _, err := a.IssueSVID(other, stepCACSR(t)); err == nil {
		t.Fatal("expected error for foreign trust domain")
	}
}

func TestStepCAMissingConfigRejected(t *testing.T) {
	// Synthesise a placeholder JWK PEM so the "no URL" / "no
	// provisioner" cases do not accidentally trip on a missing-key
	// check before they reach the field omega is supposed to flag.
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privJWK := jose.JSONWebKey{Key: priv, KeyID: "stub", Algorithm: string(jose.ES256), Use: "sig"}
	privJSON, _ := privJWK.MarshalJSON()
	cases := []struct {
		name string
		cfg  identity.Config
	}{
		{"no url", identity.Config{
			Kind: identity.KindStepCA, TrustDomain: "omega.local",
			Dir: t.TempDir(), StepCAProvisionerName: "p", StepCAProvisionerKeyPEM: privJSON,
		}},
		{"no provisioner", identity.Config{
			Kind: identity.KindStepCA, TrustDomain: "omega.local",
			Dir: t.TempDir(), StepCAURL: "https://ca.example:9000", StepCAProvisionerKeyPEM: privJSON,
		}},
		{"no key", identity.Config{
			Kind: identity.KindStepCA, TrustDomain: "omega.local",
			Dir: t.TempDir(), StepCAURL: "https://ca.example:9000", StepCAProvisionerName: "p",
		}},
		{"no dir for jwt key", identity.Config{
			Kind: identity.KindStepCA, TrustDomain: "omega.local",
			StepCAURL: "https://ca.example:9000", StepCAProvisionerName: "p", StepCAProvisionerKeyPEM: privJSON,
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

func TestStepCARejectsPublicProvisionerJWK(t *testing.T) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubJWK := jose.JSONWebKey{Key: &priv.PublicKey, KeyID: "pub", Algorithm: string(jose.ES256), Use: "sig"}
	pubJSON, _ := pubJWK.MarshalJSON()
	_, err := identity.New(identity.Config{
		Kind:                    identity.KindStepCA,
		TrustDomain:             "omega.local",
		Dir:                     filepath.Join(t.TempDir(), "ca"),
		StepCAURL:               "https://ca.example:9000",
		StepCAProvisionerName:   "p",
		StepCAProvisionerKeyPEM: pubJSON,
	})
	if err == nil || !strings.Contains(err.Error(), "private") {
		t.Fatalf("expected rejection for public JWK, got %v", err)
	}
}

// Silence unused-import: base64 is used downstream when we extend
// the fixture to assert OTT jti uniqueness. Leaving the import in
// avoids a churn-only diff when that follow-up lands.
var _ = base64.RawURLEncoding
