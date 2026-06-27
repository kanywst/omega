package federation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/federation"
)

// newSelfSignedCA returns a fresh ECDSA P-256 self-signed CA cert
// suitable for use as a SPIFFE X.509 trust anchor. PEM and DER bytes
// are both returned so tests can build TDF JSON without re-decoding.
func newSelfSignedCA(t *testing.T, cn string) (pemBytes, der []byte, cert *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err = x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	cert, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse self-signed: %v", err)
	}
	pemBytes = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, der, cert
}

// marshalTDF builds a SPIFFE Trust Domain Format JSON document using
// go-spiffe so the bytes the test server returns are guaranteed to
// match what the SDK accepts on the consume side.
func marshalTDF(t *testing.T, td spiffeid.TrustDomain, anchors []*x509.Certificate, refreshHint time.Duration, sequence uint64) []byte {
	t.Helper()
	bundle := spiffebundle.FromX509Authorities(td, anchors)
	bundle.SetRefreshHint(refreshHint)
	bundle.SetSequenceNumber(sequence)
	body, err := bundle.Marshal()
	if err != nil {
		t.Fatalf("marshal tdf: %v", err)
	}
	return body
}

func TestRegistryOwnOnly(t *testing.T) {
	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := newRegistry(t, td, ownPEM, nil, time.Hour)
	got := r.Bundles()
	if len(got) != 1 || string(got["omega.alpha"]) != string(ownPEM) {
		t.Fatalf("unexpected bundles: %v", got)
	}
}

func TestRegistryFetchesPeerViaTDF(t *testing.T) {
	peerTD := spiffeid.RequireTrustDomainFromString("omega.beta")
	peerPEM, peerDER, peerCert := newSelfSignedCA(t, "Omega Beta CA")
	tdfBody := marshalTDF(t, peerTD, []*x509.Certificate{peerCert}, 120*time.Second, 1)

	var spiffeBundleHits, legacyBundleHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/spiffe-bundle", func(w http.ResponseWriter, _ *http.Request) {
		spiffeBundleHits.Add(1)
		_, _ = w.Write(tdfBody)
	})
	mux.HandleFunc("/v1/bundle", func(w http.ResponseWriter, _ *http.Request) {
		legacyBundleHits.Add(1)
		_, _ = w.Write(peerPEM)
	})
	peerSrv := httptest.NewServer(mux)
	defer peerSrv.Close()

	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := newRegistry(t, td, ownPEM, []federation.PeerConfig{
		{TrustDomain: "omega.beta", URL: peerSrv.URL},
	}, time.Hour)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go r.Run(ctx)

	waitFor(t, 2*time.Second, func() bool {
		return string(r.Bundles()["omega.beta"]) != ""
	}, "peer bundle never appeared via TDF")

	got := r.Bundles()["omega.beta"]
	if !strings.Contains(string(got), "BEGIN CERTIFICATE") {
		t.Fatalf("peer bundle is not PEM: %q", got)
	}
	block, _ := pem.Decode(got)
	if block == nil || string(block.Bytes) != string(peerDER) {
		t.Fatal("peer bundle round-trip mismatch")
	}
	if spiffeBundleHits.Load() == 0 {
		t.Errorf("expected /v1/spiffe-bundle to be hit, got 0")
	}
	if legacyBundleHits.Load() != 0 {
		t.Errorf("legacy /v1/bundle was hit %d times when TDF was available", legacyBundleHits.Load())
	}
	// 120s peer hint should drive effective refresh below the 1h
	// operator config but stay above the 10s minimum clamp.
	if got, want := r.PeerRefresh("omega.beta"), 120*time.Second; got != want {
		t.Errorf("effective refresh: got %s want %s", got, want)
	}
}

func TestRegistryFallsBackToPEMWhenTDFAbsent(t *testing.T) {
	peerPEM, _, _ := newSelfSignedCA(t, "Omega Beta CA")

	var spiffeBundleHits, legacyBundleHits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/spiffe-bundle", func(w http.ResponseWriter, r *http.Request) {
		spiffeBundleHits.Add(1)
		http.NotFound(w, r)
	})
	mux.HandleFunc("/v1/bundle", func(w http.ResponseWriter, _ *http.Request) {
		legacyBundleHits.Add(1)
		_, _ = w.Write(peerPEM)
	})
	peerSrv := httptest.NewServer(mux)
	defer peerSrv.Close()

	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := newRegistry(t, td, ownPEM, []federation.PeerConfig{
		{TrustDomain: "omega.beta", URL: peerSrv.URL},
	}, time.Hour)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go r.Run(ctx)

	waitFor(t, 2*time.Second, func() bool {
		return string(r.Bundles()["omega.beta"]) == string(peerPEM)
	}, "peer bundle never appeared via PEM fallback")

	if spiffeBundleHits.Load() == 0 {
		t.Errorf("TDF endpoint should have been probed, got 0 hits")
	}
	if legacyBundleHits.Load() == 0 {
		t.Errorf("PEM fallback should have been used, got 0 hits")
	}
	// No TDF, no refresh hint → effective refresh stays at the
	// operator-configured value (1h, clamped to maxRefresh).
	if got, want := r.PeerRefresh("omega.beta"), time.Hour; got != want {
		t.Errorf("effective refresh: got %s want %s", got, want)
	}
}

func TestRegistryIgnoresUnreachablePeer(t *testing.T) {
	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := newRegistry(t, td, ownPEM, []federation.PeerConfig{
		{TrustDomain: "omega.dead", URL: "http://127.0.0.1:1"}, // closed port
	}, time.Hour)

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	r.Run(ctx)

	got := r.Bundles()
	if _, ok := got["omega.dead"]; ok {
		t.Fatalf("dead peer should be omitted: %v", got)
	}
	if _, ok := got["omega.alpha"]; !ok {
		t.Fatalf("own bundle missing: %v", got)
	}
}

func TestRegistryRejectsMalformedPEM(t *testing.T) {
	peerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/spiffe-bundle" {
			http.NotFound(w, r)
			return
		}
		// PEM marker present, DER body is garbage. The previous
		// behaviour would have stored this and broken every workload's
		// handshake.
		_, _ = fmt.Fprint(w, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	}))
	defer peerSrv.Close()

	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := newRegistry(t, td, ownPEM, []federation.PeerConfig{
		{TrustDomain: "omega.bad", URL: peerSrv.URL},
	}, time.Hour)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	r.Run(ctx)

	if _, ok := r.Bundles()["omega.bad"]; ok {
		t.Fatal("malformed peer bundle should not be stored")
	}
}

func TestRegistryPeersHaveIndependentCadences(t *testing.T) {
	// Two peers, divergent TDF refresh hints. The fast peer's hint
	// must clamp to the 10s minRefresh floor; the slow peer's hint
	// must drive cadence down from the 1h operator default without
	// being pulled toward the fast peer's value.
	fastTD := spiffeid.RequireTrustDomainFromString("omega.fast")
	slowTD := spiffeid.RequireTrustDomainFromString("omega.slow")
	_, _, fastCert := newSelfSignedCA(t, "Omega Fast CA")
	_, _, slowCert := newSelfSignedCA(t, "Omega Slow CA")
	fastTDF := marshalTDF(t, fastTD, []*x509.Certificate{fastCert}, 5*time.Second, 1)   // below minRefresh → clamps to 10s
	slowTDF := marshalTDF(t, slowTD, []*x509.Certificate{slowCert}, 300*time.Second, 1) // 5m, well below 1h op config

	fastSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/spiffe-bundle" {
			_, _ = w.Write(fastTDF)
			return
		}
		http.NotFound(w, r)
	}))
	defer fastSrv.Close()
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/spiffe-bundle" {
			_, _ = w.Write(slowTDF)
			return
		}
		http.NotFound(w, r)
	}))
	defer slowSrv.Close()

	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := newRegistry(t, td, ownPEM, []federation.PeerConfig{
		{TrustDomain: "omega.fast", URL: fastSrv.URL},
		{TrustDomain: "omega.slow", URL: slowSrv.URL},
	}, time.Hour)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go r.Run(ctx)

	waitFor(t, 2*time.Second, func() bool {
		return string(r.Bundles()["omega.fast"]) != "" && string(r.Bundles()["omega.slow"]) != ""
	}, "both peers never appeared")

	// fast peer: 5s hint → clamps up to 10s minRefresh.
	if got, want := r.PeerRefresh("omega.fast"), 10*time.Second; got != want {
		t.Errorf("fast peer refresh: got %s want %s (clamped from 5s)", got, want)
	}
	// slow peer: 5m hint → 5m (between minRefresh and operator
	// config). Crucially, the fast peer's smaller hint must not
	// have pulled this peer's cadence down.
	if got, want := r.PeerRefresh("omega.slow"), 300*time.Second; got != want {
		t.Errorf("slow peer refresh: got %s want %s", got, want)
	}
}

// newSPIFFEEndpoint mints a fresh CA for trust domain td and a leaf
// X.509-SVID for spiffe://td<path> signed by it. It returns the CA's
// PEM (to seed endpoint_bundle), the TLS server certificate the peer
// endpoint presents, the SVID's SPIFFE ID, and the CA cert (so it can
// also be served as the peer's own TDF bundle).
func newSPIFFEEndpoint(t *testing.T, td, path string) (caPEM []byte, serverCert tls.Certificate, id spiffeid.ID, caCert *x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen ca key: %v", err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: td + " CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("self-sign ca: %v", err)
	}
	caCert, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca: %v", err)
	}
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	id = spiffeid.RequireFromString("spiffe://" + td + path)
	uri, err := url.Parse(id.String())
	if err != nil {
		t.Fatalf("parse spiffe uri: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{uri},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("sign leaf: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	serverCert = tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}
	return caPEM, serverCert, id, caCert
}

// writeTemp writes b to a fresh file under t.TempDir and returns its path.
func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// startSPIFFEPeer starts an HTTPS test server that presents serverCert
// and serves the peer's own TDF bundle at /v1/spiffe-bundle.
func startSPIFFEPeer(t *testing.T, serverCert tls.Certificate, peerTD spiffeid.TrustDomain, anchors []*x509.Certificate) *httptest.Server {
	t.Helper()
	tdf := marshalTDF(t, peerTD, anchors, 120*time.Second, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/spiffe-bundle", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tdf)
	})
	srv := httptest.NewUnstartedServer(mux)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestRegistryHTTPSSPIFFEVerifiesPinnedEndpoint(t *testing.T) {
	const peerTD = "omega.beta"
	caPEM, serverCert, id, caCert := newSPIFFEEndpoint(t, peerTD, "/control-plane")
	peerTDObj := spiffeid.RequireTrustDomainFromString(peerTD)
	srv := startSPIFFEPeer(t, serverCert, peerTDObj, []*x509.Certificate{caCert})

	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	r := newRegistry(t, spiffeid.RequireTrustDomainFromString("omega.alpha"), ownPEM, []federation.PeerConfig{{
		TrustDomain:        peerTD,
		URL:                srv.URL,
		Profile:            federation.ProfileHTTPSSPIFFE,
		EndpointSPIFFEID:   id.String(),
		EndpointBundleFile: writeTemp(t, "beta-ca.pem", caPEM),
	}}, time.Hour)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	go r.Run(ctx)

	waitFor(t, 2*time.Second, func() bool {
		return string(r.Bundles()[peerTD]) != ""
	}, "pinned https_spiffe peer bundle never appeared")
}

func TestRegistryHTTPSSPIFFERejectsWrongEndpointID(t *testing.T) {
	const peerTD = "omega.beta"
	caPEM, serverCert, _, caCert := newSPIFFEEndpoint(t, peerTD, "/control-plane")
	peerTDObj := spiffeid.RequireTrustDomainFromString(peerTD)
	srv := startSPIFFEPeer(t, serverCert, peerTDObj, []*x509.Certificate{caCert})

	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	r := newRegistry(t, spiffeid.RequireTrustDomainFromString("omega.alpha"), ownPEM, []federation.PeerConfig{{
		TrustDomain:        peerTD,
		URL:                srv.URL,
		Profile:            federation.ProfileHTTPSSPIFFE,
		EndpointSPIFFEID:   "spiffe://" + peerTD + "/someone-else", // pinned ID != endpoint SVID
		EndpointBundleFile: writeTemp(t, "beta-ca.pem", caPEM),
	}}, time.Hour)

	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()
	r.Run(ctx)

	if _, ok := r.Bundles()[peerTD]; ok {
		t.Fatal("peer with mismatched endpoint SPIFFE ID should not be trusted")
	}
}

func TestRegistryHTTPSSPIFFERejectsWrongSeedBundle(t *testing.T) {
	const peerTD = "omega.beta"
	_, serverCert, id, caCert := newSPIFFEEndpoint(t, peerTD, "/control-plane")
	peerTDObj := spiffeid.RequireTrustDomainFromString(peerTD)
	srv := startSPIFFEPeer(t, serverCert, peerTDObj, []*x509.Certificate{caCert})

	// Seed with an UNRELATED CA: the endpoint SVID does not chain to it,
	// so verification must fail even though the pinned ID matches.
	wrongCAPEM, _, _ := newSelfSignedCA(t, "Unrelated CA")

	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	r := newRegistry(t, spiffeid.RequireTrustDomainFromString("omega.alpha"), ownPEM, []federation.PeerConfig{{
		TrustDomain:        peerTD,
		URL:                srv.URL,
		Profile:            federation.ProfileHTTPSSPIFFE,
		EndpointSPIFFEID:   id.String(),
		EndpointBundleFile: writeTemp(t, "wrong-ca.pem", wrongCAPEM),
	}}, time.Hour)

	ctx, cancel := context.WithTimeout(t.Context(), 400*time.Millisecond)
	defer cancel()
	r.Run(ctx)

	if _, ok := r.Bundles()[peerTD]; ok {
		t.Fatal("peer whose endpoint SVID does not chain to the seed bundle should not be trusted")
	}
}

func TestNewRegistryRejectsHTTPSSPIFFEWithoutSeed(t *testing.T) {
	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	_, err := federation.NewRegistry(spiffeid.RequireTrustDomainFromString("omega.alpha"), ownPEM, []federation.PeerConfig{{
		TrustDomain:      "omega.beta",
		URL:              "https://omega.beta:8443",
		Profile:          federation.ProfileHTTPSSPIFFE,
		EndpointSPIFFEID: "spiffe://omega.beta/control-plane",
		// EndpointBundleFile intentionally empty.
	}}, time.Hour)
	if err == nil {
		t.Fatal("expected NewRegistry to reject https_spiffe peer without endpoint_bundle")
	}
}

// newRegistry wraps federation.NewRegistry and fails the test on the
// construction error (file/profile validation) so the existing
// happy-path cases stay terse.
func newRegistry(t *testing.T, ownTD spiffeid.TrustDomain, ownBundle []byte, peers []federation.PeerConfig, refresh time.Duration) *federation.Registry {
	t.Helper()
	r, err := federation.NewRegistry(ownTD, ownBundle, peers, refresh)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return r
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s (waited %s)", msg, d)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
