package federation_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/0-draft/omega/internal/server/federation"
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
	r := federation.NewRegistry(td, ownPEM, nil, time.Hour)
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
	r := federation.NewRegistry(td, ownPEM, []federation.PeerConfig{
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
	if got, want := r.EffectiveRefresh(), 120*time.Second; got != want {
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
	r := federation.NewRegistry(td, ownPEM, []federation.PeerConfig{
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
	if got, want := r.EffectiveRefresh(), time.Hour; got != want {
		t.Errorf("effective refresh: got %s want %s", got, want)
	}
}

func TestRegistryIgnoresUnreachablePeer(t *testing.T) {
	ownPEM, _, _ := newSelfSignedCA(t, "Omega Alpha CA")
	td := spiffeid.RequireTrustDomainFromString("omega.alpha")
	r := federation.NewRegistry(td, ownPEM, []federation.PeerConfig{
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
	r := federation.NewRegistry(td, ownPEM, []federation.PeerConfig{
		{TrustDomain: "omega.bad", URL: peerSrv.URL},
	}, time.Hour)

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	r.Run(ctx)

	if _, ok := r.Bundles()["omega.bad"]; ok {
		t.Fatal("malformed peer bundle should not be stored")
	}
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
