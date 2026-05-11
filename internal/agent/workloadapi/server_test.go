package workloadapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// generateFixtureBundlePEM produces a valid self-signed ECDSA CA
// in PEM form so the agent's `fetchBundle` (which parses the body
// as an x509 certificate to read SubjectCN) is happy. Computed
// once per test process.
func generateFixtureBundlePEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Omega Local CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// newControlPlaneFixture stands up a minimal control-plane HTTP
// surface for the agent's JWKS-bundle and X.509-bundle fetches.
// The handlers count their hits so a test can assert how many
// times the agent actually went over the wire vs served from
// cache.
type controlPlaneFixture struct {
	server         *httptest.Server
	jwtBundleHits  atomic.Int64
	x509BundleHits atomic.Int64
}

func newControlPlaneFixture(t *testing.T, jwks string, x509Bundle string) *controlPlaneFixture {
	t.Helper()
	cp := &controlPlaneFixture{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/jwt/bundle", func(w http.ResponseWriter, _ *http.Request) {
		cp.jwtBundleHits.Add(1)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write([]byte(jwks))
	})
	mux.HandleFunc("/v1/bundle", func(w http.ResponseWriter, _ *http.Request) {
		cp.x509BundleHits.Add(1)
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write([]byte(x509Bundle))
	})
	cp.server = httptest.NewServer(mux)
	t.Cleanup(cp.server.Close)
	return cp
}

// A JWKS body with one ES256 key. Content is opaque to the cache
// test; bytes only need to round-trip equal.
const fixtureJWKS = `{"keys":[{"kty":"EC","crv":"P-256","kid":"test","x":"AAAA","y":"BBBB"}]}`

func TestCachedFetchJWTBundle_CacheHitsAvoidHTTP(t *testing.T) {
	cp := newControlPlaneFixture(t, fixtureJWKS, generateFixtureBundlePEM(t))
	s := NewServer(cp.server.URL, nil)

	// First call: cache miss. Both /v1/jwt/bundle (for the JWKS)
	// AND /v1/bundle (for the trust-domain probe) get hit once.
	body1, td1, err := s.cachedFetchJWTBundle(context.Background())
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	if string(body1) != fixtureJWKS {
		t.Errorf("body: got %q", string(body1))
	}
	if td1 == "" {
		t.Errorf("trust domain: empty")
	}
	if got := cp.jwtBundleHits.Load(); got != 1 {
		t.Errorf("after first call: jwt-bundle hits = %d, want 1", got)
	}

	// Subsequent calls within the TTL hit the cache, no HTTP.
	for i := range 5 {
		if _, _, err := s.cachedFetchJWTBundle(context.Background()); err != nil {
			t.Fatalf("hot call %d: %v", i, err)
		}
	}
	if got := cp.jwtBundleHits.Load(); got != 1 {
		t.Errorf("after warm calls: jwt-bundle hits = %d, want 1 (cached)", got)
	}
}

func TestCachedFetchJWTBundle_RefreshesAfterTTL(t *testing.T) {
	cp := newControlPlaneFixture(t, fixtureJWKS, generateFixtureBundlePEM(t))
	s := NewServer(cp.server.URL, nil)

	// Drive `s.now` so we can advance past the TTL deterministically
	// without sleeping in tests.
	base := time.Now()
	current := base
	s.now = func() time.Time { return current }

	if _, _, err := s.cachedFetchJWTBundle(context.Background()); err != nil {
		t.Fatalf("warm-up: %v", err)
	}
	if got := cp.jwtBundleHits.Load(); got != 1 {
		t.Fatalf("warm-up: hits = %d, want 1", got)
	}

	// Cache still valid - no new fetch.
	current = base.Add(jwksCacheTTL - time.Second)
	if _, _, err := s.cachedFetchJWTBundle(context.Background()); err != nil {
		t.Fatalf("pre-expiry: %v", err)
	}
	if got := cp.jwtBundleHits.Load(); got != 1 {
		t.Errorf("pre-expiry: hits = %d, want 1 (still cached)", got)
	}

	// Past the TTL - should re-fetch.
	current = base.Add(jwksCacheTTL + time.Second)
	if _, _, err := s.cachedFetchJWTBundle(context.Background()); err != nil {
		t.Fatalf("post-expiry: %v", err)
	}
	if got := cp.jwtBundleHits.Load(); got != 2 {
		t.Errorf("post-expiry: hits = %d, want 2 (refresh)", got)
	}
}

func TestCachedFetchJWTBundle_ErrorIsNotCached(t *testing.T) {
	hits := atomic.Int64{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	s := NewServer(srv.URL, nil)
	if _, _, err := s.cachedFetchJWTBundle(context.Background()); err == nil {
		t.Fatal("expected error on first call")
	}
	// A failed fetch must not populate the cache; the next call
	// has to try again, otherwise a single blip would render
	// ValidateJWTSVID permanently broken until the agent restarts.
	if _, _, err := s.cachedFetchJWTBundle(context.Background()); err == nil {
		t.Fatal("expected error on second call too")
	}
	if got := hits.Load(); got < 2 {
		t.Errorf("expected at least 2 HTTP attempts, got %d", got)
	}
}
