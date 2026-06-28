package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"

	"github.com/kanywst/omega/internal/server/identity"
)

// upstreamBundle returns a valid X.509 bundle PEM by borrowing a built-in
// CA's bundle - it is real PEM with a parseable certificate, which is all
// NewUpstreamSource validates.
func upstreamBundle(t *testing.T) []byte {
	t.Helper()
	auth, err := identity.LoadOrCreate(t.TempDir(), "upstream.example")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return auth.BundlePEM()
}

func TestNewUpstreamSourceServesUpstreamTrust(t *testing.T) {
	bundle := upstreamBundle(t)

	src, err := identity.NewUpstreamSource("upstream.example", "https://issuer.example", bundle)
	if err != nil {
		t.Fatalf("NewUpstreamSource: %v", err)
	}
	if got := src.SourceKind(); got != identity.SourceSPIREUpstream {
		t.Fatalf("SourceKind() = %q, want %q", got, identity.SourceSPIREUpstream)
	}
	if got := src.IssuerURL(); got != "https://issuer.example" {
		t.Fatalf("IssuerURL() = %q, want https://issuer.example", got)
	}
	if src.TrustDomain().Name() != "upstream.example" {
		t.Fatalf("TrustDomain() = %q, want upstream.example", src.TrustDomain().Name())
	}
	if string(src.BundlePEM()) != string(bundle) {
		t.Fatal("BundlePEM() did not return the upstream bundle verbatim")
	}
	// Mutating the returned slice must not corrupt the stored trust anchors.
	got := src.BundlePEM()
	if len(got) > 0 {
		got[0] ^= 0xff
	}
	if string(src.BundlePEM()) != string(bundle) {
		t.Fatal("BundlePEM() exposed the internal slice; a caller mutated the stored bundle")
	}
}

func TestUpstreamSourceRefusesIssuance(t *testing.T) {
	src, err := identity.NewUpstreamSource("upstream.example", "", upstreamBundle(t))
	if err != nil {
		t.Fatalf("NewUpstreamSource: %v", err)
	}

	if _, err := src.IssueSVID(src.TrustDomain().ID(), nil); !errors.Is(err, identity.ErrIssuanceUnsupported) {
		t.Fatalf("IssueSVID err = %v, want ErrIssuanceUnsupported", err)
	}
	if _, err := src.IssueJWTSVID(src.TrustDomain().ID(), nil, 0, nil); !errors.Is(err, identity.ErrIssuanceUnsupported) {
		t.Fatalf("IssueJWTSVID err = %v, want ErrIssuanceUnsupported", err)
	}
	if _, _, err := src.ParseJWTSVIDClaims("anything"); !errors.Is(err, identity.ErrIssuanceUnsupported) {
		t.Fatalf("ParseJWTSVIDClaims err = %v, want ErrIssuanceUnsupported", err)
	}
	if _, err := src.JWTKeyID(); !errors.Is(err, identity.ErrIssuanceUnsupported) {
		t.Fatalf("JWTKeyID err = %v, want ErrIssuanceUnsupported", err)
	}
	if _, err := src.ValidateJWTSVID("token", "aud"); !errors.Is(err, identity.ErrIssuanceUnsupported) {
		t.Fatalf("ValidateJWTSVID err = %v, want ErrIssuanceUnsupported", err)
	}
	if _, err := src.ValidatePresentedCertBinding("token", "aud", nil); !errors.Is(err, identity.ErrIssuanceUnsupported) {
		t.Fatalf("ValidatePresentedCertBinding err = %v, want ErrIssuanceUnsupported", err)
	}
}

func TestNewUpstreamSourceRejectsBadInput(t *testing.T) {
	if _, err := identity.NewUpstreamSource("upstream.example", "", []byte("not a pem")); err == nil {
		t.Fatal("expected error for a bundle with no CERTIFICATE block")
	}
	if _, err := identity.NewUpstreamSource("", "", upstreamBundle(t)); err == nil {
		t.Fatal("expected error for an empty trust domain")
	}
	if _, err := identity.NewUpstreamSource("upstream.example", "", leafCertPEM(t)); err == nil {
		t.Fatal("expected error for a leaf-only bundle (a trust bundle must hold CA anchors)")
	}
	malformed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("garbage")})
	if _, err := identity.NewUpstreamSource("upstream.example", "", malformed); err == nil {
		t.Fatal("expected error for a bundle with a malformed CERTIFICATE block (must fail closed)")
	}
	// A valid CA followed by a malformed block must still fail closed - the
	// validator must not stop at the first good anchor.
	validThenBad := append(append([]byte(nil), upstreamBundle(t)...), malformed...)
	if _, err := identity.NewUpstreamSource("upstream.example", "", validThenBad); err == nil {
		t.Fatal("expected error for a valid CA followed by a malformed CERTIFICATE block")
	}
}

// leafCertPEM returns a self-signed PEM certificate with IsCA=false, so it
// is parseable but not a valid trust anchor.
func leafCertPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "leaf"},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
