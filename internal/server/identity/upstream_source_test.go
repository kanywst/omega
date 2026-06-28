package identity_test

import (
	"errors"
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

	src, err := identity.NewUpstreamSource("upstream.example", bundle)
	if err != nil {
		t.Fatalf("NewUpstreamSource: %v", err)
	}
	if got := src.SourceKind(); got != identity.SourceSPIREUpstream {
		t.Fatalf("SourceKind() = %q, want %q", got, identity.SourceSPIREUpstream)
	}
	if src.TrustDomain().Name() != "upstream.example" {
		t.Fatalf("TrustDomain() = %q, want upstream.example", src.TrustDomain().Name())
	}
	if string(src.BundlePEM()) != string(bundle) {
		t.Fatal("BundlePEM() did not return the upstream bundle verbatim")
	}
}

func TestUpstreamSourceRefusesIssuance(t *testing.T) {
	src, err := identity.NewUpstreamSource("upstream.example", upstreamBundle(t))
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
}

func TestNewUpstreamSourceRejectsBadInput(t *testing.T) {
	if _, err := identity.NewUpstreamSource("upstream.example", []byte("not a pem")); err == nil {
		t.Fatal("expected error for a bundle with no CERTIFICATE block")
	}
	if _, err := identity.NewUpstreamSource("", upstreamBundle(t)); err == nil {
		t.Fatal("expected error for an empty trust domain")
	}
}
