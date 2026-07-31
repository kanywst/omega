package identity_test

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
)

func reloadable(t *testing.T, src identity.Source) identity.ReloadableSource {
	t.Helper()
	r, ok := src.(identity.ReloadableSource)
	if !ok {
		t.Fatalf("upstream source does not implement identity.ReloadableSource (%T)", src)
	}
	return r
}

func sequence(t *testing.T, src identity.Source) int64 {
	t.Helper()
	s, ok := src.(identity.BundleSequencer)
	if !ok {
		t.Fatalf("upstream source does not implement identity.BundleSequencer (%T)", src)
	}
	return s.BundleSequence()
}

// The regression this change exists for: before reload, a token minted by
// the post-rotation upstream failed with "unknown kid" until restart.
func TestUpstreamSourceReloadFollowsUpstreamRotation(t *testing.T) {
	const td = "upstream.example"
	const aud = "https://api.example.com"

	before := upstreamAuthority(t, td)
	beforeJWKS, err := before.JWTBundle()
	if err != nil {
		t.Fatalf("pre-rotation JWTBundle: %v", err)
	}
	src, err := identity.NewUpstreamSourceWithJWT(td, "", before.BundlePEM(), beforeJWKS)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	if got := sequence(t, src); got != 1 {
		t.Fatalf("initial BundleSequence() = %d, want 1", got)
	}

	// The upstream rolls to a new CA and a new signing key.
	after := upstreamAuthority(t, td)
	afterJWKS, err := after.JWTBundle()
	if err != nil {
		t.Fatalf("post-rotation JWTBundle: %v", err)
	}
	id := spiffeid.RequireFromString("spiffe://" + td + "/workload/web")
	rotated, err := after.IssueJWTSVID(id, []string{aud}, time.Minute, nil)
	if err != nil {
		t.Fatalf("post-rotation issue: %v", err)
	}

	// Before the reload the new signer is unknown - the stale-bundle failure.
	if _, err := src.ValidateJWTSVID(rotated.Token, aud); err == nil {
		t.Fatal("post-rotation token validated against the pre-rotation JWKS; the fixture is not exercising a rotation")
	}

	changed, err := reloadable(t, src).Reload(after.BundlePEM(), afterJWKS)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !changed {
		t.Fatal("Reload reported no change after the upstream rotated its CA and signing key")
	}

	got, err := src.ValidateJWTSVID(rotated.Token, aud)
	if err != nil {
		t.Fatalf("ValidateJWTSVID after reload: %v", err)
	}
	if got.String() != id.String() {
		t.Fatalf("sub = %q, want %q", got, id)
	}
	if string(src.BundlePEM()) != string(after.BundlePEM()) {
		t.Fatal("BundlePEM() still serves the pre-rotation anchors after a reload")
	}
	if got := sequence(t, src); got != 2 {
		t.Fatalf("BundleSequence() = %d after one rotation, want 2", got)
	}
}

// A rotation that cannot be validated must not disarm the source: serving
// no anchors breaks every handshake, which is worse than serving old ones.
func TestUpstreamSourceReloadKeepsPreviousMaterialOnError(t *testing.T) {
	const td = "upstream.example"
	up := upstreamAuthority(t, td)
	jwks, err := up.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	src, err := identity.NewUpstreamSourceWithJWT(td, "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	good := string(src.BundlePEM())

	cases := []struct {
		name   string
		bundle []byte
		jwks   []byte
	}{
		{"malformed certificate block", []byte("-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydA==\n-----END CERTIFICATE-----\n"), jwks},
		{"no CA certificate", leafCertPEM(t), jwks},
		{"empty bundle", nil, jwks},
		{"malformed JWKS", up.BundlePEM(), []byte("{not json")},
		{"JWKS with no usable signing key", up.BundlePEM(), []byte(`{"keys":[{"kty":"RSA","kid":"r1","n":"AQAB","e":"AQAB"}]}`)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			changed, err := reloadable(t, src).Reload(tc.bundle, tc.jwks)
			if err == nil {
				t.Fatal("Reload accepted invalid upstream trust material")
			}
			if changed {
				t.Fatal("Reload reported a change while returning an error")
			}
			if string(src.BundlePEM()) != good {
				t.Fatal("a rejected reload replaced the previously-good trust anchors")
			}
			if got := sequence(t, src); got != 1 {
				t.Fatalf("BundleSequence() = %d after a rejected reload, want it to stay 1", got)
			}
		})
	}
}

// Peers use spiffe_sequence to tell a changed bundle from a re-served one,
// so a SIGHUP that did not actually rotate anything must not advance it.
func TestUpstreamSourceReloadUnchangedDoesNotAdvanceSequence(t *testing.T) {
	const td = "upstream.example"
	up := upstreamAuthority(t, td)
	jwks, err := up.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	src, err := identity.NewUpstreamSourceWithJWT(td, "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}

	changed, err := reloadable(t, src).Reload(up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if changed {
		t.Fatal("Reload reported a change for identical trust material")
	}
	if got := sequence(t, src); got != 1 {
		t.Fatalf("BundleSequence() = %d after a no-op reload, want 1", got)
	}

	// Cosmetic differences in the operator's JWKS file - key order and
	// whitespace - are not a rotation either, because the comparison runs
	// on the canonical re-encoding.
	spaced := []byte(strings.ReplaceAll(string(jwks), ",", ", "))
	changed, err = reloadable(t, src).Reload(up.BundlePEM(), spaced)
	if err != nil {
		t.Fatalf("Reload reformatted JWKS: %v", err)
	}
	if changed {
		t.Fatal("reformatting the JWKS file was reported as a rotation")
	}
}

// An X.509-only deployment must stay X.509-only across a reload rather
// than silently gaining or losing the JWT path.
func TestUpstreamSourceReloadPreservesX509OnlyMode(t *testing.T) {
	const td = "upstream.example"
	src, err := identity.NewUpstreamSource(td, "", upstreamBundle(t))
	if err != nil {
		t.Fatalf("NewUpstreamSource: %v", err)
	}
	next := upstreamBundle(t)
	if _, err := reloadable(t, src).Reload(next, nil); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, err := src.ValidateJWTSVID("irrelevant", "aud"); !errors.Is(err, identity.ErrUpstreamJWTNotConfigured) {
		t.Fatalf("ValidateJWTSVID error = %v, want ErrUpstreamJWTNotConfigured", err)
	}
	served, err := src.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	if keyCount(t, served) != 0 {
		t.Fatal("X.509-only source served signing keys after a reload")
	}
}

// A reload lands while requests are in flight.
func TestUpstreamSourceReloadIsSafeUnderConcurrentUse(t *testing.T) {
	const td = "upstream.example"
	const aud = "https://api.example.com"
	up := upstreamAuthority(t, td)
	jwks, err := up.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	src, err := identity.NewUpstreamSourceWithJWT(td, "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	id := spiffeid.RequireFromString("spiffe://" + td + "/workload/web")
	svid, err := up.IssueJWTSVID(id, []string{aud}, time.Hour, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	// Both generations keep the original signer, so a reader pinning
	// either must still validate; a failure means it saw a torn pair.
	// Built into a fresh slice because localAuthority hands out its
	// internal bundle, which append could corrupt in place.
	widened := make([]byte, 0, len(up.BundlePEM())+len(upstreamBundle(t)))
	widened = append(widened, up.BundlePEM()...)
	widened = append(widened, upstreamBundle(t)...)
	rotations := [][]byte{up.BundlePEM(), widened}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 4 {
		wg.Go(func() {
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, err := src.ValidateJWTSVID(svid.Token, aud); err != nil {
					t.Errorf("validation failed during reload: %v", err)
					return
				}
				if len(src.BundlePEM()) == 0 {
					t.Error("BundlePEM() returned nothing during reload")
					return
				}
			}
		})
	}
	for i := range 50 {
		if _, err := reloadable(t, src).Reload(rotations[i%len(rotations)], jwks); err != nil {
			t.Errorf("Reload: %v", err)
			break
		}
	}
	close(stop)
	wg.Wait()
}
