package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/federation"
	"github.com/kanywst/omega/internal/server/identity"
)

// upstreamFixture writes a trust bundle + JWKS to disk and returns the
// authority behind them, standing in for the upstream SPIRE.
func upstreamFixture(t *testing.T, dir, name string) (identity.Authority, string, string) {
	t.Helper()
	auth, err := identity.LoadOrCreate(filepath.Join(dir, name+"-ca"), "upstream.example")
	if err != nil {
		t.Fatalf("upstream authority: %v", err)
	}
	jwks, err := auth.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	bundlePath := filepath.Join(dir, name+"-bundle.pem")
	jwksPath := filepath.Join(dir, name+"-jwks.json")
	if err := os.WriteFile(bundlePath, auth.BundlePEM(), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	if err := os.WriteFile(jwksPath, jwks, 0o600); err != nil {
		t.Fatalf("write jwks: %v", err)
	}
	return auth, bundlePath, jwksPath
}

func newTestRegistry(t *testing.T, bundle []byte) *federation.Registry {
	t.Helper()
	fed, err := federation.NewRegistry(
		spiffeid.RequireTrustDomainFromString("upstream.example"), bundle, nil, time.Hour)
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	return fed
}

// The SIGHUP path has to re-read from disk, since the rotation is a file
// swap.
func TestUpstreamReloaderPicksUpRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	before, bundlePath, jwksPath := upstreamFixture(t, dir, "before")
	beforeJWKS, err := before.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	src, err := identity.NewUpstreamSourceWithJWT("upstream.example", "", before.BundlePEM(), beforeJWKS)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	fed := newTestRegistry(t, src.BundlePEM())

	reload := upstreamReloader(src, fed, bundlePath, jwksPath)
	if reload == nil {
		t.Fatal("upstreamReloader returned nil for a reloadable spire-upstream source")
	}

	// The upstream rotates: same paths, new contents.
	after, _, _ := upstreamFixture(t, dir, "after")
	afterJWKS, err := after.JWTBundle()
	if err != nil {
		t.Fatalf("rotated JWTBundle: %v", err)
	}
	if err := os.WriteFile(bundlePath, after.BundlePEM(), 0o600); err != nil {
		t.Fatalf("rotate bundle: %v", err)
	}
	if err := os.WriteFile(jwksPath, afterJWKS, 0o600); err != nil {
		t.Fatalf("rotate jwks: %v", err)
	}

	reload()

	if string(src.BundlePEM()) != string(after.BundlePEM()) {
		t.Fatal("reload did not install the rotated bundle from disk")
	}
	if got := fed.Bundles()["upstream.example"]; string(got) != string(after.BundlePEM()) {
		t.Fatal("federation registry still serves the pre-rotation anchors")
	}
	id := spiffeid.RequireFromString("spiffe://upstream.example/workload/web")
	svid, err := after.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := src.ValidateJWTSVID(svid.Token, "https://api.example.com"); err != nil {
		t.Fatalf("post-rotation token still rejected after reload: %v", err)
	}
}

// An empty JWKS reads as "X.509-only" to the parser, so a truncated file
// would silently drop the JWT path rather than fail the reload.
func TestReadUpstreamMaterialRejectsEmptyJWKS(t *testing.T) {
	dir := t.TempDir()
	_, bundlePath, jwksPath := upstreamFixture(t, dir, "before")
	for _, content := range []string{"", "   \n"} {
		if err := os.WriteFile(jwksPath, []byte(content), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, _, err := readUpstreamMaterial(bundlePath, jwksPath); err == nil {
			t.Fatalf("readUpstreamMaterial accepted an empty JWKS (%q)", content)
		}
	}
	// With the flag unset an absent JWKS is the documented X.509-only mode.
	if _, jwks, err := readUpstreamMaterial(bundlePath, ""); err != nil || jwks != nil {
		t.Fatalf("X.509-only read: jwks=%v err=%v", jwks, err)
	}
}

// A rotation that lands a corrupt or unreadable file must leave omega
// serving the previous material rather than nothing.
func TestUpstreamReloaderKeepsPreviousMaterialOnBadFile(t *testing.T) {
	dir := t.TempDir()
	before, bundlePath, jwksPath := upstreamFixture(t, dir, "before")
	beforeJWKS, err := before.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	src, err := identity.NewUpstreamSourceWithJWT("upstream.example", "", before.BundlePEM(), beforeJWKS)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	fed := newTestRegistry(t, src.BundlePEM())
	reload := upstreamReloader(src, fed, bundlePath, jwksPath)
	good := string(src.BundlePEM())

	for _, tc := range []struct {
		name  string
		apply func()
	}{
		{"corrupt bundle", func() {
			if err := os.WriteFile(bundlePath, []byte("not a pem"), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
		}},
		{"missing bundle", func() {
			if err := os.Remove(bundlePath); err != nil {
				t.Fatalf("remove: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.apply()
			reload()
			if string(src.BundlePEM()) != good {
				t.Fatal("a failed reload replaced the previously-good trust anchors")
			}
			if got := fed.Bundles()["upstream.example"]; string(got) != good {
				t.Fatal("a failed reload corrupted the federation registry's bundle")
			}
		})
	}
}

// A built-in issuing source owns its key material and has nothing to
// re-read, so it must not get a reload hook wired to it.
func TestUpstreamReloaderNilForNonReloadableSource(t *testing.T) {
	dir := t.TempDir()
	auth, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	fed := newTestRegistry(t, auth.BundlePEM())
	if got := upstreamReloader(auth, fed, "", ""); got != nil {
		t.Fatal("upstreamReloader returned a hook for a built-in source")
	}
	// Nor when a path is somehow present without a reloadable source.
	if got := upstreamReloader(auth, fed, filepath.Join(dir, "bundle.pem"), ""); got != nil {
		t.Fatal("upstreamReloader returned a hook for a built-in source with a bundle path")
	}
}
