package identity_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"testing"
	"time"

	"github.com/0-draft/omega/internal/server/identity"
)

func TestBuildSPIFFEBundleEmitsTDFShape(t *testing.T) {
	a, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "ca"), "omega.local")
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}

	raw, err := identity.BuildSPIFFEBundle(a, identity.SPIFFEBundleOptions{
		Sequence:    1,
		RefreshHint: 5 * time.Minute,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var doc struct {
		Sequence    int64 `json:"spiffe_sequence"`
		RefreshHint int   `json:"spiffe_refresh_hint"`
		Keys        []map[string]any
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v: %s", err, raw)
	}
	if doc.Sequence != 1 {
		t.Errorf("sequence: got %d want 1", doc.Sequence)
	}
	if doc.RefreshHint != 300 {
		t.Errorf("refresh_hint: got %d want 300", doc.RefreshHint)
	}

	var sawX509, sawJWT bool
	for _, k := range doc.Keys {
		switch k["use"] {
		case "x509-svid":
			sawX509 = true
			x5c, ok := k["x5c"].([]any)
			if !ok || len(x5c) == 0 {
				t.Errorf("x509-svid entry missing x5c: %v", k)
				continue
			}
			der, err := base64.StdEncoding.DecodeString(x5c[0].(string))
			if err != nil {
				t.Errorf("x5c decode: %v", err)
				continue
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Errorf("x5c parse: %v", err)
				continue
			}
			if !cert.IsCA {
				t.Errorf("x5c cert is not a CA")
			}
			if k["kty"] != "EC" || k["crv"] != "P-256" {
				t.Errorf("expected EC P-256, got kty=%v crv=%v", k["kty"], k["crv"])
			}
		case "jwt-svid":
			sawJWT = true
			if k["kty"] != "EC" {
				t.Errorf("jwt-svid kty: got %v want EC", k["kty"])
			}
			if _, ok := k["kid"].(string); !ok {
				t.Errorf("jwt-svid missing kid: %v", k)
			}
		default:
			t.Errorf("unexpected use=%v in TDF bundle", k["use"])
		}
	}
	if !sawX509 || !sawJWT {
		t.Errorf("expected both x509-svid and jwt-svid entries: x509=%v jwt=%v", sawX509, sawJWT)
	}
}

func TestBuildSPIFFEBundleSurfacesMalformedTrustAnchor(t *testing.T) {
	// A malformed CERTIFICATE PEM block must produce an error rather
	// than be silently dropped; downstream peers depend on TDF being
	// either a full picture or a clear failure, never a partial one.
	badPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{0x30, 0x00}})
	fake := &fakeAuthority{bundle: badPEM, jwt: []byte(`{"keys":[]}`)}
	if _, err := identity.BuildSPIFFEBundle(fake, identity.SPIFFEBundleOptions{Sequence: 1}); err == nil {
		t.Fatal("expected error on malformed cert PEM, got nil")
	}
}

func TestBuildSPIFFEBundleRefreshHintClampsNegative(t *testing.T) {
	a, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "ca"), "omega.local")
	if err != nil {
		t.Fatalf("load ca: %v", err)
	}
	raw, err := identity.BuildSPIFFEBundle(a, identity.SPIFFEBundleOptions{
		Sequence:    1,
		RefreshHint: -1 * time.Second,
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	var doc struct {
		RefreshHint int `json:"spiffe_refresh_hint"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if doc.RefreshHint != 0 {
		t.Errorf("refresh_hint: got %d want 0 (clamped from negative)", doc.RefreshHint)
	}
}

// fakeAuthority is a minimal Authority stub used by the error-path
// tests. Only BundlePEM / JWTBundle are exercised; the issuance
// methods panic so a regression that calls them in this code path is
// caught loudly.
type fakeAuthority struct {
	identity.Authority
	bundle []byte
	jwt    []byte
}

func (f *fakeAuthority) BundlePEM() []byte          { return f.bundle }
func (f *fakeAuthority) JWTBundle() ([]byte, error) { return f.jwt, nil }

// Compile-time check that we can hand a fakeAuthority where an
// Authority is expected. The embedded interface means the unused
// methods will panic with a nil pointer if anyone calls them.
var _ identity.Authority = (*fakeAuthority)(nil)
