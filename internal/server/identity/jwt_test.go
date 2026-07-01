package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
)

func newTestAuthority(t *testing.T) identity.Authority {
	t.Helper()
	a, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "ca"), "omega.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	return a
}

func TestJWTSVIDIssueAndValidate(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")

	svid, err := a.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if svid.Token == "" {
		t.Fatal("empty token")
	}
	if !strings.Contains(svid.Token, ".") {
		t.Fatal("not a JWT")
	}

	got, err := a.ValidateJWTSVID(svid.Token, "https://api.example.com")
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.String() != id.String() {
		t.Errorf("sub mismatch: %s vs %s", got, id)
	}
}

func TestJWTSVIDRejectsForeignTrustDomain(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://other.example/foo")
	if _, err := a.IssueJWTSVID(id, []string{"x"}, 0, nil); err == nil {
		t.Fatal("expected trust domain error")
	}
}

func TestJWTSVIDRejectsEmptyAudience(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/x")
	if _, err := a.IssueJWTSVID(id, nil, 0, nil); err == nil {
		t.Fatal("expected audience error")
	}
}

func TestJWTSVIDRejectsWrongAudience(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/x")
	svid, err := a.IssueJWTSVID(id, []string{"audA"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.ValidateJWTSVID(svid.Token, "audB"); err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestJWTBundleHasOneKey(t *testing.T) {
	a := newTestAuthority(t)
	raw, err := a.JWTBundle()
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(raw, &jwks); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k["kty"] != "EC" || k["crv"] != "P-256" || k["alg"] != "ES256" {
		t.Errorf("wrong key params: %v", k)
	}
}

func issueTestCert(t *testing.T, a identity.Authority, sub string) *x509.Certificate {
	t.Helper()
	id := spiffeid.RequireFromString(sub)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatalf("csr: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatalf("parse csr: %v", err)
	}
	svid, err := a.IssueSVID(id, csr)
	if err != nil {
		t.Fatalf("issue svid: %v", err)
	}
	block, _ := pem.Decode(svid.CertPEM)
	if block == nil {
		t.Fatal("svid pem decode")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestValidatePresentedCertBindingMatches(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")
	cert := issueTestCert(t, a, id.String())
	thumb := identity.CertThumbprintS256(cert)

	svid, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, map[string]any{
		"cnf": map[string]string{"x5t#S256": thumb},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := a.ValidatePresentedCertBinding(svid.Token, "aud", cert)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.String() != id.String() {
		t.Errorf("sub mismatch: %s vs %s", got, id)
	}
}

func TestValidatePresentedCertBindingMismatch(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")
	bound := issueTestCert(t, a, id.String())
	other := issueTestCert(t, a, "spiffe://omega.local/example/other")

	svid, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, map[string]any{
		"cnf": map[string]string{"x5t#S256": identity.CertThumbprintS256(bound)},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.ValidatePresentedCertBinding(svid.Token, "aud", other); err == nil {
		t.Fatal("expected binding mismatch error")
	}
}

func TestValidatePresentedCertBindingMissingCert(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")
	cert := issueTestCert(t, a, id.String())
	svid, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, map[string]any{
		"cnf": map[string]string{"x5t#S256": identity.CertThumbprintS256(cert)},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.ValidatePresentedCertBinding(svid.Token, "aud", nil); err == nil {
		t.Fatal("expected missing cert error")
	}
}

func TestValidatePresentedCertBindingNoCnfPasses(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")
	svid, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := a.ValidatePresentedCertBinding(svid.Token, "aud", nil)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.String() != id.String() {
		t.Errorf("sub mismatch: %s vs %s", got, id)
	}
}

func TestValidatePresentedCertBindingRejectsMalformedCnf(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/example/web")

	// cnf present but not an object: must be rejected, not treated as
	// "no binding".
	notObj, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, map[string]any{"cnf": "malformed"})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.ValidatePresentedCertBinding(notObj.Token, "aud", nil); err == nil {
		t.Fatal("expected failure for a non-object cnf claim")
	}

	// cnf present with only an unsupported confirmation method (no
	// x5t#S256): the issuer demanded proof of possession this validator
	// cannot enforce, so it must be rejected rather than accepted.
	noX5t, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, map[string]any{"cnf": map[string]any{"jkt": "abc"}})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.ValidatePresentedCertBinding(noX5t.Token, "aud", nil); err == nil {
		t.Fatal("expected failure for a cnf with no x5t#S256 binding")
	}

	// cnf.x5t#S256 present but not a string: must be rejected.
	nonStringX5t, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, map[string]any{"cnf": map[string]any{"x5t#S256": 123}})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.ValidatePresentedCertBinding(nonStringX5t.Token, "aud", nil); err == nil {
		t.Fatal("expected failure for a non-string x5t#S256 binding")
	}

	// cnf.x5t#S256 present but an empty string: must be rejected.
	emptyX5t, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, map[string]any{"cnf": map[string]any{"x5t#S256": ""}})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, err := a.ValidatePresentedCertBinding(emptyX5t.Token, "aud", nil); err == nil {
		t.Fatal("expected failure for an empty x5t#S256 binding")
	}
}

func TestJWTSVIDExtraClaims(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/x")
	svid, err := a.IssueJWTSVID(id, []string{"x"}, 0, map[string]any{
		"cnf": map[string]string{"x5t#S256": "abc"},
	})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !strings.Contains(svid.Token, ".") {
		t.Fatal("token shape")
	}
}

func TestJWTSVIDIssClaimAbsentByDefault(t *testing.T) {
	a := newTestAuthority(t)
	id := spiffeid.RequireFromString("spiffe://omega.local/x")
	svid, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if a.IssuerURL() != "" {
		t.Fatalf("default authority must have empty IssuerURL, got %q", a.IssuerURL())
	}
	claims := decodeJWTPayload(t, svid.Token)
	if v, ok := claims["iss"]; ok {
		t.Fatalf("default authority must not emit iss claim, got %v", v)
	}
}

func TestJWTSVIDIssClaimSetWhenIssuerConfigured(t *testing.T) {
	const wantIss = "https://omega.example.com"
	a, err := identity.New(identity.Config{
		Kind:        identity.KindDisk,
		TrustDomain: "omega.local",
		Issuer:      wantIss,
		Dir:         filepath.Join(t.TempDir(), "ca"),
	})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	if got := a.IssuerURL(); got != wantIss {
		t.Fatalf("IssuerURL: got %q want %q", got, wantIss)
	}
	id := spiffeid.RequireFromString("spiffe://omega.local/x")
	svid, err := a.IssueJWTSVID(id, []string{"aud"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	claims := decodeJWTPayload(t, svid.Token)
	if got := claims["iss"]; got != wantIss {
		t.Fatalf("iss claim: got %v want %q", got, wantIss)
	}
}

func TestNewRejectsInvalidIssuerURL(t *testing.T) {
	cases := []struct {
		name   string
		issuer string
	}{
		{"http scheme", "http://omega.example.com"},
		{"missing scheme", "omega.example.com"},
		{"missing host", "https://"},
		{"with query", "https://omega.example.com?x=1"},
		{"with fragment", "https://omega.example.com#frag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := identity.New(identity.Config{
				Kind:        identity.KindDisk,
				TrustDomain: "omega.local",
				Issuer:      tc.issuer,
				Dir:         filepath.Join(t.TempDir(), "ca"),
			})
			if err == nil {
				t.Fatalf("expected error for %q, got nil", tc.issuer)
			}
		})
	}
}

func TestNewNormalizesTrailingSlashOnIssuerURL(t *testing.T) {
	cases := []struct{ name, issuer, want string }{
		{"single trailing slash", "https://omega.example.com/", "https://omega.example.com"},
		{"double trailing slash", "https://omega.example.com//", "https://omega.example.com"},
		{"path with trailing slash", "https://omega.example.com/oidc/", "https://omega.example.com/oidc"},
		{"no trailing slash unchanged", "https://omega.example.com", "https://omega.example.com"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, err := identity.New(identity.Config{
				Kind:        identity.KindDisk,
				TrustDomain: "omega.local",
				Issuer:      tc.issuer,
				Dir:         filepath.Join(t.TempDir(), "ca"),
			})
			if err != nil {
				t.Fatalf("new: %v", err)
			}
			if got := a.IssuerURL(); got != tc.want {
				t.Fatalf("IssuerURL: got %q want %q", got, tc.want)
			}
		})
	}
}

// decodeJWTPayload base64url-decodes the second segment of a compact JWS
// without verifying the signature. Tests use it to assert claim shape;
// signature checks live in TestJWTSVIDIssueAndValidate.
func decodeJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3-part JWT, got %d parts", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("base64 payload: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("json payload: %v", err)
	}
	return out
}
