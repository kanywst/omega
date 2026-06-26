package oidc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kanywst/omega/internal/server/oidc"
)

// fakeIdP serves an OIDC discovery document and a JWKS that lets
// tests sign tokens with a known key. It is intentionally minimal:
// no /token, no /authorize, no /userinfo - omega never calls those
// endpoints, so a real IdP is overkill.
type fakeIdP struct {
	t         *testing.T
	server    *httptest.Server
	signer    jose.Signer
	publicKey jose.JSONWebKey
	kid       string
	issuer    string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	kid := "test-kid-1"
	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"},
	}
	signer, err := jose.NewSigner(signingKey, &jose.SignerOptions{})
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	pub := jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	idp := &fakeIdP{t: t, signer: signer, publicKey: pub, kid: kid}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":   idp.issuer,
			"jwks_uri": idp.issuer + "/jwks.json",
		})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	})
	idp.server = httptest.NewServer(mux)
	idp.issuer = idp.server.URL
	t.Cleanup(idp.server.Close)
	return idp
}

func (i *fakeIdP) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	raw, err := jwt.Signed(i.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return raw
}

func baseClaims(idp *fakeIdP, sub string) map[string]any {
	return map[string]any{
		"iss": idp.issuer,
		"sub": sub,
		"aud": "omega-test",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
}

func TestRegistryValidatesGoodToken(t *testing.T) {
	idp := newFakeIdP(t)
	reg, err := oidc.NewRegistry([]oidc.IdPConfig{{
		Name:             "corp",
		Issuer:           idp.issuer,
		Audiences:        []string{"omega-test"},
		SPIFFEIDTemplate: "spiffe://omega.local/humans/{idp}/{sub}",
	}})
	if err != nil {
		t.Fatalf("new registry: %v", err)
	}
	claims := baseClaims(idp, "alice@example.com")
	claims["email"] = "alice@example.com"
	claims["preferred_username"] = "alice"
	token := idp.sign(t, claims)

	got, err := reg.Validate(context.Background(), "corp", token)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if got.Subject != "alice@example.com" {
		t.Errorf("sub: got %q", got.Subject)
	}
	if got.Issuer != idp.issuer {
		t.Errorf("iss: got %q want %q", got.Issuer, idp.issuer)
	}
	if got.Email != "alice@example.com" || got.PreferredUN != "alice" {
		t.Errorf("email/preferred_username: %+v", got)
	}
}

func TestRegistryRejectsUnknownIdP(t *testing.T) {
	reg, err := oidc.NewRegistry(nil)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	_, err = reg.Validate(context.Background(), "nope", "x.y.z")
	if err == nil || !strings.Contains(err.Error(), "unknown idp") {
		t.Fatalf("expected ErrUnknownIdP, got %v", err)
	}
}

func TestRegistryRejectsWrongIssuer(t *testing.T) {
	idp := newFakeIdP(t)
	reg, _ := oidc.NewRegistry([]oidc.IdPConfig{{
		Name:             "corp",
		Issuer:           idp.issuer,
		Audiences:        []string{"omega-test"},
		SPIFFEIDTemplate: "spiffe://omega.local/humans/{sub}",
	}})
	c := baseClaims(idp, "alice")
	c["iss"] = "https://attacker.example"
	token := idp.sign(t, c)
	_, err := reg.Validate(context.Background(), "corp", token)
	if err == nil || !strings.Contains(err.Error(), "iss mismatch") {
		t.Fatalf("expected iss mismatch, got %v", err)
	}
}

func TestRegistryRejectsWrongAudience(t *testing.T) {
	idp := newFakeIdP(t)
	reg, _ := oidc.NewRegistry([]oidc.IdPConfig{{
		Name:             "corp",
		Issuer:           idp.issuer,
		Audiences:        []string{"omega-test"},
		SPIFFEIDTemplate: "spiffe://omega.local/humans/{sub}",
	}})
	c := baseClaims(idp, "alice")
	c["aud"] = "someone-else"
	token := idp.sign(t, c)
	_, err := reg.Validate(context.Background(), "corp", token)
	if err == nil || !strings.Contains(err.Error(), "claim validation") {
		t.Fatalf("expected audience-claim validation error, got %v", err)
	}
}

func TestRegistryRejectsExpiredToken(t *testing.T) {
	idp := newFakeIdP(t)
	reg, _ := oidc.NewRegistry([]oidc.IdPConfig{{
		Name:             "corp",
		Issuer:           idp.issuer,
		Audiences:        []string{"omega-test"},
		SPIFFEIDTemplate: "spiffe://omega.local/humans/{sub}",
	}})
	c := baseClaims(idp, "alice")
	c["exp"] = time.Now().Add(-time.Hour).Unix()
	token := idp.sign(t, c)
	_, err := reg.Validate(context.Background(), "corp", token)
	if err == nil {
		t.Fatal("expected expiry validation error")
	}
}

func TestRegistryRejectsForeignSignature(t *testing.T) {
	// Two IdPs with independent keys. A token from idpB presented as
	// if it were from idpA must fail signature verification.
	idpA := newFakeIdP(t)
	idpB := newFakeIdP(t)
	reg, _ := oidc.NewRegistry([]oidc.IdPConfig{{
		Name:             "corp",
		Issuer:           idpA.issuer,
		Audiences:        []string{"omega-test"},
		SPIFFEIDTemplate: "spiffe://omega.local/humans/{sub}",
	}})
	// Forge a token: iss claims idpA but it is signed by idpB.
	c := baseClaims(idpA, "alice")
	token := idpB.sign(t, c)
	_, err := reg.Validate(context.Background(), "corp", token)
	if err == nil {
		t.Fatal("expected signature verification to fail")
	}
}

func TestRegistryRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  oidc.IdPConfig
	}{
		{"empty name", oidc.IdPConfig{Issuer: "https://x", SPIFFEIDTemplate: "spiffe://x/{sub}"}},
		{"empty issuer", oidc.IdPConfig{Name: "x", SPIFFEIDTemplate: "spiffe://x/{sub}"}},
		{"non-http issuer", oidc.IdPConfig{Name: "x", Issuer: "ftp://x", SPIFFEIDTemplate: "spiffe://x/{sub}"}},
		{"empty template", oidc.IdPConfig{Name: "x", Issuer: "https://x", Audiences: []string{"omega"}}},
		{"missing audiences", oidc.IdPConfig{Name: "x", Issuer: "https://x", SPIFFEIDTemplate: "spiffe://x/{sub}"}},
		{"blank audience value", oidc.IdPConfig{Name: "x", Issuer: "https://x", Audiences: []string{"  "}, SPIFFEIDTemplate: "spiffe://x/{sub}"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oidc.NewRegistry([]oidc.IdPConfig{tc.cfg})
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
		})
	}
}

// Audiences is a required field: an empty AnyAudience makes go-jose
// skip the `aud` check entirely, so a token minted for any relying
// party at the issuer would be accepted (confused deputy). Validate
// must reject it with a clear message.
func TestValidateRequiresAudiences(t *testing.T) {
	err := oidc.IdPConfig{
		Name:             "corp",
		Issuer:           "https://corp.example",
		SPIFFEIDTemplate: "spiffe://omega.local/humans/{sub}",
	}.Validate()
	if err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("expected audience-required error, got %v", err)
	}
}

func TestRegistryRejectsDuplicateIdPName(t *testing.T) {
	_, err := oidc.NewRegistry([]oidc.IdPConfig{
		{Name: "x", Issuer: "https://a.example", Audiences: []string{"omega"}, SPIFFEIDTemplate: "spiffe://x/{sub}"},
		{Name: "x", Issuer: "https://b.example", Audiences: []string{"omega"}, SPIFFEIDTemplate: "spiffe://x/{sub}"},
	})
	if err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestRegistryNamesIsLexicographicallySorted(t *testing.T) {
	// Register in non-alphabetical order; Names() must still come
	// back sorted so loggers and tests see a stable listing across
	// runs (Go map iteration is non-deterministic).
	reg, _ := oidc.NewRegistry([]oidc.IdPConfig{
		{Name: "okta", Issuer: "https://okta.example", Audiences: []string{"omega"}, SPIFFEIDTemplate: "spiffe://x/{sub}"},
		{Name: "corp", Issuer: "https://corp.example", Audiences: []string{"omega"}, SPIFFEIDTemplate: "spiffe://x/{sub}"},
		{Name: "google", Issuer: "https://google.example", Audiences: []string{"omega"}, SPIFFEIDTemplate: "spiffe://x/{sub}"},
	})
	got := reg.Names()
	want := []string{"corp", "google", "okta"}
	if len(got) != len(want) {
		t.Fatalf("len: got %d want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Names()[%d]: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestRenderSPIFFEIDExpandsPlaceholders(t *testing.T) {
	got, err := oidc.RenderSPIFFEID(
		"spiffe://omega.local/humans/{idp}/{preferred_username}",
		&oidc.Claims{IdPName: "corp", PreferredUN: "alice"},
	)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	want := "spiffe://omega.local/humans/corp/alice"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestRenderSPIFFEIDRejectsEmptyClaimReferencedByTemplate(t *testing.T) {
	_, err := oidc.RenderSPIFFEID(
		"spiffe://omega.local/humans/{email}",
		&oidc.Claims{Subject: "alice"},
	)
	if err == nil {
		t.Fatal("expected error for missing email claim")
	}
}

// A claim value that happens to look like a placeholder must NOT
// trigger a second round of substitution. Single-pass replacement
// via strings.NewReplacer is the property gemini-code-assist flagged.
func TestRenderSPIFFEIDDoesNotRecursivelyExpandPlaceholdersInValues(t *testing.T) {
	got, err := oidc.RenderSPIFFEID(
		"spiffe://omega.local/humans/{idp}/{email}",
		&oidc.Claims{IdPName: "corp", Email: "alice+{sub}@example.com"},
	)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// `{sub}` inside Email must stay as the literal substring, not
	// be re-replaced with the (empty) Subject and cause an error or
	// an unintended path collapse.
	want := "spiffe://omega.local/humans/corp/alice+{sub}@example.com"
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestRenderSPIFFEIDPassesThroughTemplateWithoutPlaceholders(t *testing.T) {
	got, err := oidc.RenderSPIFFEID(
		"spiffe://omega.local/humans/static",
		&oidc.Claims{Subject: "ignored"},
	)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != "spiffe://omega.local/humans/static" {
		t.Errorf("got %q", got)
	}
}

// Surface-only sanity check: make sure the helper text in Lookup
// stays readable; not testing functionality there.
func TestRegistryLookupReturnsConfig(t *testing.T) {
	reg, err := oidc.NewRegistry([]oidc.IdPConfig{{
		Name:             "corp",
		Issuer:           "https://corp.example",
		Audiences:        []string{"omega"},
		SPIFFEIDTemplate: "spiffe://omega.local/humans/{sub}",
	}})
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	got, err := reg.Lookup("corp")
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.Issuer != "https://corp.example" {
		t.Errorf("issuer: got %q", got.Issuer)
	}
	if _, err := reg.Lookup("nope"); err == nil {
		t.Error("expected error for unknown idp")
	}
}

// Compile-time sanity: claims renderer should keep working with an
// empty template that produces an empty string.
func TestRenderSPIFFEIDEmptyTemplateIsEmpty(t *testing.T) {
	got, err := oidc.RenderSPIFFEID("", &oidc.Claims{})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty, got %q", got)
	}
}

// Smoke test using fmt to make sure the JWS we produce above looks
// like a compact JWS at all (3 segments separated by dots).
func TestFakeIdPSignsCompactJWS(t *testing.T) {
	idp := newFakeIdP(t)
	tok := idp.sign(t, baseClaims(idp, "x"))
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWS: %s", fmt.Sprintf("len=%d", len(parts)))
	}
}
