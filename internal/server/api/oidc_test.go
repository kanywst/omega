package api_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/oidc"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

// idpFixture is a tiny in-process OIDC IdP. discovery + jwks only;
// omega never calls /token or /authorize so leaving them off keeps
// the fixture honest.
type idpFixture struct {
	server *httptest.Server
	signer jose.Signer
	issuer string
}

func newIdPFixture(t *testing.T) *idpFixture {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	kid := "fixture-kid"
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}},
		&jose.SignerOptions{},
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	pub := jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	idp := &idpFixture{signer: signer}
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

func (i *idpFixture) sign(t *testing.T, claims map[string]any) string {
	t.Helper()
	tok, err := jwt.Signed(i.signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func newOIDCTestServer(t *testing.T, idp *idpFixture, template string) (*httptest.Server, *storage.Store) {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.LoadOrCreate(filepath.Join(dir, "ca"), "omega.local")
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	reg, err := oidc.NewRegistry([]oidc.IdPConfig{{
		Name:             "corp",
		Issuer:           idp.issuer,
		Audiences:        []string{"omega-test"},
		SPIFFEIDTemplate: template,
	}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	srv := httptest.NewServer(
		api.NewServer(store, ca, policy.New()).WithOIDCRegistry(reg).Handler(),
	)
	t.Cleanup(srv.Close)
	return srv, store
}

func TestOIDCExchangeReturns404WhenRegistryUnset(t *testing.T) {
	srv := newTestServer(t)
	resp, err := http.Post(srv.URL+"/v1/oidc/exchange", "application/json",
		bytes.NewReader([]byte(`{"idp":"x","id_token":"y","audience":["z"]}`)))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", resp.StatusCode)
	}
}

func TestOIDCExchangeIssuesSVIDFromValidIDToken(t *testing.T) {
	idp := newIdPFixture(t)
	srv, _ := newOIDCTestServer(t, idp,
		"spiffe://omega.local/humans/{idp}/{preferred_username}")

	claims := map[string]any{
		"iss":                idp.issuer,
		"sub":                "u-1",
		"aud":                "omega-test",
		"iat":                time.Now().Add(-time.Minute).Unix(),
		"exp":                time.Now().Add(5 * time.Minute).Unix(),
		"preferred_username": "alice",
		"email":              "alice@example.com",
	}
	idToken := idp.sign(t, claims)

	body, _ := json.Marshal(api.OIDCExchangeRequest{
		IDP:      "corp",
		IDToken:  idToken,
		Audience: []string{"target-api"},
	})
	resp, err := http.Post(srv.URL+"/v1/oidc/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200", resp.StatusCode)
	}
	var out api.OIDCExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.SPIFFEID != "spiffe://omega.local/humans/corp/alice" {
		t.Errorf("spiffe_id: got %q", out.SPIFFEID)
	}
	if out.TokenType != "Bearer" {
		t.Errorf("token_type: got %q", out.TokenType)
	}
	if out.IdP != "corp" {
		t.Errorf("idp: got %q", out.IdP)
	}
	if len(out.Audience) != 1 || out.Audience[0] != "target-api" {
		t.Errorf("audience: %v", out.Audience)
	}
	if out.AccessToken == "" {
		t.Error("access_token is empty")
	}
}

func TestOIDCExchangeRejectsUnknownIdP(t *testing.T) {
	idp := newIdPFixture(t)
	srv, _ := newOIDCTestServer(t, idp,
		"spiffe://omega.local/humans/{sub}")
	body, _ := json.Marshal(api.OIDCExchangeRequest{
		IDP:      "nope",
		IDToken:  "irrelevant",
		Audience: []string{"target"},
	})
	resp, err := http.Post(srv.URL+"/v1/oidc/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestOIDCExchangeReturns401OnInvalidIDToken(t *testing.T) {
	idp := newIdPFixture(t)
	srv, store := newOIDCTestServer(t, idp,
		"spiffe://omega.local/humans/{sub}")

	// Forged iss: token says it came from somewhere else.
	claims := map[string]any{
		"iss": "https://attacker.example",
		"sub": "u-1",
		"aud": "omega-test",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	token := idp.sign(t, claims)
	body, _ := json.Marshal(api.OIDCExchangeRequest{IDP: "corp", IDToken: token, Audience: []string{"target"}})
	resp, err := http.Post(srv.URL+"/v1/oidc/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
	// Audit must record one deny row for this rejection.
	events, err := store.ListAudit(context.Background(), 0, 100)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var seenDeny bool
	for _, ev := range events {
		if ev.Kind == "oidc.exchange" && ev.Decision == "deny" {
			seenDeny = true
		}
	}
	if !seenDeny {
		t.Fatal("expected an oidc.exchange deny audit row")
	}
}

func TestOIDCExchangeRejectsTemplateOutOfTrustDomain(t *testing.T) {
	idp := newIdPFixture(t)
	srv, _ := newOIDCTestServer(t, idp,
		"spiffe://other.example/humans/{sub}")
	claims := map[string]any{
		"iss": idp.issuer, "sub": "u-1", "aud": "omega-test",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(),
	}
	body, _ := json.Marshal(api.OIDCExchangeRequest{
		IDP: "corp", IDToken: idp.sign(t, claims), Audience: []string{"target"},
	})
	resp, err := http.Post(srv.URL+"/v1/oidc/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}
