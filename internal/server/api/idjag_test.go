package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/api"
	"github.com/kanywst/omega/internal/server/identity"
	"github.com/kanywst/omega/internal/server/oidc"
	"github.com/kanywst/omega/internal/server/policy"
	"github.com/kanywst/omega/internal/server/storage"
)

const (
	jagOmegaIssuer = "https://omega.example.com"
	jagAgent       = "spiffe://omega.local/agents/claude-code"
	jagTool        = "https://mcp.example.com/github"
)

// jagIDP is an in-process enterprise IdP that signs ID-JAGs.
type jagIDP struct {
	server *httptest.Server
	key    *ecdsa.PrivateKey
	issuer string
}

func newJAGIDP(t *testing.T) *jagIDP {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	idp := &jagIDP{key: key}
	pub := jose.JSONWebKey{Key: key.Public(), KeyID: "jag-kid", Algorithm: string(jose.ES256), Use: "sig"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": idp.issuer, "jwks_uri": idp.issuer + "/jwks.json"})
	})
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	})
	idp.server = httptest.NewServer(mux)
	idp.issuer = idp.server.URL
	t.Cleanup(idp.server.Close)
	return idp
}

func (i *jagIDP) sign(t *testing.T, typ string, claims map[string]any) string {
	t.Helper()
	opts := &jose.SignerOptions{}
	if typ != "" {
		opts = opts.WithType(jose.ContentType(typ))
	}
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: i.key, KeyID: "jag-kid", Algorithm: string(jose.ES256)},
	}, opts)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// validClaims is an ID-JAG that omega should accept from jagAgent.
func (i *jagIDP) validClaims() map[string]any {
	now := time.Now()
	return map[string]any{
		"iss":       i.issuer,
		"sub":       "u-alice",
		"aud":       jagOmegaIssuer,
		"client_id": jagAgent,
		"jti":       "jti-1",
		"iat":       now.Add(-10 * time.Second).Unix(),
		"exp":       now.Add(4 * time.Minute).Unix(),
		"scope":     "issues:read issues:write",
		"resource":  jagTool,
		"email":     "alice@example.com",
	}
}

type jagEnv struct {
	srv   *httptest.Server
	ca    identity.Authority
	store *storage.Store
	idp   *jagIDP
}

// permitIDJAG lets any client redeem an ID-JAG; the grant is always
// policy-gated, so every test server needs some permit.
const permitIDJAG = `permit (principal, action == Action::"token.id_jag", resource);`

func newJAGEnv(t *testing.T, cedarSrc string) *jagEnv {
	t.Helper()
	if cedarSrc == "" {
		cedarSrc = permitIDJAG
	}
	return newJAGEnvWith(t, cedarSrc, nil)
}

// newJAGEnvWith serves over mTLS with --require-auth when tca is non-nil.
func newJAGEnvWith(t *testing.T, cedarSrc string, tca *testCA) *jagEnv {
	t.Helper()
	dir := t.TempDir()
	store, err := storage.Open(filepath.Join(dir, "omega.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ca, err := identity.New(identity.Config{
		Kind:        identity.KindDisk,
		TrustDomain: "omega.local",
		Issuer:      jagOmegaIssuer,
		Dir:         filepath.Join(dir, "ca"),
	})
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	idp := newJAGIDP(t)
	reg, err := oidc.NewRegistry([]oidc.IDPConfig{{
		Name:             "corp",
		Issuer:           idp.issuer,
		Audiences:        []string{jagOmegaIssuer},
		SPIFFEIDTemplate: "spiffe://omega.local/humans/{idp}/{sub}",
		RequiredTyp:      api.IDJAGTyp,
		ExactAudience:    true,
	}})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	pdp := policy.New()
	s := api.NewServer(store, ca, pdp).
		WithRequireAuth(tca != nil).
		WithIDJAG(api.IDJAGConfig{Registry: reg, MTLSClientAuth: tca != nil})
	if cedarSrc != "" {
		pdir := t.TempDir()
		if err := os.WriteFile(filepath.Join(pdir, "p.cedar"), []byte(cedarSrc), 0o644); err != nil {
			t.Fatalf("write policy: %v", err)
		}
		if err := pdp.LoadDir(pdir); err != nil {
			t.Fatalf("load policy: %v", err)
		}
	}
	srv := httptest.NewUnstartedServer(s.Handler())
	if tca != nil {
		srv.TLS = &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{tca.issue(t, "omega-server", "", []net.IP{net.ParseIP("127.0.0.1")})},
			ClientCAs:    tca.pool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
		}
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return &jagEnv{srv: srv, ca: ca, store: store, idp: idp}
}

// clientAssertion mints a JWT-SVID for id usable as a jwt-spiffe client assertion.
func (e *jagEnv) clientAssertion(t *testing.T, id string, aud ...string) string {
	t.Helper()
	if len(aud) == 0 {
		aud = []string{jagOmegaIssuer}
	}
	svid, err := e.ca.IssueJWTSVID(spiffeid.RequireFromString(id), aud, time.Minute, nil)
	if err != nil {
		t.Fatalf("client assertion: %v", err)
	}
	return svid.Token
}

func (e *jagEnv) clientAssertionWith(t *testing.T, id string, extra map[string]any) string {
	t.Helper()
	svid, err := e.ca.IssueJWTSVID(spiffeid.RequireFromString(id), []string{jagOmegaIssuer}, time.Minute, extra)
	if err != nil {
		t.Fatalf("client assertion: %v", err)
	}
	return svid.Token
}

func (e *jagEnv) baseForm(t *testing.T, assertion string) url.Values {
	t.Helper()
	return url.Values{
		"grant_type":            {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":             {assertion},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"},
		"client_assertion":      {e.clientAssertion(t, jagAgent)},
	}
}

func postToken(t *testing.T, base string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	return postTokenWith(t, http.DefaultClient, base, form)
}

func postTokenWith(t *testing.T, c *http.Client, base string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := c.PostForm(base+"/oauth2/token", form)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("decode %q: %v", raw, err)
	}
	return resp, body
}

func TestIDJAGGrantIssuesDelegatedSVID(t *testing.T) {
	env := newJAGEnv(t, "")
	resp, body := postToken(t, env.srv.URL, env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %v", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q", got)
	}
	if body["token_type"] != "Bearer" || body["spiffe_id"] != jagAgent || body["scope"] != "issues:read issues:write" {
		t.Errorf("response: %v", body)
	}
	if exp, _ := body["expires_in"].(float64); exp <= 0 || exp > 240 {
		t.Errorf("expires_in %v must be capped at the assertion lifetime", exp)
	}
	chain, _ := body["delegation_chain"].([]any)
	if len(chain) != 2 || chain[0] != "spiffe://omega.local/humans/corp/u-alice" || chain[1] != jagAgent {
		t.Errorf("delegation_chain: %v", chain)
	}

	id, claims, err := env.ca.ParseJWTSVIDClaims(body["access_token"].(string))
	if err != nil {
		t.Fatalf("parse issued token: %v", err)
	}
	if id.String() != jagAgent {
		t.Errorf("sub = %s", id)
	}
	act, _ := claims["act"].(map[string]any)
	if act["sub"] != "spiffe://omega.local/humans/corp/u-alice" || act["kind"] != "id-jag" || act["upstream_sub"] != "u-alice" {
		t.Errorf("act: %v", act)
	}
	if aud, _ := claims["aud"].(string); aud != jagTool {
		if arr, _ := claims["aud"].([]any); len(arr) != 1 || arr[0] != jagTool {
			t.Errorf("aud: %v", claims["aud"])
		}
	}

	events, err := env.store.ListAudit(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var found bool
	for _, ev := range events {
		if ev.Kind == "token.id_jag" && ev.Decision == "allow" && ev.Actor == jagAgent {
			found = true
		}
	}
	if !found {
		t.Errorf("no token.id_jag allow audit row in %+v", events)
	}
}

func TestIDJAGGrantTokenExtendsThroughTokenExchange(t *testing.T) {
	env := newJAGEnv(t, "")
	_, body := postToken(t, env.srv.URL, env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())))
	subAgent := "spiffe://omega.local/agents/claude-code/github-tool"
	actor, err := env.ca.IssueJWTSVID(spiffeid.RequireFromString(subAgent), []string{"omega-internal"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("actor: %v", err)
	}
	resp, raw := postExchange(t, env.srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      body["access_token"].(string),
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        actor.Token,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: subAgent,
		Audience:          []string{jagTool},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status %d: %s", resp.StatusCode, raw)
	}
	var out api.TokenExchangeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{"spiffe://omega.local/humans/corp/u-alice", jagAgent, subAgent}
	if strings.Join(out.DelegationChain, ",") != strings.Join(want, ",") {
		t.Errorf("chain = %v, want %v", out.DelegationChain, want)
	}
}

func TestIDJAGGrantRejectsInvalidAssertions(t *testing.T) {
	env := newJAGEnv(t, "")
	cases := []struct {
		name   string
		typ    string
		mutate func(map[string]any)
	}{
		{"id token without typ", "", nil},
		{"wrong typ", "JWT", nil},
		{"aud is another server", api.IDJAGTyp, func(c map[string]any) { c["aud"] = "https://other.example.com" }},
		{"aud has two values", api.IDJAGTyp, func(c map[string]any) { c["aud"] = []string{jagOmegaIssuer, "https://other.example.com"} }},
		{"client_id is another client", api.IDJAGTyp, func(c map[string]any) { c["client_id"] = "spiffe://omega.local/agents/other" }},
		{"no client_id", api.IDJAGTyp, func(c map[string]any) { delete(c, "client_id") }},
		{"no jti", api.IDJAGTyp, func(c map[string]any) { delete(c, "jti") }},
		{"no iat", api.IDJAGTyp, func(c map[string]any) { delete(c, "iat") }},
		{"lifetime above the maximum", api.IDJAGTyp, func(c map[string]any) { c["exp"] = time.Now().Add(time.Hour).Unix() }},
		{"expired", api.IDJAGTyp, func(c map[string]any) {
			c["iat"] = time.Now().Add(-3 * time.Minute).Unix()
			c["exp"] = time.Now().Add(-2 * time.Minute).Unix()
		}},
		{"dpop bound", api.IDJAGTyp, func(c map[string]any) { c["cnf"] = map[string]any{"jkt": "abc"} }},
		{"unknown issuer", api.IDJAGTyp, func(c map[string]any) { c["iss"] = "https://unknown.example.com" }},
		{"sub with a slash", api.IDJAGTyp, func(c map[string]any) { c["sub"] = "admin/svc" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := env.idp.validClaims()
			if tc.mutate != nil {
				tc.mutate(claims)
			}
			resp, body := postToken(t, env.srv.URL, env.baseForm(t, env.idp.sign(t, tc.typ, claims)))
			if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
				t.Fatalf("got %d %v, want 400 invalid_grant", resp.StatusCode, body)
			}
		})
	}
}

func TestIDJAGGrantClientAuthentication(t *testing.T) {
	env := newJAGEnv(t, "")
	jag := env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())
	cases := []struct {
		name   string
		mutate func(url.Values)
		status int
		code   string
	}{
		{"no client auth", func(f url.Values) { f.Del("client_assertion"); f.Del("client_assertion_type") }, http.StatusUnauthorized, "invalid_client"},
		{"bearer assertion type", func(f url.Values) {
			f.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
		}, http.StatusUnauthorized, "invalid_client"},
		{"assertion aud is not omega", func(f url.Values) {
			f.Set("client_assertion", env.clientAssertion(t, jagAgent, "https://other.example.com"))
		}, http.StatusUnauthorized, "invalid_client"},
		{"assertion with extra aud", func(f url.Values) {
			f.Set("client_assertion", env.clientAssertion(t, jagAgent, jagOmegaIssuer, "https://other.example.com"))
		}, http.StatusUnauthorized, "invalid_client"},
		{"garbage assertion", func(f url.Values) { f.Set("client_assertion", "not-a-jwt") }, http.StatusUnauthorized, "invalid_client"},
		{"delegated token as assertion", func(f url.Values) {
			f.Set("client_assertion", env.clientAssertionWith(t, jagAgent, map[string]any{"act": map[string]any{"sub": "spiffe://omega.local/humans/x"}}))
		}, http.StatusUnauthorized, "invalid_client"},
		{"cert-bound token as assertion", func(f url.Values) {
			f.Set("client_assertion", env.clientAssertionWith(t, jagAgent, map[string]any{"cnf": map[string]any{"x5t#S256": "abc"}}))
		}, http.StatusUnauthorized, "invalid_client"},
		{"client_id param mismatch", func(f url.Values) { f.Set("client_id", "spiffe://omega.local/agents/other") }, http.StatusUnauthorized, "invalid_client"},
		{"other client presents the grant", func(f url.Values) {
			f.Set("client_assertion", env.clientAssertion(t, "spiffe://omega.local/agents/other"))
		}, http.StatusBadRequest, "invalid_grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := env.baseForm(t, jag)
			tc.mutate(form)
			resp, body := postToken(t, env.srv.URL, form)
			if resp.StatusCode != tc.status || body["error"] != tc.code {
				t.Fatalf("got %d %v, want %d %s", resp.StatusCode, body, tc.status, tc.code)
			}
		})
	}
}

func TestIDJAGGrantRequestValidation(t *testing.T) {
	env := newJAGEnv(t, "")
	jag := env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())
	cases := []struct {
		name   string
		mutate func(url.Values)
		code   string
	}{
		{"token exchange grant", func(f url.Values) { f.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange") }, "unsupported_grant_type"},
		{"no assertion", func(f url.Values) { f.Del("assertion") }, "invalid_request"},
		{"repeated parameter", func(f url.Values) { f.Add("assertion", "second") }, "invalid_request"},
		{"resource not granted", func(f url.Values) { f.Set("resource", "https://mcp.example.com/slack") }, "invalid_target"},
		{"scope not granted", func(f url.Values) { f.Set("scope", "admin") }, "invalid_scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			form := env.baseForm(t, jag)
			tc.mutate(form)
			resp, body := postToken(t, env.srv.URL, form)
			if resp.StatusCode != http.StatusBadRequest || body["error"] != tc.code {
				t.Fatalf("got %d %v, want 400 %s", resp.StatusCode, body, tc.code)
			}
		})
	}

	t.Run("json body", func(t *testing.T) {
		resp, err := http.Post(env.srv.URL+"/oauth2/token", "application/json", strings.NewReader(`{}`))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})

	t.Run("no resource anywhere", func(t *testing.T) {
		claims := env.idp.validClaims()
		delete(claims, "resource")
		resp, body := postToken(t, env.srv.URL, env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, claims)))
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_target" {
			t.Fatalf("got %d %v", resp.StatusCode, body)
		}
	})

	t.Run("resource requested but the assertion grants none", func(t *testing.T) {
		claims := env.idp.validClaims()
		delete(claims, "resource")
		form := env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, claims))
		form.Set("resource", "https://payroll.internal")
		resp, body := postToken(t, env.srv.URL, form)
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_target" {
			t.Fatalf("got %d %v", resp.StatusCode, body)
		}
	})

	t.Run("scope narrows", func(t *testing.T) {
		form := env.baseForm(t, jag)
		form.Set("scope", "issues:read")
		resp, body := postToken(t, env.srv.URL, form)
		if resp.StatusCode != http.StatusOK || body["scope"] != "issues:read" {
			t.Fatalf("got %d %v", resp.StatusCode, body)
		}
	})
}

func TestIDJAGGrantPolicyGate(t *testing.T) {
	allowAI := `permit (principal is Spiffe, action == Action::"token.id_jag", resource is Spiffe)
when { principal has kind && principal.kind == "ai" };`
	env := newJAGEnv(t, allowAI)
	resp, body := postToken(t, env.srv.URL, env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("allow: got %d %v", resp.StatusCode, body)
	}

	denyAll := `forbid (principal, action, resource);`
	env = newJAGEnv(t, denyAll)
	resp, body = postToken(t, env.srv.URL, env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())))
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("deny: got %d %v", resp.StatusCode, body)
	}
}

func TestIDJAGDisabledAndMetadata(t *testing.T) {
	plain := newTestServer(t)
	for _, path := range []string{"/oauth2/token", "/.well-known/oauth-authorization-server"} {
		var resp *http.Response
		var err error
		if path == "/oauth2/token" {
			resp, err = http.PostForm(plain.URL+path, url.Values{})
		} else {
			resp, err = http.Get(plain.URL + path)
		}
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("%s without ID-JAG: status %d, want 404", path, resp.StatusCode)
		}
	}

	env := newJAGEnv(t, "")
	resp, err := http.Get(env.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer resp.Body.Close()
	var md api.OAuthASMetadata
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if md.Issuer != jagOmegaIssuer || md.TokenEndpoint != jagOmegaIssuer+"/oauth2/token" {
		t.Errorf("metadata: %+v", md)
	}
	if len(md.GrantTypesSupported) != 1 || md.GrantTypesSupported[0] != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
		t.Errorf("grant_types_supported: %v", md.GrantTypesSupported)
	}
	if len(md.AuthorizationGrantProfilesSupported) != 1 || md.AuthorizationGrantProfilesSupported[0] != "urn:ietf:params:oauth:grant-profile:id-jag" {
		t.Errorf("authorization_grant_profiles_supported: %v", md.AuthorizationGrantProfilesSupported)
	}
	if len(md.TokenEndpointAuthMethodsSupported) != 1 || md.TokenEndpointAuthMethodsSupported[0] != "spiffe_jwt" {
		t.Errorf("auth methods without mTLS: %v", md.TokenEndpointAuthMethodsSupported)
	}
}

func TestIDJAGGrantAuditsRefusals(t *testing.T) {
	env := newJAGEnv(t, "")
	form := env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims()))
	form.Del("client_assertion")
	form.Del("client_assertion_type")
	postToken(t, env.srv.URL, form)

	form = env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims()))
	form.Set("scope", "admin")
	postToken(t, env.srv.URL, form)

	events, err := env.store.ListAudit(context.Background(), 0, 10)
	if err != nil {
		t.Fatalf("list audit: %v", err)
	}
	var deny int
	for _, ev := range events {
		if ev.Kind == "token.id_jag" && ev.Decision == "deny" {
			deny++
		}
	}
	if deny != 1 {
		t.Fatalf("want 1 token.id_jag deny row (invalid_scope; unauthenticated requests are not audited), got %d", deny)
	}
}

func TestIDJAGGrantMTLSClient(t *testing.T) {
	tca := newTestCA(t)
	env := newJAGEnvWith(t, permitIDJAG, tca)
	agentCert := tca.issue(t, "agent", jagAgent, nil)
	client := clientWith(tca, &agentCert)
	jag := env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())
	form := url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"},
		"assertion":  {jag},
	}

	resp, body := postTokenWith(t, client, env.srv.URL, form)
	if resp.StatusCode != http.StatusOK || body["spiffe_id"] != jagAgent {
		t.Fatalf("spiffe_x509: got %d %v", resp.StatusCode, body)
	}

	withJWT := url.Values{
		"grant_type":            form["grant_type"],
		"assertion":             form["assertion"],
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-spiffe"},
		"client_assertion":      {env.clientAssertion(t, jagAgent)},
	}
	resp, body = postTokenWith(t, client, env.srv.URL, withJWT)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_request" {
		t.Fatalf("cert + client_assertion: got %d %v, want 400 invalid_request", resp.StatusCode, body)
	}

	otherCert := tca.issue(t, "other", "spiffe://omega.local/agents/other", nil)
	resp, body = postTokenWith(t, clientWith(tca, &otherCert), env.srv.URL, form)
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("other agent's cert: got %d %v, want 400 invalid_grant", resp.StatusCode, body)
	}

	foreignCert := tca.issue(t, "foreign", "spiffe://elsewhere.example/agents/claude-code", nil)
	resp, body = postTokenWith(t, clientWith(tca, &foreignCert), env.srv.URL, form)
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("foreign trust domain: got %d %v, want 401 invalid_client", resp.StatusCode, body)
	}

	mresp, err := client.Get(env.srv.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}
	defer mresp.Body.Close()
	var md api.OAuthASMetadata
	if err := json.NewDecoder(mresp.Body).Decode(&md); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(md.TokenEndpointAuthMethodsSupported) != 1 || md.TokenEndpointAuthMethodsSupported[0] != "spiffe_x509" {
		t.Errorf("auth methods under mTLS: %v", md.TokenEndpointAuthMethodsSupported)
	}
}

func TestIDJAGGrantDeniedWithoutPolicy(t *testing.T) {
	env := newJAGEnvWith(t, "", nil)
	resp, body := postToken(t, env.srv.URL, env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())))
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("no permit policy: got %d %v, want 400 invalid_grant", resp.StatusCode, body)
	}
}

func TestIDJAGGrantWithholdsTokenWhenAuditFails(t *testing.T) {
	env := newJAGEnv(t, "")
	jag := env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())
	if err := env.store.Close(); err != nil {
		t.Fatalf("close store: %v", err)
	}
	resp, body := postToken(t, env.srv.URL, env.baseForm(t, jag))
	if resp.StatusCode != http.StatusInternalServerError || body["access_token"] != nil {
		t.Fatalf("audit unavailable: got %d %v, want 500 with no token", resp.StatusCode, body)
	}
}

func TestIDJAGGrantIgnoresTokenExchangePermits(t *testing.T) {
	env := newJAGEnv(t, `permit (principal, action == Action::"token.exchange", resource);`)
	resp, body := postToken(t, env.srv.URL, env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims())))
	if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_grant" {
		t.Fatalf("token.exchange permit must not authorize an ID-JAG grant: got %d %v", resp.StatusCode, body)
	}
}

func TestIDJAGClientAssertionLifetimeCap(t *testing.T) {
	env := newJAGEnv(t, "")
	long, err := env.ca.IssueJWTSVID(spiffeid.RequireFromString(jagAgent), []string{jagOmegaIssuer}, time.Hour, nil)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	form := env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims()))
	form.Set("client_assertion", long.Token)
	resp, body := postToken(t, env.srv.URL, form)
	if resp.StatusCode != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("hour-long client assertion: got %d %v, want 401 invalid_client", resp.StatusCode, body)
	}
}
