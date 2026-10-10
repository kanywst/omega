package api_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/api"
)

type dpopKey struct {
	priv *ecdsa.PrivateKey
	jkt  string
}

func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	pub := jose.JSONWebKey{Key: priv.Public()}
	sum, err := pub.Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return dpopKey{priv: priv, jkt: base64.RawURLEncoding.EncodeToString(sum)}
}

func (k dpopKey) proof(t *testing.T, htm, htu string, iat time.Time, jti string) string {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: k.priv},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	payload, _ := json.Marshal(map[string]any{"jti": jti, "htm": htm, "htu": htu, "iat": iat.Unix()})
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := jws.CompactSerialize()
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}
	return out
}

func postWithDPoP(t *testing.T, target, contentType, body, proof string) (*http.Response, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", contentType)
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

const tokenEndpoint = jagOmegaIssuer + "/oauth2/token"

func TestIDJAGGrantDPoP(t *testing.T) {
	env := newJAGEnv(t, "")
	key := newDPoPKey(t)
	bound := func() url.Values {
		c := env.idp.validClaims()
		c["cnf"] = map[string]any{"jkt": key.jkt}
		return env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, c))
	}
	post := func(form url.Values, proof string) (*http.Response, map[string]any) {
		return postWithDPoP(t, env.srv.URL+"/oauth2/token", "application/x-www-form-urlencoded", form.Encode(), proof)
	}

	t.Run("bound assertion with matching proof", func(t *testing.T) {
		resp, body := post(bound(), key.proof(t, "POST", tokenEndpoint, time.Now(), "p1"))
		if resp.StatusCode != http.StatusOK || body["token_type"] != "DPoP" {
			t.Fatalf("got %d %v", resp.StatusCode, body)
		}
		_, claims, err := env.ca.ParseJWTSVIDClaims(body["access_token"].(string))
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		cnf, _ := claims["cnf"].(map[string]any)
		if cnf["jkt"] != key.jkt {
			t.Errorf("issued cnf = %v, want jkt %s", claims["cnf"], key.jkt)
		}
	})

	other := newDPoPKey(t)
	cases := []struct {
		name  string
		proof string
		code  string
	}{
		{"no proof", "", "invalid_grant"},
		{"proof from another key", other.proof(t, "POST", tokenEndpoint, time.Now(), "p2"), "invalid_grant"},
		{"replayed proof", key.proof(t, "POST", tokenEndpoint, time.Now(), "p1"), "invalid_dpop_proof"},
		{"wrong htu", key.proof(t, "POST", jagOmegaIssuer+"/v1/token/exchange", time.Now(), "p3"), "invalid_dpop_proof"},
		{"wrong htm", key.proof(t, "GET", tokenEndpoint, time.Now(), "p4"), "invalid_dpop_proof"},
		{"stale iat", key.proof(t, "POST", tokenEndpoint, time.Now().Add(-5*time.Minute), "p5"), "invalid_dpop_proof"},
		{"oversized jti", key.proof(t, "POST", tokenEndpoint, time.Now(), strings.Repeat("j", 300)), "invalid_dpop_proof"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, body := post(bound(), tc.proof)
			if resp.StatusCode != http.StatusBadRequest || body["error"] != tc.code {
				t.Fatalf("got %d %v, want 400 %s", resp.StatusCode, body, tc.code)
			}
		})
	}

	t.Run("unbound assertion with a proof is bound to it", func(t *testing.T) {
		form := env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims()))
		resp, body := post(form, other.proof(t, "POST", tokenEndpoint, time.Now(), "p6"))
		if resp.StatusCode != http.StatusOK || body["token_type"] != "DPoP" {
			t.Fatalf("got %d %v", resp.StatusCode, body)
		}
	})

	t.Run("unbound assertion with a bad proof", func(t *testing.T) {
		form := env.baseForm(t, env.idp.sign(t, api.IDJAGTyp, env.idp.validClaims()))
		resp, body := post(form, "not-a-proof")
		if resp.StatusCode != http.StatusBadRequest || body["error"] != "invalid_dpop_proof" {
			t.Fatalf("got %d %v", resp.StatusCode, body)
		}
	})
}

func TestTokenExchangeHonoursSubjectBinding(t *testing.T) {
	env := newJAGEnv(t, "")
	key := newDPoPKey(t)
	exchangeURL := jagOmegaIssuer + "/v1/token/exchange"
	subAgent := "spiffe://omega.local/agents/claude-code/github-tool"
	actor, err := env.ca.IssueJWTSVID(spiffeid.RequireFromString(subAgent), []string{"omega-internal"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("actor: %v", err)
	}
	exchange := func(subject, proof string) (*http.Response, map[string]any) {
		body, _ := json.Marshal(api.TokenExchangeRequest{
			GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
			SubjectToken:      subject,
			SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
			ActorToken:        actor.Token,
			ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
			RequestedSPIFFEID: subAgent,
			Audience:          []string{jagTool},
		})
		return postWithDPoP(t, env.srv.URL+"/v1/token/exchange", "application/json", string(body), proof)
	}

	dpopBound, err := env.ca.IssueJWTSVID(spiffeid.RequireFromString(jagAgent), []string{jagTool}, time.Minute,
		map[string]any{"cnf": map[string]any{"jkt": key.jkt}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if resp, body := exchange(dpopBound.Token, ""); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("DPoP-bound subject without proof: got %d %v", resp.StatusCode, body)
	}
	if resp, body := exchange(dpopBound.Token, key.proof(t, "POST", exchangeURL, time.Now(), "x1")); resp.StatusCode != http.StatusOK {
		t.Fatalf("DPoP-bound subject with proof: got %d %v", resp.StatusCode, body)
	}

	// The key holder exchanging its bound token with itself keeps the binding.
	selfBody, _ := json.Marshal(api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      dpopBound.Token,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        dpopBound.Token,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: jagAgent,
		Audience:          []string{"https://elsewhere.example.com"},
	})
	resp, body := postWithDPoP(t, env.srv.URL+"/v1/token/exchange", "application/json", string(selfBody), key.proof(t, "POST", exchangeURL, time.Now(), "x2"))
	if resp.StatusCode != http.StatusOK || body["token_type"] != "DPoP" {
		t.Fatalf("self-exchange of a bound token: got %d %v, want 200 DPoP", resp.StatusCode, body)
	}
	_, claims, err := env.ca.ParseJWTSVIDClaims(body["access_token"].(string))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cnf, _ := claims["cnf"].(map[string]any); cnf["jkt"] != key.jkt {
		t.Fatalf("self-exchange dropped the binding: cnf = %v", claims["cnf"])
	}

	certBound, err := env.ca.IssueJWTSVID(spiffeid.RequireFromString(jagAgent), []string{jagTool}, time.Minute,
		map[string]any{"cnf": map[string]any{"x5t#S256": "AAAA"}})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if resp, body := exchange(certBound.Token, ""); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("cert-bound subject without its cert: got %d %v", resp.StatusCode, body)
	}
}

func TestSameTargetURINormalisation(t *testing.T) {
	if !api.SameTargetURIForTest("https://Omega.Example.com:443/oauth2/token?x=1#f", "https://omega.example.com/oauth2/token") {
		t.Error("case, default port, query and fragment must not matter")
	}
	if api.SameTargetURIForTest("https://omega.example.com:8443/oauth2/token", "https://omega.example.com/oauth2/token") {
		t.Error("a non-default port must matter")
	}
	if api.SameTargetURIForTest("http://omega.example.com/oauth2/token", "https://omega.example.com/oauth2/token") {
		t.Error("the scheme must matter")
	}
}
