package api_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kanywst/omega/internal/server/api"
)

// issueJWT is a small wrapper around POST /v1/svid/jwt so the
// token-exchange tests can mint subject and actor tokens through the
// same surface a real client would.
func issueJWT(t *testing.T, srv string, sub string, audience []string) string {
	t.Helper()
	body, _ := json.Marshal(api.IssueJWTSVIDRequest{
		SPIFFEID:   sub,
		Audience:   audience,
		TTLSeconds: 600,
	})
	resp, err := http.Post(srv+"/v1/svid/jwt", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("issue jwt: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("issue jwt: status %d body=%s", resp.StatusCode, raw)
	}
	var out api.IssueJWTSVIDResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out.Token
}

func postExchange(t *testing.T, srv string, req api.TokenExchangeRequest) (*http.Response, []byte) {
	t.Helper()
	body, _ := json.Marshal(req)
	resp, err := http.Post(srv+"/v1/token/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post exchange: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}

func TestTokenExchangeBasic(t *testing.T) {
	srv := newTestServer(t)

	human := "spiffe://omega.local/humans/u-alice"
	agent := "spiffe://omega.local/agents/claude/inst-1"
	tool := "spiffe://omega.local/svc/github/issues"

	subjectTok := issueJWT(t, srv.URL, human, []string{"omega-internal"})
	actorTok := issueJWT(t, srv.URL, agent, []string{"omega-internal"})

	resp, raw := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      subjectTok,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        actorTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: agent,
		Audience:          []string{tool},
		Scope:             "github:issues:read",
		TTLSeconds:        120,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status: got %d want 200, body=%s", resp.StatusCode, raw)
	}
	var out api.TokenExchangeResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.SPIFFEID != agent {
		t.Errorf("sub: got %q want %q", out.SPIFFEID, agent)
	}
	if out.Scope != "github:issues:read" {
		t.Errorf("scope: %q", out.Scope)
	}
	if got, want := out.DelegationChain, []string{human, agent}; !equalStrings(got, want) {
		t.Errorf("chain: got %v want %v", got, want)
	}

	// Crack the issued token to confirm the nested act claim shape.
	parsed, err := jwt.ParseSigned(out.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatalf("parse output token: %v", err)
	}
	var claims map[string]any
	if err := parsed.UnsafeClaimsWithoutVerification(&claims); err != nil {
		t.Fatalf("read claims: %v", err)
	}
	if claims["sub"] != agent {
		t.Errorf("token sub: got %v want %s", claims["sub"], agent)
	}
	act, _ := claims["act"].(map[string]any)
	if act == nil || act["sub"] != human {
		t.Errorf("act.sub: got %v want %s", act, human)
	}
	if claims["scope"] != "github:issues:read" {
		t.Errorf("token scope: %v", claims["scope"])
	}
	// JWT serializes single-element aud as a string, multi-element as an array.
	switch a := claims["aud"].(type) {
	case string:
		if a != tool {
			t.Errorf("token aud: %q want %q", a, tool)
		}
	case []any:
		if len(a) != 1 || a[0] != tool {
			t.Errorf("token aud: %v", a)
		}
	default:
		t.Errorf("token aud: unexpected type %T (%v)", a, a)
	}

	// Audit row must capture the chain at kind=token.exchange.
	auditResp, err := http.Get(srv.URL + "/v1/audit?since=0")
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	defer auditResp.Body.Close()
	var auditOut struct {
		Items []struct {
			Kind     string          `json:"kind"`
			Actor    string          `json:"actor"`
			Subject  string          `json:"subject"`
			Decision string          `json:"decision"`
			Payload  json.RawMessage `json:"payload"`
		} `json:"items"`
	}
	if err := json.NewDecoder(auditResp.Body).Decode(&auditOut); err != nil {
		t.Fatalf("decode audit: %v", err)
	}
	var found bool
	for _, ev := range auditOut.Items {
		if ev.Kind != "token.exchange" {
			continue
		}
		found = true
		if ev.Actor != agent {
			t.Errorf("audit actor: got %q want %q", ev.Actor, agent)
		}
		if ev.Subject != human {
			t.Errorf("audit subject (root principal): got %q want %q", ev.Subject, human)
		}
		if ev.Decision != "allow" {
			t.Errorf("audit decision: %q", ev.Decision)
		}
		var payload struct {
			Chain []string `json:"chain"`
			Scope string   `json:"scope"`
		}
		if err := json.Unmarshal(ev.Payload, &payload); err != nil {
			t.Fatalf("payload unmarshal: %v", err)
		}
		if !equalStrings(payload.Chain, []string{human, agent}) {
			t.Errorf("audit chain: %v", payload.Chain)
		}
		if payload.Scope != "github:issues:read" {
			t.Errorf("audit scope: %q", payload.Scope)
		}
	}
	if !found {
		t.Fatalf("no token.exchange audit row found in %d items", len(auditOut.Items))
	}
}

func TestTokenExchangeMultiHopNests(t *testing.T) {
	srv := newTestServer(t)
	human := "spiffe://omega.local/humans/u-alice"
	coord := "spiffe://omega.local/agents/coordinator/inst-1"
	sub := "spiffe://omega.local/agents/researcher/inst-1"
	tool := "spiffe://omega.local/svc/notion/pages"

	humanTok := issueJWT(t, srv.URL, human, []string{"omega-internal"})
	coordTok := issueJWT(t, srv.URL, coord, []string{"omega-internal"})
	subTok := issueJWT(t, srv.URL, sub, []string{"omega-internal"})

	// Hop 1: human → coordinator
	resp1, raw1 := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      humanTok,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        coordTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: coord,
		Audience:          []string{"omega-internal"},
		TTLSeconds:        120,
	})
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("hop1: %d %s", resp1.StatusCode, raw1)
	}
	var hop1 api.TokenExchangeResponse
	_ = json.Unmarshal(raw1, &hop1)

	// Hop 2: (human → coordinator) → sub-agent. Subject token is now
	// the hop1 output, which already carries act={sub:human}.
	resp2, raw2 := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      hop1.AccessToken,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        subTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: sub,
		Audience:          []string{tool},
		TTLSeconds:        60,
	})
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("hop2: %d %s", resp2.StatusCode, raw2)
	}
	var hop2 api.TokenExchangeResponse
	_ = json.Unmarshal(raw2, &hop2)
	if got, want := hop2.DelegationChain, []string{human, coord, sub}; !equalStrings(got, want) {
		t.Errorf("hop2 chain: got %v want %v", got, want)
	}

	// Inner act.act must reach back to the human at the bottom.
	parsed, _ := jwt.ParseSigned(hop2.AccessToken, []jose.SignatureAlgorithm{jose.ES256})
	var claims map[string]any
	_ = parsed.UnsafeClaimsWithoutVerification(&claims)
	a1, _ := claims["act"].(map[string]any)
	if a1["sub"] != coord {
		t.Errorf("hop2 act.sub: got %v want %s", a1["sub"], coord)
	}
	a2, _ := a1["act"].(map[string]any)
	if a2["sub"] != human {
		t.Errorf("hop2 act.act.sub: got %v want %s", a2["sub"], human)
	}
}

func TestTokenExchangeRejectsImpersonation(t *testing.T) {
	srv := newTestServer(t)
	human := "spiffe://omega.local/humans/u-alice"
	agent := "spiffe://omega.local/agents/claude/inst-1"
	other := "spiffe://omega.local/agents/evil/inst-1"

	subjectTok := issueJWT(t, srv.URL, human, []string{"omega-internal"})
	actorTok := issueJWT(t, srv.URL, agent, []string{"omega-internal"})

	// agent's token cannot get a delegated identity for some other agent.
	resp, raw := postExchange(t, srv.URL, api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      subjectTok,
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        actorTok,
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: other,
		Audience:          []string{"omega-internal"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status: got %d want 403, body=%s", resp.StatusCode, raw)
	}
}

func TestTokenExchangeBadInputs(t *testing.T) {
	srv := newTestServer(t)
	good := api.TokenExchangeRequest{
		GrantType:         "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken:      "x",
		SubjectTokenType:  "urn:ietf:params:oauth:token-type:jwt",
		ActorToken:        "x",
		ActorTokenType:    "urn:ietf:params:oauth:token-type:jwt",
		RequestedSPIFFEID: "spiffe://omega.local/agents/x",
		Audience:          []string{"a"},
	}
	cases := []struct {
		name string
		mut  func(*api.TokenExchangeRequest)
	}{
		{"empty grant_type", func(r *api.TokenExchangeRequest) { r.GrantType = "" }},
		{"wrong grant_type", func(r *api.TokenExchangeRequest) { r.GrantType = "client_credentials" }},
		{"empty subject_token", func(r *api.TokenExchangeRequest) { r.SubjectToken = "" }},
		{"unsupported subject_token_type", func(r *api.TokenExchangeRequest) {
			r.SubjectTokenType = "urn:ietf:params:oauth:token-type:saml2"
		}},
		{"empty actor_token", func(r *api.TokenExchangeRequest) { r.ActorToken = "" }},
		{"missing requested_spiffe_id", func(r *api.TokenExchangeRequest) { r.RequestedSPIFFEID = "" }},
		{"missing audience", func(r *api.TokenExchangeRequest) { r.Audience = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := good
			tc.mut(&req)
			resp, raw := postExchange(t, srv.URL, req)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("status: got %d want 400, body=%s", resp.StatusCode, raw)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
