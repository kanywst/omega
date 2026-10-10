// idp is a stand-in enterprise IdP for the ID-JAG demo. It signs an ID
// token for a user (in place of a real SSO login) and, through RFC 8693
// token exchange, turns that ID token into an ID-JAG for one downstream
// authorization server: omega.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

type idp struct {
	issuer       string
	key          *ecdsa.PrivateKey
	clientID     string
	clientSecret string
	clientAtRAS  string
	rasIssuer    string
}

func main() {
	var (
		addr         = flag.String("addr", "127.0.0.1:19100", "listen address")
		clientID     = flag.String("client-id", "claude-code", "the agent's client_id at this IdP")
		clientSecret = flag.String("client-secret", "demo-secret", "the agent's client secret at this IdP")
		clientAtRAS  = flag.String("client-at-ras", "spiffe://omega.local/agents/claude-code", "the agent's client_id at omega (its SPIFFE ID)")
		rasIssuer    = flag.String("ras-issuer", "https://omega.demo.local", "omega's issuer URL; the only audience this IdP issues ID-JAGs for")
	)
	flag.Parse()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	p := &idp{
		issuer: "http://" + *addr, key: key,
		clientID: *clientID, clientSecret: *clientSecret,
		clientAtRAS: *clientAtRAS, rasIssuer: *rasIssuer,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"issuer": p.issuer, "jwks_uri": p.issuer + "/jwks.json", "token_endpoint": p.issuer + "/token"})
	})
	mux.HandleFunc("GET /jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: key.Public(), KeyID: "idp-1", Algorithm: string(jose.ES256), Use: "sig"}}})
	})
	mux.HandleFunc("POST /login", p.login)
	mux.HandleFunc("POST /token", p.token)
	log.Printf("idp listening on %s", *addr)
	log.Fatal((&http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
}

// login stands in for SSO: it returns an ID token for the named user,
// issued to the agent's client_id.
func (p *idp) login(w http.ResponseWriter, r *http.Request) {
	user := r.FormValue("user")
	if user == "" {
		oauthErr(w, "invalid_request", "user is required")
		return
	}
	now := time.Now()
	tok, err := p.sign("JWT", map[string]any{
		"iss": p.issuer, "sub": user, "aud": p.clientID,
		"email": user + "@example.com", "iat": now.Unix(), "exp": now.Add(time.Hour).Unix(),
	})
	if err != nil {
		oauthErr(w, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id_token": tok})
}

// token implements the IdP half of the ID-JAG flow.
func (p *idp) token(w http.ResponseWriter, r *http.Request) {
	if r.FormValue("client_id") != p.clientID || r.FormValue("client_secret") != p.clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	if r.FormValue("grant_type") != "urn:ietf:params:oauth:grant-type:token-exchange" ||
		r.FormValue("requested_token_type") != "urn:ietf:params:oauth:token-type:id-jag" ||
		r.FormValue("subject_token_type") != "urn:ietf:params:oauth:token-type:id_token" {
		oauthErr(w, "invalid_request", "expected a token exchange for an id-jag from an id_token")
		return
	}
	if r.FormValue("audience") != p.rasIssuer {
		oauthErr(w, "invalid_grant", "audience validation failed")
		return
	}
	user, err := p.verifyIDToken(r.FormValue("subject_token"))
	if err != nil {
		oauthErr(w, "invalid_grant", err.Error())
		return
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	now := time.Now()
	claims := map[string]any{
		"iss": p.issuer, "sub": user, "aud": p.rasIssuer, "client_id": p.clientAtRAS,
		"jti": hex.EncodeToString(jti), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
	}
	if s := strings.TrimSpace(r.FormValue("scope")); s != "" {
		claims["scope"] = s
	}
	if res := r.FormValue("resource"); res != "" {
		claims["resource"] = res
	}
	jag, err := p.sign("oauth-id-jag+jwt", claims)
	if err != nil {
		oauthErr(w, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":      jag,
		"issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
		"token_type":        "N_A",
		"expires_in":        300,
		"scope":             claims["scope"],
	})
}

func (p *idp) verifyIDToken(raw string) (string, error) {
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return "", err
	}
	var c jwt.Claims
	if err := parsed.Claims(&p.key.PublicKey, &c); err != nil {
		return "", err
	}
	if err := c.Validate(jwt.Expected{Issuer: p.issuer, AnyAudience: jwt.Audience{p.clientID}, Time: time.Now()}); err != nil {
		return "", err
	}
	return c.Subject, nil
}

func (p *idp) sign(typ string, claims map[string]any) (string, error) {
	signer, err := jose.NewSigner(jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jose.JSONWebKey{Key: p.key, KeyID: "idp-1", Algorithm: string(jose.ES256)},
	}, (&jose.SignerOptions{}).WithType(jose.ContentType(typ)))
	if err != nil {
		return "", err
	}
	return jwt.Signed(signer).Claims(claims).Serialize()
}

func oauthErr(w http.ResponseWriter, code, desc string) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": code, "error_description": desc})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
