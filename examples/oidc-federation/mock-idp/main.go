// mock-idp is a tiny OIDC identity provider for the
// examples/oidc-federation demo. It generates an ECDSA P-256 key
// pair at startup and serves the minimal OIDC surface omega
// consumes:
//
//	GET  /.well-known/openid-configuration
//	GET  /jwks.json
//	POST /sign       -- demo-only helper: returns a freshly signed ID token
//	GET  /authorize  -- authorization code flow with PKCE (S256)
//	POST /token      -- code and refresh_token grants
//
// The /sign endpoint is what makes this binary an "IdP that you can
// drive from a shell script": omega itself only validates ID tokens, so
// the oidc-federation demo POSTs a JSON description of the claims it
// wants. /authorize and /token serve a web UI that signs people in
// (examples/ui-auth). /authorize has no login page: it signs in the
// person named by --login-username at once, so a script can follow the
// redirects.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"log"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// signRequest is the body of POST /sign. Empty fields fall back to a
// sensible demo default so a callers can run with `curl -d '{}'`.
type signRequest struct {
	Sub               string         `json:"sub"`
	Aud               []string       `json:"aud"`
	PreferredUsername string         `json:"preferred_username,omitempty"`
	Email             string         `json:"email,omitempty"`
	Name              string         `json:"name,omitempty"`
	TTLSeconds        int            `json:"ttl_seconds,omitempty"`
	Extra             map[string]any `json:"extra,omitempty"`
}

type signResponse struct {
	IDToken string `json:"id_token"`
}

// grant is what an authorization code or a refresh token stands for.
type grant struct {
	clientID    string
	redirectURI string
	challenge   string
	nonce       string
	expires     time.Time
}

// grants holds the outstanding codes and refresh tokens. Each is
// single use.
type grants struct {
	mu sync.Mutex
	m  map[string]grant
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("mock-idp: rand: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (g *grants) put(v grant) string {
	k := randomToken()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.m[k] = v
	return k
}

func (g *grants) take(k string) (grant, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	v, ok := g.m[k]
	delete(g.m, k)
	return v, ok && time.Now().Before(v.expires)
}

// tokenError answers an RFC 6749 section 5.2 error.
func tokenError(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

func main() {
	addr := flag.String("addr", "127.0.0.1:18190", "listen address")
	clientID := flag.String("client-id", "omega-ui", "client_id of the one client /authorize and /token serve")
	clientSecret := flag.String("client-secret", "", "client secret the client must present at /token; empty for a public client")
	redirectURI := flag.String("redirect-uri", "", "the client's registered redirect URI; /authorize refuses any other")
	loginSub := flag.String("login-sub", "alice@example.com", "sub of the person /authorize signs in")
	loginUsername := flag.String("login-username", "alice", "preferred_username of the person /authorize signs in")
	idTokenTTL := flag.Duration("id-token-ttl", 5*time.Minute, "lifetime of the ID tokens /token issues")
	flag.Parse()
	pending := &grants{m: map[string]grant{}}

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("mock-idp: gen key: %v", err)
	}
	const kid = "mock-idp-1"
	signer, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: jose.ES256,
			Key:       jose.JSONWebKey{Key: priv, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"},
		},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		log.Fatalf("mock-idp: new signer: %v", err)
	}
	pub := jose.JSONWebKey{Key: priv.Public(), KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}

	issuer := "http://" + *addr
	mux := http.NewServeMux()

	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"jwks_uri":                              issuer + "/jwks.json",
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"response_types_supported":              []string{"code", "id_token"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"ES256"},
		})
	})

	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}})
	})

	mux.HandleFunc("/sign", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req signRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "decode: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Sub == "" {
			req.Sub = "alice@example.com"
		}
		if len(req.Aud) == 0 {
			req.Aud = []string{"omega-clients"}
		}
		if req.TTLSeconds <= 0 {
			req.TTLSeconds = 300
		}
		now := time.Now()
		std := jwt.Claims{
			Issuer:   issuer,
			Subject:  req.Sub,
			Audience: jwt.Audience(req.Aud),
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(time.Duration(req.TTLSeconds) * time.Second)),
		}
		extra := map[string]any{}
		if req.PreferredUsername != "" {
			extra["preferred_username"] = req.PreferredUsername
		}
		if req.Email != "" {
			extra["email"] = req.Email
		}
		if req.Name != "" {
			extra["name"] = req.Name
		}
		for k, v := range req.Extra {
			extra[k] = v
		}
		builder := jwt.Signed(signer).Claims(std)
		if len(extra) > 0 {
			builder = builder.Claims(extra)
		}
		tok, err := builder.Serialize()
		if err != nil {
			http.Error(w, "sign: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(signResponse{IDToken: tok})
	})

	signIDToken := func(nonce string) (string, error) {
		now := time.Now()
		std := jwt.Claims{
			Issuer:   issuer,
			Subject:  *loginSub,
			Audience: jwt.Audience{*clientID},
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(*idTokenTTL)),
		}
		extra := map[string]any{"preferred_username": *loginUsername, "email": *loginSub}
		if nonce != "" {
			extra["nonce"] = nonce
		}
		return jwt.Signed(signer).Claims(std).Claims(extra).Serialize()
	}

	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != *clientID || *redirectURI == "" || q.Get("redirect_uri") != *redirectURI {
			// Never redirect to an unregistered URI.
			http.Error(w, "unknown client_id or redirect_uri", http.StatusBadRequest)
			return
		}
		back, err := url.Parse(*redirectURI)
		if err != nil {
			http.Error(w, "redirect_uri: "+err.Error(), http.StatusBadRequest)
			return
		}
		v := url.Values{}
		if state := q.Get("state"); state != "" {
			v.Set("state", state)
		}
		switch {
		case q.Get("response_type") != "code":
			v.Set("error", "unsupported_response_type")
		case q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "":
			v.Set("error", "invalid_request")
			v.Set("error_description", "PKCE with S256 is required")
		default:
			v.Set("code", pending.put(grant{
				clientID: *clientID, redirectURI: *redirectURI, challenge: q.Get("code_challenge"),
				nonce: q.Get("nonce"), expires: time.Now().Add(time.Minute),
			}))
		}
		back.RawQuery = v.Encode()
		http.Redirect(w, r, back.String(), http.StatusFound)
	})

	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			tokenError(w, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		id, secret, basic := r.BasicAuth()
		if !basic {
			id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		if id != *clientID || subtle.ConstantTimeCompare([]byte(secret), []byte(*clientSecret)) != 1 {
			tokenError(w, http.StatusUnauthorized, "invalid_client", "unknown client or wrong secret")
			return
		}
		var g grant
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			var ok bool
			g, ok = pending.take(r.PostForm.Get("code"))
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			if !ok || g.clientID != id || g.redirectURI != r.PostForm.Get("redirect_uri") ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
				tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired code, or wrong redirect_uri or code_verifier")
				return
			}
		case "refresh_token":
			var ok bool
			g, ok = pending.take(r.PostForm.Get("refresh_token"))
			if !ok || g.clientID != id {
				tokenError(w, http.StatusBadRequest, "invalid_grant", "unknown, used or expired refresh token")
				return
			}
			// A refreshed ID token carries no nonce (OIDC Core 12.2).
			g.nonce = ""
		default:
			tokenError(w, http.StatusBadRequest, "unsupported_grant_type", "authorization_code or refresh_token")
			return
		}
		tok, err := signIDToken(g.nonce)
		if err != nil {
			tokenError(w, http.StatusInternalServerError, "server_error", err.Error())
			return
		}
		g.expires = time.Now().Add(time.Hour)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  randomToken(),
			"token_type":    "Bearer",
			"expires_in":    int(idTokenTTL.Seconds()),
			"id_token":      tok,
			"refresh_token": pending.put(g),
		})
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("mock-idp: issuer=%s listening", issuer)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("mock-idp: listen: %v", err)
	}
}
