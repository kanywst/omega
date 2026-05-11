// mock-idp is a tiny OIDC identity provider for the
// examples/oidc-federation demo. It generates an ECDSA P-256 key
// pair at startup and serves the minimal OIDC surface omega
// consumes:
//
//   GET  /.well-known/openid-configuration
//   GET  /jwks.json
//   POST /sign  -- demo-only helper: returns a freshly signed ID token
//
// The /sign endpoint is what makes this binary an "IdP that you can
// drive from a shell script". A real IdP would issue tokens through
// /authorize + /token after a user login; omega never calls those
// surfaces, so we skip them and let the demo POST a JSON description
// of the desired claims instead.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"log"
	"net/http"
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

func main() {
	addr := flag.String("addr", "127.0.0.1:18190", "listen address")
	flag.Parse()

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
			"response_types_supported":              []string{"id_token"},
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
