package identity_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/kanywst/omega/internal/server/identity"
)

// spireJWKS encodes pub the way go-spiffe's jwtbundle.Marshal does for a
// SPIRE trust domain: kty, kid and the key members, with no alg or use.
func spireJWKS(t *testing.T, kid string, pub crypto.PublicKey) []byte {
	t.Helper()
	out, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: pub, KeyID: kid}}})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return out
}

func signWith(t *testing.T, alg jose.SignatureAlgorithm, key crypto.Signer, kid string, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func svidClaims(td string) map[string]any {
	return map[string]any{
		"sub": "spiffe://" + td + "/workload/web",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(time.Minute).Unix(),
	}
}

func genKey(t *testing.T, alg jose.SignatureAlgorithm) crypto.Signer {
	t.Helper()
	var (
		key crypto.Signer
		err error
	)
	switch alg {
	case jose.ES256:
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case jose.ES384:
		key, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case jose.RS256:
		key, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		t.Fatalf("no key for %s", alg)
	}
	if err != nil {
		t.Fatalf("gen %s key: %v", alg, err)
	}
	return key
}

// Each jwt_key_type SPIRE offers (ec-p256, ec-p384, rsa-2048 / rsa-4096)
// signs JWT-SVIDs with a different algorithm. omega has to validate all of
// them, so an upstream SPIRE does not have to change its key type for it.
func TestUpstreamSourceValidatesEverySPIREJWTKeyType(t *testing.T) {
	const td = "upstream.example"
	for _, alg := range identity.JWTSVIDAlgs {
		t.Run(string(alg), func(t *testing.T) {
			key := genKey(t, alg)
			src, err := identity.NewUpstreamSourceWithJWT(td, "", upstreamBundle(t), spireJWKS(t, "k1", key.Public()))
			if err != nil {
				t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
			}

			served, err := src.JWTBundle()
			if err != nil {
				t.Fatalf("JWTBundle: %v", err)
			}
			var set jose.JSONWebKeySet
			if err := json.Unmarshal(served, &set); err != nil {
				t.Fatalf("served JWKS: %v", err)
			}
			if len(set.Keys) != 1 || set.Keys[0].Algorithm != string(alg) || set.Keys[0].Use != "sig" {
				t.Fatalf("served %s, want one %s signing key", served, alg)
			}

			id, err := src.ValidateJWTSVID(signWith(t, alg, key, "k1", svidClaims(td)), "https://api.example.com")
			if err != nil {
				t.Fatalf("ValidateJWTSVID: %v", err)
			}
			if id.String() != "spiffe://"+td+"/workload/web" {
				t.Fatalf("id = %s", id)
			}
		})
	}
}

// A key verifies only the algorithm its type is pinned to, so a token's alg
// header cannot pick how its own signature is checked.
func TestUpstreamSourceRejectsAlgOtherThanTheKeys(t *testing.T) {
	const td = "upstream.example"
	p384 := genKey(t, jose.ES384)
	src, err := identity.NewUpstreamSourceWithJWT(td, "", upstreamBundle(t), spireJWKS(t, "k384", p384.Public()))
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	tok := signWith(t, jose.ES256, genKey(t, jose.ES256), "k384", svidClaims(td))
	_, err = src.ValidateJWTSVID(tok, "https://api.example.com")
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("ValidateJWTSVID = %v, want an alg mismatch", err)
	}

	// PS256 is an algorithm an RSA key could verify, but not one a
	// JWT-SVID is signed with.
	rsaKey := genKey(t, jose.RS256)
	src, err = identity.NewUpstreamSourceWithJWT(td, "", upstreamBundle(t), spireJWKS(t, "rsa", rsaKey.Public()))
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	if _, err := src.ValidateJWTSVID(signWith(t, jose.PS256, rsaKey, "rsa", svidClaims(td)), "https://api.example.com"); err == nil {
		t.Fatal("ValidateJWTSVID accepted a PS256 token")
	}
}

func TestNewUpstreamSourceWithJWTRejectsCorruptRSAAndP384Keys(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024) //nolint:gosec // deliberately too small: the case under test
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	good := genKey(t, jose.RS256).Public()
	var rsaJWK map[string]any
	if err := json.Unmarshal(spireJWKS(t, "a", good), &struct {
		Keys []*map[string]any `json:"keys"`
	}{Keys: []*map[string]any{&rsaJWK}}); err != nil {
		t.Fatalf("decode rsa jwk: %v", err)
	}
	nb, err := base64.RawURLEncoding.DecodeString(rsaJWK["n"].(string))
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	paddedN := base64.RawURLEncoding.EncodeToString(append([]byte{0}, nb...))
	x, y := validP256XY(t)

	cases := map[string][]byte{
		"RSA under 2048 bits": spireJWKS(t, "a", &small.PublicKey),
		"RSA even exponent":   fmt.Appendf(nil, `{"keys":[{"kty":"RSA","kid":"a","n":%q,"e":"Ag"}]}`, rsaJWK["n"]),
		"RSA n leading zero":  fmt.Appendf(nil, `{"keys":[{"kty":"RSA","kid":"a","n":%q,"e":"AQAB"}]}`, paddedN),
		"RSA missing kid":     fmt.Appendf(nil, `{"keys":[{"kty":"RSA","n":%q,"e":"AQAB"}]}`, rsaJWK["n"]),
		// P-256-sized coordinates on a P-384 key.
		"P-384 short coordinates": fmt.Appendf(nil, `{"keys":[{"kty":"EC","crv":"P-384","kid":"a","x":%q,"y":%q}]}`, x, y),
	}
	for name, jwks := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := identity.NewUpstreamSourceWithJWT("upstream.example", "", upstreamBundle(t), jwks); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}
