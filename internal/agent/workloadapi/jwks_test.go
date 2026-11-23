package workloadapi

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The control plane re-serves an upstream SPIRE's JWT keys at
// /v1/jwt/bundle, and the agent validates JWT-SVIDs against that bundle
// locally. Every key type the control plane accepts has to validate here
// too, or a token omega's server accepts is refused by its own agent.
func TestValidateAgainstJWKSAcceptsEverySPIREKeyType(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen rsa: %v", err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p384: %v", err)
	}
	p256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen p256: %v", err)
	}
	cases := []struct {
		alg jose.SignatureAlgorithm
		key crypto.Signer
	}{
		{jose.ES256, p256},
		{jose.ES384, p384},
		{jose.RS256, rsaKey},
	}
	for _, tc := range cases {
		t.Run(string(tc.alg), func(t *testing.T) {
			// The shape the control plane serves: alg and use set.
			jwks, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
				Key: tc.key.Public(), KeyID: "k1", Algorithm: string(tc.alg), Use: "sig",
			}}})
			if err != nil {
				t.Fatalf("marshal jwks: %v", err)
			}
			cp := newControlPlaneFixture(t, string(jwks), generateFixtureBundlePEM(t))
			s := NewServer(cp.server.URL, nil)

			sign := func(alg jose.SignatureAlgorithm, key crypto.Signer) string {
				signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key},
					(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
				if err != nil {
					t.Fatalf("signer: %v", err)
				}
				tok, err := jwt.Signed(signer).Claims(map[string]any{
					"sub": "spiffe://omega.local/workload/web",
					"aud": []string{"api"},
					"exp": time.Now().Add(time.Minute).Unix(),
				}).Serialize()
				if err != nil {
					t.Fatalf("sign: %v", err)
				}
				return tok
			}

			sub, _, err := validateAgainstJWKS(context.Background(), s, sign(tc.alg, tc.key), "api")
			if err != nil {
				t.Fatalf("validateAgainstJWKS: %v", err)
			}
			if sub != "spiffe://omega.local/workload/web" {
				t.Fatalf("sub = %q", sub)
			}

			// The same kid with a different algorithm is refused.
			other := map[jose.SignatureAlgorithm]crypto.Signer{jose.ES256: p256, jose.ES384: p384, jose.RS256: rsaKey}
			for alg, key := range other {
				if alg == tc.alg {
					continue
				}
				if _, _, err := validateAgainstJWKS(context.Background(), s, sign(alg, key), "api"); err == nil {
					t.Fatalf("a %s token under the %s key validated", alg, tc.alg)
				}
			}
		})
	}
}
