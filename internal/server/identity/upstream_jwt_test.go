package identity_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"github.com/kanywst/omega/internal/server/identity"
)

// upstreamAuthority stands in for an external SPIRE / Istio trust domain: a
// real issuing authority whose X.509 bundle, JWKS, and minted JWT-SVIDs we
// hand to omega's non-issuing upstream source.
func upstreamAuthority(t *testing.T, td string) identity.Authority {
	t.Helper()
	a, err := identity.LoadOrCreate(filepath.Join(t.TempDir(), "upstream-ca"), td)
	if err != nil {
		t.Fatalf("upstream authority: %v", err)
	}
	return a
}

func TestUpstreamSourceValidatesUpstreamJWTSVID(t *testing.T) {
	const td = "upstream.example"
	up := upstreamAuthority(t, td)
	jwks, err := up.JWTBundle()
	if err != nil {
		t.Fatalf("upstream JWTBundle: %v", err)
	}

	src, err := identity.NewUpstreamSourceWithJWT(td, "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}

	// JWTBundle now serves the upstream signing keys, not the empty JWKS.
	served, err := src.JWTBundle()
	if err != nil {
		t.Fatalf("src.JWTBundle: %v", err)
	}
	if keyCount(t, served) == 0 {
		t.Fatal("upstream source served an empty JWKS; expected the upstream signing key")
	}

	id := spiffeid.RequireFromString("spiffe://" + td + "/workload/web")
	svid, err := up.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)
	if err != nil {
		t.Fatalf("upstream issue: %v", err)
	}

	got, err := src.ValidateJWTSVID(svid.Token, "https://api.example.com")
	if err != nil {
		t.Fatalf("ValidateJWTSVID: %v", err)
	}
	if got.String() != id.String() {
		t.Fatalf("sub = %q, want %q", got, id)
	}

	// ParseJWTSVIDClaims returns the subject and the raw claims without an
	// audience requirement.
	pid, claims, err := src.ParseJWTSVIDClaims(svid.Token)
	if err != nil {
		t.Fatalf("ParseJWTSVIDClaims: %v", err)
	}
	if pid.String() != id.String() {
		t.Fatalf("parsed sub = %q, want %q", pid, id)
	}
	if claims["sub"] != id.String() {
		t.Fatalf("claims sub = %v, want %q", claims["sub"], id)
	}
}

func TestUpstreamSourceRejectsWrongAudience(t *testing.T) {
	const td = "upstream.example"
	up := upstreamAuthority(t, td)
	jwks, _ := up.JWTBundle()
	src, err := identity.NewUpstreamSourceWithJWT(td, "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	id := spiffeid.RequireFromString("spiffe://" + td + "/workload/web")
	svid, _ := up.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)

	if _, err := src.ValidateJWTSVID(svid.Token, "https://other.example.com"); err == nil {
		t.Fatal("expected validation to fail on a mismatched audience")
	}
}

func TestUpstreamSourceRejectsUnknownSigner(t *testing.T) {
	const td = "upstream.example"
	trusted := upstreamAuthority(t, td)
	jwks, _ := trusted.JWTBundle()
	src, err := identity.NewUpstreamSourceWithJWT(td, "", trusted.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}

	// A different authority for the same trust domain: same sub, different
	// signing key, so its kid is absent from the served JWKS.
	rogue := upstreamAuthority(t, td)
	id := spiffeid.RequireFromString("spiffe://" + td + "/workload/web")
	svid, _ := rogue.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)

	if _, err := src.ValidateJWTSVID(svid.Token, "https://api.example.com"); err == nil {
		t.Fatal("expected validation to fail for a token signed by an unknown key")
	}
}

func TestUpstreamSourceRejectsSubjectOutsideTrustDomain(t *testing.T) {
	// The source's trust domain differs from the issuing authority's, so a
	// validly-signed token's subject is not a member of the source's domain.
	const issuerTD = "issuer.example"
	up := upstreamAuthority(t, issuerTD)
	jwks, _ := up.JWTBundle()
	src, err := identity.NewUpstreamSourceWithJWT("other.example", "", up.BundlePEM(), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	id := spiffeid.RequireFromString("spiffe://" + issuerTD + "/workload/web")
	svid, _ := up.IssueJWTSVID(id, []string{"https://api.example.com"}, time.Minute, nil)

	if _, err := src.ValidateJWTSVID(svid.Token, "https://api.example.com"); err == nil {
		t.Fatal("expected validation to fail for a subject outside the source trust domain")
	}
}

func TestNewUpstreamSourceWithJWTRejectsBadJWKS(t *testing.T) {
	bundle := upstreamBundle(t)

	cases := map[string][]byte{
		"not json":        []byte("{not json"),
		"no usable keys":  []byte(`{"keys":[]}`),
		"unsupported kty": []byte(`{"keys":[{"kty":"RSA","kid":"a","n":"x","e":"AQAB"}]}`),
		"missing kid":     []byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}]}`),
		"bad coordinate":  []byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"!!","y":"!!"}]}`),
		"off curve":       []byte(`{"keys":[{"kty":"EC","crv":"P-256","kid":"a","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","y":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}]}`),
		"encryption key":  []byte(`{"keys":[{"kty":"EC","crv":"P-256","use":"enc","kid":"a","x":"AA","y":"AA"}]}`),
	}
	for name, jwks := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := identity.NewUpstreamSourceWithJWT("upstream.example", "", bundle, jwks); err == nil {
				t.Fatalf("expected error for %s JWKS", name)
			}
		})
	}
}

func TestUpstreamSourceWithoutJWTServesEmptyJWKS(t *testing.T) {
	src, err := identity.NewUpstreamSource("upstream.example", "", upstreamBundle(t))
	if err != nil {
		t.Fatalf("NewUpstreamSource: %v", err)
	}
	jwks, err := src.JWTBundle()
	if err != nil {
		t.Fatalf("JWTBundle: %v", err)
	}
	if keyCount(t, jwks) != 0 {
		t.Fatalf("X.509-only source served %d keys, want empty JWKS", keyCount(t, jwks))
	}
	if _, err := src.ValidateJWTSVID("token", "aud"); !errors.Is(err, identity.ErrUpstreamJWTNotConfigured) {
		t.Fatalf("ValidateJWTSVID err = %v, want ErrUpstreamJWTNotConfigured", err)
	}
}

func keyCount(t *testing.T, jwks []byte) int {
	t.Helper()
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(jwks, &set); err != nil {
		t.Fatalf("parse served JWKS: %v", err)
	}
	return len(set.Keys)
}

// ecSigningKey generates an EC P-256 key and the single-key JWKS that
// advertises it, so a test can sign tokens with full control over the
// claims and headers (which the issuing Authority does not expose).
func ecSigningKey(t *testing.T, kid string) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	// SEC1 uncompressed point (0x04 || X || Y) via crypto/ecdh, avoiding the
	// deprecated ecdsa.PublicKey.X / .Y fields.
	ecdhPub, err := key.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("ecdh: %v", err)
	}
	point := ecdhPub.Bytes()
	jwks := fmt.Sprintf(`{"keys":[{"kty":"EC","crv":"P-256","alg":"ES256","use":"sig","kid":%q,"x":%q,"y":%q}]}`,
		kid,
		base64.RawURLEncoding.EncodeToString(point[1:33]),
		base64.RawURLEncoding.EncodeToString(point[33:65]))
	return key, []byte(jwks)
}

func signClaims(t *testing.T, key *ecdsa.PrivateKey, kid string, setKid bool, claims map[string]any) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if setKid {
		opts = opts.WithHeader("kid", kid)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	tok, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestUpstreamSourceRejectsTokenMissingExp(t *testing.T) {
	const td = "upstream.example"
	key, jwks := ecSigningKey(t, "k1")
	src, err := identity.NewUpstreamSourceWithJWT(td, "", upstreamBundle(t), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	// A validly-signed token whose only flaw is a missing exp claim: it
	// must be rejected rather than treated as valid indefinitely.
	tok := signClaims(t, key, "k1", true, map[string]any{
		"sub": "spiffe://" + td + "/workload/web",
		"aud": []string{"https://api.example.com"},
		"iat": time.Now().Unix(),
	})
	if _, err := src.ValidateJWTSVID(tok, "https://api.example.com"); err == nil {
		t.Fatal("expected validation to fail for a token missing exp")
	}
}

func TestUpstreamSourceRejectsTokenMissingKidHeader(t *testing.T) {
	const td = "upstream.example"
	key, jwks := ecSigningKey(t, "k1")
	src, err := identity.NewUpstreamSourceWithJWT(td, "", upstreamBundle(t), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	// Signed by the trusted key but with no kid header: validation cannot
	// select a key by trial and must fail closed.
	tok := signClaims(t, key, "k1", false, map[string]any{
		"sub": "spiffe://" + td + "/workload/web",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := src.ValidateJWTSVID(tok, "https://api.example.com"); err == nil {
		t.Fatal("expected validation to fail for a token with no kid header")
	}
}

func TestUpstreamSourceSkipsUnsupportedKeys(t *testing.T) {
	const td = "upstream.example"
	key, ecJWKS := ecSigningKey(t, "k1")

	// A heterogeneous upstream JWKS: an RSA key and a P-384 key omega cannot
	// consume, alongside the one EC P-256 signer it can. The unsupported keys
	// are ignored (RFC 7517 §5) rather than failing the whole bundle.
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(ecJWKS, &set); err != nil {
		t.Fatalf("unmarshal ec jwks: %v", err)
	}
	mixed, err := json.Marshal(struct {
		Keys []json.RawMessage `json:"keys"`
	}{Keys: []json.RawMessage{
		json.RawMessage(`{"kty":"RSA","kid":"rsa1","use":"sig","n":"x","e":"AQAB"}`),
		json.RawMessage(`{"kty":"EC","crv":"P-384","kid":"ec384","x":"AA","y":"AA"}`),
		set.Keys[0],
	}})
	if err != nil {
		t.Fatalf("marshal mixed jwks: %v", err)
	}

	src, err := identity.NewUpstreamSourceWithJWT(td, "", upstreamBundle(t), mixed)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	served, _ := src.JWTBundle()
	if n := keyCount(t, served); n != 1 {
		t.Fatalf("served %d keys, want 1 (only the EC P-256 signer)", n)
	}

	tok := signClaims(t, key, "k1", true, map[string]any{
		"sub": "spiffe://" + td + "/workload/web",
		"aud": []string{"https://api.example.com"},
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	if _, err := src.ValidateJWTSVID(tok, "https://api.example.com"); err != nil {
		t.Fatalf("ValidateJWTSVID after skipping unsupported keys: %v", err)
	}
}

func TestUpstreamSourceRejectsMalformedCertBinding(t *testing.T) {
	const td = "upstream.example"
	key, jwks := ecSigningKey(t, "k1")
	src, err := identity.NewUpstreamSourceWithJWT(td, "", upstreamBundle(t), jwks)
	if err != nil {
		t.Fatalf("NewUpstreamSourceWithJWT: %v", err)
	}
	withCnf := func(cnf any) string {
		return signClaims(t, key, "k1", true, map[string]any{
			"sub": "spiffe://" + td + "/workload/web",
			"aud": []string{"https://api.example.com"},
			"exp": time.Now().Add(time.Minute).Unix(),
			"cnf": cnf,
		})
	}

	// A cnf claim that is present but not an object must be rejected, not
	// treated as "no binding".
	if _, err := src.ValidatePresentedCertBinding(withCnf("malformed"), "https://api.example.com", nil); err == nil {
		t.Fatal("expected validation to fail for a non-object cnf claim")
	}
	// A cnf.x5t#S256 that is present but not a string must be rejected too.
	if _, err := src.ValidatePresentedCertBinding(withCnf(map[string]any{"x5t#S256": 123}), "https://api.example.com", nil); err == nil {
		t.Fatal("expected validation to fail for a non-string x5t#S256 claim")
	}
}
