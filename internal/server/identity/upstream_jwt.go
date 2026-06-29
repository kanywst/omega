package identity

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// parseUpstreamJWKS parses an upstream JWT bundle (RFC 7517 JWKS) into a
// kid -> public key map plus a canonical, public-only re-encoding to serve
// at /v1/jwt/bundle. It is fail-closed: a malformed JWKS, a key with a bad
// coordinate, or an off-curve point is an error rather than a silently
// dropped trust anchor. A nil/empty input is the X.509-only case and yields
// no keys with the empty JWKS as the canonical bundle.
//
// Only EC P-256 (ES256) keys are consumed, matching the rest of omega's
// JWT-SVID path (issuance, the agent's local validator) and SPIRE / Istio
// defaults. A JWKS carrying an unsupported key type is rejected so the
// limitation surfaces at startup instead of as a later "unknown kid".
func parseUpstreamJWKS(jwksJSON []byte) (map[string]*ecdsa.PublicKey, []byte, error) {
	if len(jwksJSON) == 0 {
		return nil, []byte(emptyJWKS), nil
	}

	var raw struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			Use string `json:"use"`
			X   string `json:"x"`
			Y   string `json:"y"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(jwksJSON, &raw); err != nil {
		return nil, nil, fmt.Errorf("identity: upstream JWKS is not valid JSON: %w", err)
	}

	keys := make(map[string]*ecdsa.PublicKey, len(raw.Keys))
	canonical := make([]map[string]string, 0, len(raw.Keys))
	for i, k := range raw.Keys {
		// Ignore keys that are structurally not ours (RFC 7517 §5): other
		// key types, other curves, or non-signing keys. A heterogeneous
		// upstream JWKS - e.g. EC and RSA side by side during a key
		// transition, or an "enc" key alongside the signing one - stays
		// usable as long as it carries at least one EC P-256 signing key.
		if k.Kty != "EC" || k.Crv != "P-256" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		// From here the key is a recognised EC P-256 signing key. One we
		// cannot consume is a corrupt trust anchor, not a foreign one, so
		// fail closed rather than silently drop it.
		if k.Kid == "" {
			return nil, nil, fmt.Errorf("identity: upstream JWKS key %d is EC/P-256 but has no kid (a kid is required to select the verification key)", i)
		}
		if _, dup := keys[k.Kid]; dup {
			return nil, nil, fmt.Errorf("identity: upstream JWKS has duplicate kid %q", k.Kid)
		}
		pub, err := ecPublicKeyFromXY(k.X, k.Y)
		if err != nil {
			return nil, nil, fmt.Errorf("identity: upstream JWKS key %q: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
		canonical = append(canonical, map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"alg": "ES256",
			"use": "sig",
			"kid": k.Kid,
			"x":   k.X,
			"y":   k.Y,
		})
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("identity: upstream JWKS contained no usable EC P-256 signing keys")
	}

	out, err := json.Marshal(struct {
		Keys []map[string]string `json:"keys"`
	}{Keys: canonical})
	if err != nil {
		return nil, nil, fmt.Errorf("identity: re-encode upstream JWKS: %w", err)
	}
	return keys, out, nil
}

// ecPublicKeyFromXY decodes a base64url EC point (x, y) into an ECDSA
// public key, rejecting points that are not on the P-256 curve. The point
// is round-tripped through crypto/ecdh, whose NewPublicKey enforces the
// on-curve check.
func ecPublicKeyFromXY(x, y string) (*ecdsa.PublicKey, error) {
	xb, err := base64.RawURLEncoding.DecodeString(x)
	if err != nil {
		return nil, fmt.Errorf("jwk x: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(y)
	if err != nil {
		return nil, fmt.Errorf("jwk y: %w", err)
	}
	if len(xb) != 32 || len(yb) != 32 {
		return nil, fmt.Errorf("jwk coordinates must be 32 bytes each (got x=%d, y=%d)", len(xb), len(yb))
	}
	point := make([]byte, 0, 65)
	point = append(point, 0x04)
	point = append(point, xb...)
	point = append(point, yb...)
	if _, err := ecdh.P256().NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("jwk point is not on the P-256 curve: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xb),
		Y:     new(big.Int).SetBytes(yb),
	}, nil
}

// validateUpstreamJWT verifies token against the upstream signing keys: it
// selects the key by the token's kid header, checks the signature, enforces
// exp / nbf / iat (and audience when aud is non-nil), and confirms the
// subject lies in the upstream trust domain. It returns the SPIFFE ID and
// the raw claims. When no upstream JWKS was supplied it fails with
// ErrUpstreamJWTNotConfigured.
func (u *upstreamSource) validateUpstreamJWT(token string, aud *string) (spiffeid.ID, map[string]any, error) {
	if len(u.jwtKeys) == 0 {
		return spiffeid.ID{}, nil, ErrUpstreamJWTNotConfigured
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("parse jwt: %w", err)
	}
	if len(parsed.Headers) == 0 {
		return spiffeid.ID{}, nil, errors.New("jwt has no header")
	}
	kid := parsed.Headers[0].KeyID
	if kid == "" {
		return spiffeid.ID{}, nil, errors.New("jwt has no kid header")
	}
	pub, ok := u.jwtKeys[kid]
	if !ok {
		return spiffeid.ID{}, nil, fmt.Errorf("jwt signed by unknown kid %q", kid)
	}
	var std jwt.Claims
	var rawClaims map[string]any
	if err := parsed.Claims(pub, &std, &rawClaims); err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("verify jwt: %w", err)
	}
	// SPIFFE JWT-SVID requires exp; go-jose's ValidateWithLeeway does not
	// reject a token that simply omits it, which would otherwise validate
	// indefinitely. Enforce its presence explicitly for these external
	// tokens. (iat is optional per the SPIFFE JWT-SVID spec, so it is not
	// required here.)
	if std.Expiry == nil {
		return spiffeid.ID{}, nil, errors.New("jwt is missing the required exp claim")
	}
	expected := jwt.Expected{Time: time.Now()}
	if aud != nil {
		expected.AnyAudience = jwt.Audience{*aud}
	}
	if err := std.ValidateWithLeeway(expected, 30*time.Second); err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("validate jwt: %w", err)
	}
	id, err := spiffeid.FromString(std.Subject)
	if err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("svid sub: %w", err)
	}
	if !id.MemberOf(u.td) {
		return spiffeid.ID{}, nil, fmt.Errorf("svid sub %q not in trust domain %q", id, u.td)
	}
	return id, rawClaims, nil
}

// ValidateJWTSVID verifies an upstream JWT-SVID's signature, expiry, and
// audience against the upstream JWKS and returns its SPIFFE ID.
func (u *upstreamSource) ValidateJWTSVID(token, audience string) (spiffeid.ID, error) {
	id, _, err := u.validateUpstreamJWT(token, &audience)
	return id, err
}

// ParseJWTSVIDClaims verifies an upstream JWT-SVID's signature and standard
// time claims (without requiring a specific audience) and returns its
// SPIFFE ID plus all claims. Mirrors the built-in authority's behaviour for
// token-exchange-style flows.
func (u *upstreamSource) ParseJWTSVIDClaims(token string) (spiffeid.ID, map[string]any, error) {
	return u.validateUpstreamJWT(token, nil)
}

// ValidatePresentedCertBinding runs the normal upstream JWT-SVID validation
// and, when the token carries an RFC 8705 cnf.x5t#S256 claim, verifies the
// presented certificate's thumbprint matches. Tokens without a cnf claim
// pass through so binding stays opt-in for the upstream issuer - but a cnf
// claim that IS present yet malformed is rejected rather than skipped, so a
// bad confirmation claim cannot silently bypass the binding check.
func (u *upstreamSource) ValidatePresentedCertBinding(token, audience string, presented *x509.Certificate) (spiffeid.ID, error) {
	id, raw, err := u.validateUpstreamJWT(token, &audience)
	if err != nil {
		return spiffeid.ID{}, err
	}
	cnfVal, present := raw["cnf"]
	if !present {
		return id, nil
	}
	cnf, ok := cnfVal.(map[string]any)
	if !ok {
		return spiffeid.ID{}, errors.New("token cnf claim is malformed (not an object)")
	}
	boundVal, present := cnf["x5t#S256"]
	if !present {
		return id, nil
	}
	bound, ok := boundVal.(string)
	if !ok || bound == "" {
		return spiffeid.ID{}, errors.New("token cnf.x5t#S256 is malformed (not a non-empty string)")
	}
	if presented == nil {
		return spiffeid.ID{}, errors.New("token is cert-bound but no certificate was presented")
	}
	if got := CertThumbprintS256(presented); got != bound {
		return spiffeid.ID{}, fmt.Errorf("cert binding mismatch: token bound to %s, presented %s", bound, got)
	}
	return id, nil
}
