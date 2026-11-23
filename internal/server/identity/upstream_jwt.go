package identity

import (
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// parseUpstreamJWKS parses an upstream JWT bundle (RFC 7517 JWKS) into a
// kid -> verification key map plus a canonical, public-only re-encoding to
// serve at /v1/jwt/bundle. It is fail-closed: a malformed JWKS, a key with
// a bad coordinate or modulus, or an off-curve point is an error rather
// than a silently dropped trust anchor. A nil/empty input is the X.509-only
// case and yields no keys with the empty JWKS as the canonical bundle.
//
// EC P-256 (ES256), EC P-384 (ES384) and RSA (RS256, 2048 bits or more)
// keys are consumed: the signing keys SPIRE produces for each of its
// jwt_key_type values. Keys that are structurally not ours - other key
// types or curves, non-signing usages, an alg other than the one the key
// type is pinned to, or key_ops without verify - are skipped so a
// heterogeneous upstream JWKS stays usable as long as it carries at least
// one signing key omega consumes.
func parseUpstreamJWKS(jwksJSON []byte) (map[string]JWTVerificationKey, []byte, error) {
	if len(jwksJSON) == 0 {
		return nil, []byte(emptyJWKS), nil
	}

	var raw struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(jwksJSON, &raw); err != nil {
		return nil, nil, fmt.Errorf("identity: upstream JWKS is not valid JSON: %w", err)
	}

	keys := make(map[string]JWTVerificationKey, len(raw.Keys))
	canonical := make([]map[string]string, 0, len(raw.Keys))
	for i, k := range raw.Keys {
		key, ok, err := ParseJWTSigningKey(k)
		if !ok {
			continue
		}
		// From here the key is a recognised signing key. One we cannot
		// consume is a corrupt trust anchor, not a foreign one, so fail
		// closed rather than silently drop it.
		if k.Kid == "" {
			return nil, nil, fmt.Errorf("identity: upstream JWKS key %d is a %s signing key but has no kid (a kid is required to select the verification key)", i, k.Kty)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("identity: upstream JWKS key %q: %w", k.Kid, err)
		}
		if _, dup := keys[k.Kid]; dup {
			return nil, nil, fmt.Errorf("identity: upstream JWKS has duplicate kid %q", k.Kid)
		}
		jwk, err := canonicalJWK(k.Kid, key)
		if err != nil {
			return nil, nil, fmt.Errorf("identity: re-encode upstream JWKS key %q: %w", k.Kid, err)
		}
		keys[k.Kid] = key
		canonical = append(canonical, jwk)
	}
	if len(keys) == 0 {
		return nil, nil, errors.New("identity: upstream JWKS contained no usable signing keys (EC P-256, EC P-384 or RSA)")
	}

	out, err := json.Marshal(struct {
		Keys []map[string]string `json:"keys"`
	}{Keys: canonical})
	if err != nil {
		return nil, nil, fmt.Errorf("identity: re-encode upstream JWKS: %w", err)
	}
	return keys, out, nil
}

// validateUpstreamJWT verifies token against the upstream signing keys: it
// selects the key by the token's kid header, checks the signature, enforces
// exp / nbf / iat (and audience when aud is non-nil), and confirms the
// subject lies in the upstream trust domain. It returns the SPIFFE ID and
// the raw claims. When no upstream JWKS was supplied it fails with
// ErrUpstreamJWTNotConfigured.
func (u *upstreamSource) validateUpstreamJWT(token string, aud *string) (spiffeid.ID, map[string]any, error) {
	// Pin one generation of the trust material for the whole validation:
	// a concurrent Reload must not let the kid lookup and the signature
	// check land on different key sets.
	trust := u.trust.Load()
	if len(trust.jwtKeys) == 0 {
		return spiffeid.ID{}, nil, ErrUpstreamJWTNotConfigured
	}
	parsed, err := jwt.ParseSigned(token, JWTSVIDAlgs)
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
	key, ok := trust.jwtKeys[kid]
	if !ok {
		return spiffeid.ID{}, nil, fmt.Errorf("jwt signed by unknown kid %q", kid)
	}
	if alg := parsed.Headers[0].Algorithm; alg != string(key.Alg) {
		return spiffeid.ID{}, nil, fmt.Errorf("jwt alg %q does not match the %s key %q", alg, key.Alg, kid)
	}
	var std jwt.Claims
	var rawClaims map[string]any
	if err := parsed.Claims(key.Key, &std, &rawClaims); err != nil {
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
// pass through so binding stays opt-in for the upstream issuer. A cnf claim
// that IS present is fail-closed: a malformed cnf, or one whose confirmation
// method is not the x5t#S256 this validator can enforce, is rejected rather
// than accepted as a bearer token - the issuer demanded proof of possession
// we cannot silently waive.
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
	// A cnf claim is the issuer demanding proof of possession. x5t#S256
	// (RFC 8705 certificate binding) is the only method this validator can
	// enforce; a cnf carrying some other method (e.g. DPoP jkt) cannot be
	// proven here, so accepting the token as a bearer would bypass the
	// binding the issuer required. Reject rather than fail open.
	boundVal, present := cnf["x5t#S256"]
	if !present {
		return spiffeid.ID{}, errors.New("token cnf claim has no x5t#S256 binding (unsupported confirmation method)")
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
