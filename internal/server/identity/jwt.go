package identity

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	defaultJWTTTL = 5 * time.Minute
	maxJWTTTL     = 24 * time.Hour
)

// JWTSVID is a signed SPIFFE JWT-SVID with metadata useful for callers.
type JWTSVID struct {
	Token     string    `json:"token"`
	SPIFFEID  string    `json:"spiffe_id"`
	Audience  []string  `json:"audience"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	KeyID     string    `json:"kid"`
}

// IssueJWTSVID signs a JWT-SVID for id valid for the given audience.
// ttl is clamped to [1m, 24h]; zero means defaultJWTTTL. The audience
// list must contain at least one entry per the SPIFFE JWT-SVID spec.
func (a *localAuthority) IssueJWTSVID(id spiffeid.ID, audience []string, ttl time.Duration, extraClaims map[string]any) (*JWTSVID, error) {
	if id.IsZero() {
		return nil, errors.New("spiffe id is empty")
	}
	if !id.MemberOf(a.trustDomain) {
		return nil, fmt.Errorf("spiffe id %q is not in trust domain %q", id, a.trustDomain)
	}
	if len(audience) == 0 {
		return nil, errors.New("audience is required")
	}
	for _, aud := range audience {
		if aud == "" {
			return nil, errors.New("audience entries must be non-empty")
		}
	}
	if ttl <= 0 {
		ttl = defaultJWTTTL
	}
	if ttl > maxJWTTTL {
		ttl = maxJWTTTL
	}

	kid, err := a.JWTKeyID()
	if err != nil {
		return nil, err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: a.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid),
	)
	if err != nil {
		return nil, fmt.Errorf("jwt signer: %w", err)
	}

	now := time.Now().UTC()
	exp := now.Add(ttl)
	claims := jwt.Claims{
		Subject:  id.String(),
		Audience: jwt.Audience(audience),
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(exp),
		ID:       fmt.Sprintf("%d", now.UnixNano()),
	}
	// Setting `iss` is opt-in: SPIFFE JWT-SVID does not mandate it,
	// and external OIDC RPs (AWS IAM OIDC trust, GCP WIF, K8s SA
	// issuer trust) require an `iss` whose value matches the configured
	// OIDC issuer URL. Operators set Issuer in identity.Config when
	// they want OIDC-compatible tokens.
	if iss := a.issuerURL; iss != "" {
		claims.Issuer = iss
	}

	builder := jwt.Signed(signer).Claims(claims)
	if len(extraClaims) > 0 {
		builder = builder.Claims(extraClaims)
	}
	tok, err := builder.Serialize()
	if err != nil {
		return nil, fmt.Errorf("sign jwt: %w", err)
	}

	return &JWTSVID{
		Token:     tok,
		SPIFFEID:  id.String(),
		Audience:  audience,
		IssuedAt:  now,
		ExpiresAt: exp,
		KeyID:     kid,
	}, nil
}

// JWTKeyID returns a deterministic key ID derived from the CA public key
// (first 16 hex chars of SHA-256 over the SPKI DER). Stable as long as
// the CA key is stable.
func (a *localAuthority) JWTKeyID() (string, error) {
	pub, ok := a.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("ca key is not ECDSA (only ES256 is supported)")
	}
	der, err := marshalECPublicKey(pub)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(h[:8]), nil
}

// JWTBundle returns a JWKS containing the CA public key, suitable for
// verifying JWT-SVIDs issued by this authority. Format follows SPIFFE
// JWT bundle conventions (RFC 7517 JWKS).
func (a *localAuthority) JWTBundle() ([]byte, error) {
	pub, ok := a.cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("ca key is not ECDSA")
	}
	kid, err := a.JWTKeyID()
	if err != nil {
		return nil, err
	}
	point, err := ecPointBytes(pub)
	if err != nil {
		return nil, err
	}
	jwk := struct {
		Keys []map[string]string `json:"keys"`
	}{
		Keys: []map[string]string{{
			"kty": "EC",
			"crv": "P-256",
			"alg": "ES256",
			"use": "sig",
			"kid": kid,
			"x":   base64.RawURLEncoding.EncodeToString(point[1:33]),
			"y":   base64.RawURLEncoding.EncodeToString(point[33:65]),
		}},
	}
	return json.Marshal(jwk)
}

// ValidateJWTSVID checks the signature, expiry, and audience of a token.
// Returns the SPIFFE ID claim on success.
//
// The `iss` claim is intentionally NOT validated here even when the
// authority is configured with an Issuer URL: SPIFFE JWT-SVIDs do not
// mandate iss, so SPIFFE-only consumers must keep working. External
// OIDC relying parties (AWS IAM, GCP WIF, K8s SA issuer trust) check
// iss themselves against the discovery document's issuer field, which
// is the layer where the enforcement belongs.
func (a *localAuthority) ValidateJWTSVID(token string, audience string) (spiffeid.ID, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("parse jwt: %w", err)
	}
	var claims jwt.Claims
	if err := parsed.Claims(a.cert.PublicKey, &claims); err != nil {
		return spiffeid.ID{}, fmt.Errorf("verify jwt: %w", err)
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{
		AnyAudience: jwt.Audience{audience},
		Time:        time.Now(),
	}, 30*time.Second); err != nil {
		return spiffeid.ID{}, fmt.Errorf("validate jwt: %w", err)
	}
	id, err := spiffeid.FromString(claims.Subject)
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("svid sub: %w", err)
	}
	if !id.MemberOf(a.trustDomain) {
		return spiffeid.ID{}, fmt.Errorf("svid sub %q not in trust domain %q", id, a.trustDomain)
	}
	return id, nil
}

// ParseJWTSVIDClaims verifies the signature of a token issued by this
// authority and returns the SPIFFE ID (sub claim) along with all the
// custom claims as a map. Unlike ValidateJWTSVID it does NOT require a
// specific audience: token-exchange flows treat the input tokens as
// self-presented identity assertions whose original audience is
// irrelevant to the exchange itself. exp / nbf / iat are still
// enforced via go-jose's default validation (Time = now, with a 30s
// leeway to match ValidateJWTSVID).
func (a *localAuthority) ParseJWTSVIDClaims(token string) (spiffeid.ID, map[string]any, error) {
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("parse jwt: %w", err)
	}
	var raw map[string]any
	if err := parsed.Claims(a.cert.PublicKey, &raw); err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("verify jwt: %w", err)
	}
	var std jwt.Claims
	if err := parsed.Claims(a.cert.PublicKey, &std); err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("verify jwt: %w", err)
	}
	if err := std.ValidateWithLeeway(jwt.Expected{Time: time.Now()}, 30*time.Second); err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("validate jwt: %w", err)
	}
	id, err := spiffeid.FromString(std.Subject)
	if err != nil {
		return spiffeid.ID{}, nil, fmt.Errorf("svid sub: %w", err)
	}
	if !id.MemberOf(a.trustDomain) {
		return spiffeid.ID{}, nil, fmt.Errorf("svid sub %q not in trust domain %q", id, a.trustDomain)
	}
	return id, raw, nil
}

// CertThumbprintS256 returns the RFC 8705 cnf.x5t#S256 value for a
// certificate: SHA-256 over its DER encoding, base64url without padding.
func CertThumbprintS256(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidatePresentedCertBinding checks that a JWT-SVID carrying an RFC
// 8705 cnf.x5t#S256 claim is being presented alongside the matching
// X.509-SVID. It first runs the normal SPIFFE JWT-SVID validation, then
// - if a cnf claim is present - verifies the thumbprint of presented
// matches the bound thumbprint. Tokens without a cnf claim pass through
// unchanged so binding remains opt-in for issuers. A cnf claim that IS
// present is fail-closed: a malformed cnf, or one whose confirmation
// method is not the x5t#S256 this validator can enforce, is rejected
// rather than accepted as a bearer token - the issuer demanded proof of
// possession we cannot silently waive.
func (a *localAuthority) ValidatePresentedCertBinding(token, audience string, presented *x509.Certificate) (spiffeid.ID, error) {
	id, err := a.ValidateJWTSVID(token, audience)
	if err != nil {
		return spiffeid.ID{}, err
	}
	parsed, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return spiffeid.ID{}, fmt.Errorf("parse jwt: %w", err)
	}
	var raw map[string]any
	if err := parsed.Claims(a.cert.PublicKey, &raw); err != nil {
		return spiffeid.ID{}, fmt.Errorf("read claims: %w", err)
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

func marshalECPublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	return ecPointBytes(pub)
}

// ecPointBytes returns the SEC1 uncompressed point encoding of pub
// (0x04 || X || Y) using the modern crypto/ecdh API. For P-256 the
// result is 65 bytes; X occupies bytes [1:33] and Y bytes [33:65].
func ecPointBytes(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub.Curve != nil && pub.Curve.Params().BitSize != 256 {
		return nil, fmt.Errorf("unsupported curve %q", pub.Curve.Params().Name)
	}
	ecdhPub, err := pub.ECDH()
	if err != nil {
		return nil, fmt.Errorf("convert ECDSA public key to ECDH: %w", err)
	}
	return ecdhPub.Bytes(), nil
}
