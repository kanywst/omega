package identity

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ErrIssuanceUnsupported is returned by every minting / local-signing
// method of a non-issuing Source. In spire-upstream mode Omega does not
// run a CA: SVIDs come from the upstream SPIFFE issuer, and Omega only
// serves the upstream trust material plus the authorization + audit
// layer on top of it.
var ErrIssuanceUnsupported = errors.New("identity: omega is in spire-upstream mode and does not issue or locally validate SVIDs; obtain them from the upstream SPIFFE issuer")

// ErrUpstreamJWTNotConfigured is returned by the JWT-SVID validation
// methods when omega is in spire-upstream mode but no upstream JWKS was
// supplied (X.509-only upstream consumption). Supply the upstream JWT
// bundle via --identity-source-jwt-bundle to enable JWT-SVID validation.
var ErrUpstreamJWTNotConfigured = errors.New("identity: upstream JWT-SVID validation is not configured (set --identity-source-jwt-bundle to the upstream JWKS)")

// upstreamSource is the non-issuing identity source: Omega consumes
// identities minted by an upstream SPIFFE trust domain (SPIRE / Istio)
// rather than issuing its own. It carries the upstream trust domain and
// its X.509 trust bundle so /v1/bundle, federation, and downstream peers
// see the upstream root; every issuance / local-signing method fails with
// ErrIssuanceUnsupported, which the API layer surfaces as 501 on the
// issuance routes.
//
// When an upstream JWKS is supplied it also carries the upstream JWT-SVID
// signing keys: JWTBundle serves them at /v1/jwt/bundle so agents pull and
// validate upstream JWT-SVIDs locally, and the validation methods verify a
// presented token against them. Without an upstream JWKS (X.509-only
// consumption) JWTBundle serves an empty JWKS and validation returns
// ErrUpstreamJWTNotConfigured.
// Upstream trust material rotates: SPIRE rolls its X.509 CA and its JWT
// signing key on a schedule, so a bundle read once at boot goes stale
// while the process is still running. Reload installs replacement
// material without a restart; see ADR 0009.
type upstreamSource struct {
	td        spiffeid.TrustDomain
	issuerURL string

	// trust is the current trust material. Reload swaps in a whole new
	// snapshot, so readers on the request and validation paths observe a
	// consistent bundle+JWKS pair without taking a lock and without ever
	// seeing an X.509 bundle paired with the other generation's keys.
	trust atomic.Pointer[upstreamTrust]

	// seq counts installed generations of the trust material, starting at
	// 1. It backs `spiffe_sequence`, which peers use to tell a changed
	// bundle from a re-served one, so it advances only when the material
	// actually differs.
	seq atomic.Int64
}

// upstreamTrust is one immutable generation of upstream trust material.
// Nothing mutates a snapshot after it is published; rotation replaces the
// pointer instead.
type upstreamTrust struct {
	x509Bundle []byte

	// jwtBundle is the canonical JWKS served at /v1/jwt/bundle: the
	// upstream JWT signing keys, or emptyJWKS when none were supplied.
	jwtBundle []byte
	// jwtKeys maps each upstream signing key's kid to its public key for
	// JWT-SVID verification. nil / empty when no upstream JWKS was supplied.
	jwtKeys map[string]*ecdsa.PublicKey
}

// newUpstreamTrust validates upstream trust material and returns it as a
// snapshot. It is the single validation path shared by construction and
// reload, so material rejected at boot is equally rejected at rotation.
func newUpstreamTrust(x509BundlePEM, jwtJWKS []byte) (*upstreamTrust, error) {
	hasCA, err := validateCABundle(x509BundlePEM)
	if err != nil {
		return nil, err
	}
	if !hasCA {
		return nil, errors.New("identity: upstream bundle contained no CA certificate (a trust bundle must hold trust anchors)")
	}
	keys, canonicalJWKS, err := parseUpstreamJWKS(jwtJWKS)
	if err != nil {
		return nil, err
	}
	return &upstreamTrust{
		x509Bundle: append([]byte(nil), x509BundlePEM...),
		jwtBundle:  canonicalJWKS,
		jwtKeys:    keys,
	}, nil
}

// equal reports whether two snapshots carry the same trust material. The
// JWKS side compares the canonical re-encoding, so a cosmetic difference
// in the operator's file - key order, whitespace, a dropped foreign key -
// is not mistaken for a rotation.
func (t *upstreamTrust) equal(other *upstreamTrust) bool {
	return bytes.Equal(t.x509Bundle, other.x509Bundle) &&
		bytes.Equal(t.jwtBundle, other.jwtBundle)
}

// emptyJWKS is the JWT bundle served in spire-upstream mode when no
// upstream JWKS was supplied (X.509-only consumption). A const string (not
// a package-level []byte) so the shared value cannot be mutated by a caller.
const emptyJWKS = `{"keys":[]}`

// NewUpstreamSource builds an X.509-only non-issuing Source for
// trustDomain. It is equivalent to NewUpstreamSourceWithJWT with no
// upstream JWKS: JWTBundle serves an empty JWKS and JWT-SVID validation
// returns ErrUpstreamJWTNotConfigured.
func NewUpstreamSource(trustDomain, issuerURL string, x509BundlePEM []byte) (Source, error) {
	return NewUpstreamSourceWithJWT(trustDomain, issuerURL, x509BundlePEM, nil)
}

// NewUpstreamSourceWithJWT builds a non-issuing Source for trustDomain whose
// X.509 trust bundle is the PEM in x509BundlePEM (the upstream SPIRE /
// Istio root, the same material an operator would wire into --client-ca).
// issuerURL is the OIDC issuer advertised at /.well-known/openid-configuration
// (empty disables discovery). jwtJWKS is the upstream JWT bundle (an RFC
// 7517 JWKS); when non-empty its signing keys are served at /v1/jwt/bundle
// and used to validate upstream JWT-SVIDs. A nil/empty jwtJWKS leaves JWT
// validation disabled (X.509-only consumption).
//
// It validates that the trust domain parses, the issuer URL normalizes, the
// X.509 bundle contains at least one CA certificate, and - when supplied -
// the JWKS holds at least one usable signing key. Both bundles are copied so
// a later mutation of the caller's slices cannot alter the stored trust
// material.
func NewUpstreamSourceWithJWT(trustDomain, issuerURL string, x509BundlePEM, jwtJWKS []byte) (Source, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("identity: upstream trust domain: %w", err)
	}
	issuer, err := normalizeIssuerURL(issuerURL)
	if err != nil {
		return nil, err
	}
	trust, err := newUpstreamTrust(x509BundlePEM, jwtJWKS)
	if err != nil {
		return nil, err
	}
	u := &upstreamSource{td: td, issuerURL: issuer}
	u.trust.Store(trust)
	u.seq.Store(1)
	return u, nil
}

// Reload validates replacement upstream trust material and installs it
// atomically, so an operator can follow an upstream CA or JWT signing-key
// rotation without restarting Omega. It reports whether the material
// actually changed; an unchanged reload is a no-op that does not advance
// the bundle sequence.
//
// It is fail-closed in the strongest sense: the new material runs the
// same validation as boot, and on any error the previous generation stays
// installed. A rotation that would have replaced a good bundle with a
// corrupt one leaves Omega serving the good one.
func (u *upstreamSource) Reload(x509BundlePEM, jwtJWKS []byte) (bool, error) {
	next, err := newUpstreamTrust(x509BundlePEM, jwtJWKS)
	if err != nil {
		return false, err
	}
	if current := u.trust.Load(); current != nil && current.equal(next) {
		return false, nil
	}
	u.trust.Store(next)
	u.seq.Add(1)
	return true, nil
}

// BundleSequence reports the current generation of the trust material,
// starting at 1 and advancing on every Reload that changed it.
func (u *upstreamSource) BundleSequence() int64 { return u.seq.Load() }

// validateCABundle scans the CERTIFICATE blocks in pemBytes. It fails
// closed on a malformed CERTIFICATE block - a corrupt trust anchor in a
// security-critical bundle should surface at startup, not be silently
// dropped - and reports whether at least one parseable CA certificate
// (a trust anchor) is present.
func validateCABundle(pemBytes []byte) (hasCA bool, err error) {
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, perr := x509.ParseCertificate(block.Bytes)
		if perr != nil {
			return false, fmt.Errorf("identity: upstream bundle has a malformed CERTIFICATE block: %w", perr)
		}
		if cert.IsCA {
			hasCA = true
		}
	}
	return hasCA, nil
}

func (u *upstreamSource) SourceKind() SourceKind            { return SourceSPIREUpstream }
func (u *upstreamSource) TrustDomain() spiffeid.TrustDomain { return u.td }
func (u *upstreamSource) IssuerURL() string                 { return u.issuerURL }

// BundlePEM returns a copy of the trust anchors so a caller cannot mutate
// the stored bundle through the returned slice.
func (u *upstreamSource) BundlePEM() []byte {
	return append([]byte(nil), u.trust.Load().x509Bundle...)
}

// JWTBundle returns a copy of the upstream JWKS (the upstream JWT signing
// keys), or an empty JWKS when no upstream JWT bundle was supplied. The copy
// keeps callers from mutating the stored bundle through the returned slice.
func (u *upstreamSource) JWTBundle() ([]byte, error) {
	return append([]byte(nil), u.trust.Load().jwtBundle...), nil
}

func (u *upstreamSource) IssueSVID(spiffeid.ID, *x509.CertificateRequest) (*SVID, error) {
	return nil, ErrIssuanceUnsupported
}

func (u *upstreamSource) IssueJWTSVID(spiffeid.ID, []string, time.Duration, map[string]any) (*JWTSVID, error) {
	return nil, ErrIssuanceUnsupported
}

func (u *upstreamSource) JWTKeyID() (string, error) { return "", ErrIssuanceUnsupported }
