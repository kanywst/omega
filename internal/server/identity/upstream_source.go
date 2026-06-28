package identity

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// ErrIssuanceUnsupported is returned by every minting / local-signing
// method of a non-issuing Source. In spire-upstream mode Omega does not
// run a CA: SVIDs come from the upstream SPIFFE issuer, and Omega only
// serves the upstream trust material plus the authorization + audit
// layer on top of it.
var ErrIssuanceUnsupported = errors.New("identity: omega is in spire-upstream mode and does not issue or locally validate SVIDs; obtain them from the upstream SPIFFE issuer")

// upstreamSource is the non-issuing identity source: Omega consumes
// identities minted by an upstream SPIFFE trust domain (SPIRE / Istio)
// rather than issuing its own. It carries the upstream trust domain and
// its X.509 trust bundle so /v1/bundle, federation, and downstream peers
// see the upstream root; every issuance / local-signing method fails with
// ErrIssuanceUnsupported, which the API layer surfaces as 501 on the
// issuance routes.
//
// JWT-SVID authorities are not consumed yet: JWTBundle serves an empty
// JWKS so the combined SPIFFE bundle endpoint stays valid, and upstream
// JWT-SVID validation is a follow-up.
type upstreamSource struct {
	td         spiffeid.TrustDomain
	issuerURL  string
	x509Bundle []byte
}

// emptyJWKS is the JWT bundle served in spire-upstream mode until upstream
// JWT-SVID authorities are consumed. A const string (not a package-level
// []byte) so the shared value cannot be mutated by a caller.
const emptyJWKS = `{"keys":[]}`

// NewUpstreamSource builds a non-issuing Source for trustDomain whose
// X.509 trust bundle is the PEM in x509BundlePEM (the upstream SPIRE /
// Istio root, the same material an operator would wire into --client-ca).
// issuerURL is the OIDC issuer advertised at /.well-known/openid-configuration
// (empty disables discovery). It validates that the trust domain parses,
// the issuer URL normalizes, and the bundle contains at least one CA
// certificate. The bundle is copied so a later mutation of the caller's
// slice cannot alter the stored trust anchors.
func NewUpstreamSource(trustDomain, issuerURL string, x509BundlePEM []byte) (Source, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("identity: upstream trust domain: %w", err)
	}
	issuer, err := normalizeIssuerURL(issuerURL)
	if err != nil {
		return nil, err
	}
	hasCA, err := validateCABundle(x509BundlePEM)
	if err != nil {
		return nil, err
	}
	if !hasCA {
		return nil, errors.New("identity: upstream bundle contained no CA certificate (a trust bundle must hold trust anchors)")
	}
	return &upstreamSource{td: td, issuerURL: issuer, x509Bundle: append([]byte(nil), x509BundlePEM...)}, nil
}

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
func (u *upstreamSource) BundlePEM() []byte { return append([]byte(nil), u.x509Bundle...) }

// JWTBundle returns an empty JWKS so the combined SPIFFE bundle document
// stays well-formed; consuming upstream JWT-SVID authorities is a
// follow-up.
func (u *upstreamSource) JWTBundle() ([]byte, error) { return []byte(emptyJWKS), nil }

func (u *upstreamSource) IssueSVID(spiffeid.ID, *x509.CertificateRequest) (*SVID, error) {
	return nil, ErrIssuanceUnsupported
}

func (u *upstreamSource) IssueJWTSVID(spiffeid.ID, []string, time.Duration, map[string]any) (*JWTSVID, error) {
	return nil, ErrIssuanceUnsupported
}

func (u *upstreamSource) JWTKeyID() (string, error) { return "", ErrIssuanceUnsupported }

func (u *upstreamSource) ValidateJWTSVID(string, string) (spiffeid.ID, error) {
	return spiffeid.ID{}, ErrIssuanceUnsupported
}

func (u *upstreamSource) ValidatePresentedCertBinding(string, string, *x509.Certificate) (spiffeid.ID, error) {
	return spiffeid.ID{}, ErrIssuanceUnsupported
}

func (u *upstreamSource) ParseJWTSVIDClaims(string) (spiffeid.ID, map[string]any, error) {
	return spiffeid.ID{}, nil, ErrIssuanceUnsupported
}
