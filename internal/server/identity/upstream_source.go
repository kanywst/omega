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
// JWT-SVID authorities are consumed. Precomputed so JWTBundle does not
// allocate per call.
var emptyJWKS = []byte(`{"keys":[]}`)

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
	if !hasCACertificate(x509BundlePEM) {
		return nil, errors.New("identity: upstream bundle contained no CA certificate (a trust bundle must hold trust anchors)")
	}
	return upstreamSource{td: td, issuerURL: issuer, x509Bundle: append([]byte(nil), x509BundlePEM...)}, nil
}

// hasCACertificate reports whether pemBytes holds at least one parseable
// X.509 CA certificate. A trust bundle is a set of trust anchors, so a
// PEM carrying only leaf certificates is rejected.
func hasCACertificate(pemBytes []byte) bool {
	for rest := pemBytes; len(rest) > 0; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil && cert.IsCA {
			return true
		}
	}
	return false
}

func (u upstreamSource) SourceKind() SourceKind            { return SourceSPIREUpstream }
func (u upstreamSource) TrustDomain() spiffeid.TrustDomain { return u.td }
func (u upstreamSource) BundlePEM() []byte                 { return u.x509Bundle }
func (u upstreamSource) IssuerURL() string                 { return u.issuerURL }

// JWTBundle returns an empty JWKS so the combined SPIFFE bundle document
// stays well-formed; consuming upstream JWT-SVID authorities is a
// follow-up.
func (u upstreamSource) JWTBundle() ([]byte, error) { return emptyJWKS, nil }

func (u upstreamSource) IssueSVID(spiffeid.ID, *x509.CertificateRequest) (*SVID, error) {
	return nil, ErrIssuanceUnsupported
}

func (u upstreamSource) IssueJWTSVID(spiffeid.ID, []string, time.Duration, map[string]any) (*JWTSVID, error) {
	return nil, ErrIssuanceUnsupported
}

func (u upstreamSource) JWTKeyID() (string, error) { return "", ErrIssuanceUnsupported }

func (u upstreamSource) ValidateJWTSVID(string, string) (spiffeid.ID, error) {
	return spiffeid.ID{}, ErrIssuanceUnsupported
}

func (u upstreamSource) ValidatePresentedCertBinding(string, string, *x509.Certificate) (spiffeid.ID, error) {
	return spiffeid.ID{}, ErrIssuanceUnsupported
}

func (u upstreamSource) ParseJWTSVIDClaims(string) (spiffeid.ID, map[string]any, error) {
	return spiffeid.ID{}, nil, ErrIssuanceUnsupported
}
