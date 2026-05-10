// Package identity owns the Omega CA and SVID issuance.
//
// Authority is the pluggable signing surface. The default implementation
// is a self-signed ECDSA P-256 CA persisted to disk; HSM (PKCS#11) and
// cloud KMS (AWS / GCP / Azure) implementations are added by introducing
// new Kind values to Config and routing through New. Every backend must
// expose a crypto.Signer-compatible private key path: that constraint
// is what lets remote signers slot in without changing callers.
//
// Callers should always go through New / LoadOrCreate and depend on the
// Authority interface - never on a concrete type. The package-private
// localAuthority struct is intentionally unexported so adding kinds in
// the future does not break the public API.
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

const (
	caValidity   = 10 * 365 * 24 * time.Hour
	svidValidity = 30 * time.Minute
)

// Kind identifies which Authority implementation New should construct.
// Empty / unset is treated as KindDisk for backwards compatibility.
type Kind string

const (
	// KindDisk is the default self-signed CA persisted to data-dir/ca/.
	// This is currently the only backing kind; HSM / KMS variants will
	// register their own Kind values without changing this one.
	KindDisk Kind = "disk"
)

// Config is the disjoint-union-style argument to New. Fields are read
// only by the implementation matching Kind; for KindDisk the relevant
// fields are Dir and TrustDomain. Future kinds will add their own
// fields (e.g. KMSKeyARN, PKCS11ModulePath) without touching existing
// callers.
type Config struct {
	Kind        Kind
	TrustDomain string
	// Issuer is the public OIDC issuer URL embedded as the `iss` claim
	// of every JWT-SVID. Empty (the default) keeps the SPIFFE-only
	// behaviour where issued tokens carry no `iss` claim. Set this
	// when external OIDC relying parties (AWS IAM OIDC trust, GCP
	// Workload Identity Federation, Kubernetes ServiceAccount issuer
	// trust) need to verify Omega-issued tokens; the same value is
	// returned by the `/.well-known/openid-configuration` discovery
	// endpoint and must point at the publicly reachable URL of this
	// server.
	Issuer string
	// KindDisk
	Dir string
}

// Authority is the signing + bundle interface every Omega CA backend
// must satisfy. The methods are issuance-only on purpose: management
// concerns (CA rotation, key escrow, audit) live elsewhere so that an
// HSM-backed Authority does not need to expose its key material to
// implement them.
type Authority interface {
	TrustDomain() spiffeid.TrustDomain
	BundlePEM() []byte

	IssueSVID(id spiffeid.ID, pub crypto.PublicKey) (*SVID, error)

	IssueJWTSVID(id spiffeid.ID, audience []string, ttl time.Duration, extraClaims map[string]any) (*JWTSVID, error)
	JWTKeyID() (string, error)
	JWTBundle() ([]byte, error)
	// IssuerURL returns the OIDC issuer URL configured for this
	// authority, or "" when JWT-SVIDs do not carry an `iss` claim.
	IssuerURL() string
	ValidateJWTSVID(token, audience string) (spiffeid.ID, error)
	ValidatePresentedCertBinding(token, audience string, presented *x509.Certificate) (spiffeid.ID, error)
	// ParseJWTSVIDClaims verifies signature + standard time claims and
	// returns sub + the raw claims map without enforcing audience.
	// Used by token-exchange flows where the input token's audience is
	// not relevant to the new issuance.
	ParseJWTSVIDClaims(token string) (spiffeid.ID, map[string]any, error)
}

// New builds an Authority from cfg. It is the only constructor that
// understands Kind; LoadOrCreate is a thin convenience wrapper for the
// disk default that keeps the original call sites unchanged.
func New(cfg Config) (Authority, error) {
	if cfg.TrustDomain == "" {
		return nil, errors.New("identity: trust domain is required")
	}
	switch cfg.Kind {
	case "", KindDisk:
		if cfg.Dir == "" {
			return nil, errors.New("identity: disk authority requires Dir")
		}
		a, err := loadOrCreateDisk(cfg.Dir, cfg.TrustDomain)
		if err != nil {
			return nil, err
		}
		a.issuerURL = cfg.Issuer
		return a, nil
	default:
		return nil, fmt.Errorf("identity: unknown kind %q (supported: %q)", cfg.Kind, KindDisk)
	}
}

// LoadOrCreate is shorthand for New(Config{Kind: KindDisk, ...}). It is
// retained because every existing call site (cli, tests) wired into the
// disk default. Use New directly when picking a non-disk Kind.
func LoadOrCreate(dir, trustDomain string) (Authority, error) {
	return New(Config{Kind: KindDisk, TrustDomain: trustDomain, Dir: dir})
}

// localAuthority is the disk-backed implementation: ECDSA P-256
// self-signed CA, key + cert in two PEM files. Unexported because new
// Kinds will add their own structs and callers should not type-assert.
type localAuthority struct {
	trustDomain spiffeid.TrustDomain
	cert        *x509.Certificate
	key         crypto.Signer
	bundlePEM   []byte
	issuerURL   string
}

var _ Authority = (*localAuthority)(nil)

func loadOrCreateDisk(dir, trustDomain string) (*localAuthority, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("trust domain: %w", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("ca dir: %w", err)
	}
	keyPath := filepath.Join(dir, "ca.key")
	crtPath := filepath.Join(dir, "ca.crt")
	if _, err := os.Stat(keyPath); err == nil {
		return loadAuthority(td, keyPath, crtPath)
	}
	return createAuthority(td, keyPath, crtPath)
}

func createAuthority(td spiffeid.TrustDomain, keyPath, crtPath string) (*localAuthority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("gen ca key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Omega Local CA"},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign ca: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, err
	}
	// #nosec G306 -- ca.crt is the public root that workloads need to read.
	if err := os.WriteFile(crtPath, crtPEM, 0o644); err != nil {
		return nil, err
	}
	return &localAuthority{trustDomain: td, cert: cert, key: key, bundlePEM: crtPEM}, nil
}

func loadAuthority(td spiffeid.TrustDomain, keyPath, crtPath string) (*localAuthority, error) {
	// #nosec G304 -- keyPath comes from operator-supplied --data-dir, not user input.
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read ca key: %w", err)
	}
	// #nosec G304 -- crtPath comes from operator-supplied --data-dir, not user input.
	crtPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid CA key PEM")
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca key: %w", err)
	}
	signer, ok := keyAny.(crypto.Signer)
	if !ok {
		return nil, errors.New("ca key is not a crypto.Signer")
	}
	crtBlock, _ := pem.Decode(crtPEM)
	if crtBlock == nil {
		return nil, errors.New("invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	return &localAuthority{trustDomain: td, cert: cert, key: signer, bundlePEM: crtPEM}, nil
}

func (a *localAuthority) TrustDomain() spiffeid.TrustDomain { return a.trustDomain }

func (a *localAuthority) IssuerURL() string { return a.issuerURL }
func (a *localAuthority) BundlePEM() []byte                 { return a.bundlePEM }

type SVID struct {
	SPIFFEID  spiffeid.ID
	CertPEM   []byte
	BundlePEM []byte
	NotBefore time.Time
	NotAfter  time.Time
}

// IssueSVID signs an X.509-SVID for id over the public key in pub.
// The SPIFFE ID must be a member of this authority's trust domain.
func (a *localAuthority) IssueSVID(id spiffeid.ID, pub crypto.PublicKey) (*SVID, error) {
	if id.IsZero() {
		return nil, errors.New("spiffe id is empty")
	}
	if !id.MemberOf(a.trustDomain) {
		return nil, fmt.Errorf("spiffe id %q is not in trust domain %q", id, a.trustDomain)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: id.String()},
		NotBefore:             now.Add(-1 * time.Minute),
		NotAfter:              now.Add(svidValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageKeyAgreement,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		URIs:                  []*url.URL{idAsURL(id)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, a.cert, pub, a.key)
	if err != nil {
		return nil, fmt.Errorf("sign svid: %w", err)
	}
	return &SVID{
		SPIFFEID:  id,
		CertPEM:   pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		BundlePEM: a.bundlePEM,
		NotBefore: tpl.NotBefore,
		NotAfter:  tpl.NotAfter,
	}, nil
}

func idAsURL(id spiffeid.ID) *url.URL {
	u, _ := url.Parse(id.String())
	return u
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 159)
	return rand.Int(rand.Reader, limit)
}
